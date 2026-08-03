#include <chrono>
#include <future>
#include <stdexcept>
#include <string>
#include <thread>

#include <curl/curl.h>

#include "handler/curl_handle_pool.h"
#include "httplib.h"

using namespace std::chrono_literals;

static void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

static size_t collect(char *data, size_t size, size_t count, void *output) {
  static_cast<std::string *>(output)->append(data, size * count);
  return size * count;
}

int main() {
  require(curl_global_init(CURL_GLOBAL_ALL) == CURLE_OK,
          "curl_global_init failed");
  {
    CurlHandlePool pool(1);

    CurlHandleLease first = pool.acquire();
    require(static_cast<bool>(first), "failed to acquire first handle");
    CURL *original = first.get();
    curl_easy_setopt(original, CURLOPT_COOKIEFILE, "");
    curl_easy_setopt(
        original, CURLOPT_COOKIELIST,
        "example.test\tFALSE\t/\tFALSE\t0\tpool-cookie\tsecret");
    curl_slist *cookies = nullptr;
    require(curl_easy_getinfo(original, CURLINFO_COOKIELIST, &cookies) ==
                CURLE_OK,
            "failed to read seeded cookie list");
    require(cookies != nullptr, "seeded cookie was not stored");
    curl_slist_free_all(cookies);

    auto waiting = std::async(std::launch::async, [&] {
      CurlHandleLease lease = pool.acquire();
      return lease.get();
    });
    require(waiting.wait_for(50ms) == std::future_status::timeout,
            "pool capacity did not block a second acquisition");
    first = CurlHandleLease();
    CURL *reused = waiting.get();
    require(reused == original, "pool did not reuse the released handle");

    CurlHandleLease isolated = pool.acquire();
    require(isolated.get() == original,
            "pool returned an unexpected handle after reuse");
    cookies = nullptr;
    require(curl_easy_getinfo(isolated.get(), CURLINFO_COOKIELIST, &cookies) ==
                CURLE_OK,
            "failed to read reset cookie list");
    require(cookies == nullptr, "cookie state leaked between leases");
    curl_slist_free_all(cookies);
    isolated = CurlHandleLease();

    httplib::Server server;
    auto echo = [](const httplib::Request &request,
                   httplib::Response &response) {
      response.set_content(
          request.method + "|" + request.get_header_value("X-Pool-Leak") +
              "|" + request.get_header_value("Cookie"),
          "text/plain");
    };
    server.Get("/echo", echo);
    server.Post("/echo", echo);
    server.Patch("/echo", echo);
    int port = server.bind_to_any_port("127.0.0.1");
    require(port > 0, "failed to bind the local test server");
    std::thread server_thread([&] { server.listen_after_bind(); });
    std::string url =
        "http://127.0.0.1:" + std::to_string(port) + "/echo";

    std::string first_response;
    curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "X-Pool-Leak: first-request");
    {
      CurlHandleLease request = pool.acquire();
      curl_easy_setopt(request.get(), CURLOPT_URL, url.c_str());
      curl_easy_setopt(request.get(), CURLOPT_POST, 1L);
      curl_easy_setopt(request.get(), CURLOPT_HTTPHEADER, headers);
      curl_easy_setopt(request.get(), CURLOPT_COOKIEFILE, "");
      curl_easy_setopt(
          request.get(), CURLOPT_COOKIELIST,
          "127.0.0.1\tFALSE\t/\tFALSE\t0\tpool-cookie\tsecret");
      curl_easy_setopt(request.get(), CURLOPT_WRITEFUNCTION, collect);
      curl_easy_setopt(request.get(), CURLOPT_WRITEDATA, &first_response);
      require(curl_easy_perform(request.get()) == CURLE_OK,
              "first pooled request failed");
      curl_easy_setopt(request.get(), CURLOPT_PROXY, "http://127.0.0.1:1");
      curl_easy_setopt(request.get(), CURLOPT_NOPROXY, "");
    }
    curl_slist_free_all(headers);
    require(first_response.find("POST|first-request|") == 0,
            "first request method or header was not received");
    require(first_response.find("pool-cookie=secret") != std::string::npos,
            "first request cookie was not received");

    std::string second_response;
    {
      CurlHandleLease request = pool.acquire();
      curl_easy_setopt(request.get(), CURLOPT_URL, url.c_str());
      curl_easy_setopt(request.get(), CURLOPT_WRITEFUNCTION, collect);
      curl_easy_setopt(request.get(), CURLOPT_WRITEDATA, &second_response);
      require(curl_easy_perform(request.get()) == CURLE_OK,
              "second pooled request failed");
    }
    require(second_response == "GET||",
            "method, header, or cookie state leaked into second request");

    std::string head_response;
    {
      CurlHandleLease request = pool.acquire();
      curl_easy_setopt(request.get(), CURLOPT_URL, url.c_str());
      curl_easy_setopt(request.get(), CURLOPT_NOBODY, 1L);
      curl_easy_setopt(request.get(), CURLOPT_WRITEFUNCTION, collect);
      curl_easy_setopt(request.get(), CURLOPT_WRITEDATA, &head_response);
      require(curl_easy_perform(request.get()) == CURLE_OK,
              "HEAD pooled request failed");
    }
    require(head_response.empty(), "HEAD request unexpectedly returned a body");

    std::string after_head_response;
    {
      CurlHandleLease request = pool.acquire();
      curl_easy_setopt(request.get(), CURLOPT_URL, url.c_str());
      curl_easy_setopt(request.get(), CURLOPT_WRITEFUNCTION, collect);
      curl_easy_setopt(request.get(), CURLOPT_WRITEDATA,
                       &after_head_response);
      require(curl_easy_perform(request.get()) == CURLE_OK,
              "request after HEAD failed");
    }
    require(after_head_response == "GET||",
            "HEAD state leaked into the following request");

    std::string patch_response;
    std::string patch_data = "patch-body";
    {
      CurlHandleLease request = pool.acquire();
      curl_easy_setopt(request.get(), CURLOPT_URL, url.c_str());
      curl_easy_setopt(request.get(), CURLOPT_CUSTOMREQUEST, "PATCH");
      curl_easy_setopt(request.get(), CURLOPT_POSTFIELDS, patch_data.data());
      curl_easy_setopt(request.get(), CURLOPT_POSTFIELDSIZE,
                       static_cast<long>(patch_data.size()));
      curl_easy_setopt(request.get(), CURLOPT_WRITEFUNCTION, collect);
      curl_easy_setopt(request.get(), CURLOPT_WRITEDATA, &patch_response);
      require(curl_easy_perform(request.get()) == CURLE_OK,
              "PATCH pooled request failed");
    }
    require(patch_response == "PATCH||", "PATCH request state was incorrect");

    std::string after_patch_response;
    {
      CurlHandleLease request = pool.acquire();
      curl_easy_setopt(request.get(), CURLOPT_URL, url.c_str());
      curl_easy_setopt(request.get(), CURLOPT_WRITEFUNCTION, collect);
      curl_easy_setopt(request.get(), CURLOPT_WRITEDATA,
                       &after_patch_response);
      require(curl_easy_perform(request.get()) == CURLE_OK,
              "request after PATCH failed");
    }
    require(after_patch_response == "GET||",
            "PATCH state leaked into the following request");
    server.stop();
    server_thread.join();
  }

  curl_global_cleanup();
  return 0;
}
