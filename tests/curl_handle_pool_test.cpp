#include <cassert>
#include <chrono>
#include <future>
#include <string>
#include <thread>

#include <curl/curl.h>

#include "handler/curl_handle_pool.h"
#include "httplib.h"
#include "server/request_context.h"

using namespace std::chrono_literals;

static size_t collect(char *data, size_t size, size_t count, void *output) {
  static_cast<std::string *>(output)->append(data, size * count);
  return size * count;
}

int main() {
  constexpr uint64_t response_limit = UINT64_C(64) * 1024 * 1024;
  configureRetainedResponseByteLimit(response_limit);
  auto first_context = std::make_shared<RequestContext>(
      "curl-budget-first", RequestContext::Clock::now());
  auto second_context = std::make_shared<RequestContext>(
      "curl-budget-second", RequestContext::Clock::now());
  assert(first_context->retainResponseBytes(response_limit));
  assert(!second_context->retainResponseBytes(1));
  std::shared_ptr<RequestContext> completed_result_owner = first_context;
  first_context.reset();
  assert(retainedResponseByteSnapshot().used == response_limit);
  completed_result_owner.reset();
  assert(retainedResponseByteSnapshot().used == 0);
  assert(second_context->retainResponseBytes(response_limit));
  second_context.reset();
  assert(retainedResponseByteSnapshot().used == 0);
  configureRetainedResponseByteLimit(0);

  assert(curl_global_init(CURL_GLOBAL_ALL) == CURLE_OK);
  {
    CurlHandlePool pool(1);

    CurlHandleLease first = pool.acquire();
    assert(first);
    CURL *original = first.get();
    curl_easy_setopt(original, CURLOPT_COOKIEFILE, "");
    curl_easy_setopt(
        original, CURLOPT_COOKIELIST,
        "example.test\tFALSE\t/\tFALSE\t0\tpool-cookie\tsecret");
    curl_slist *cookies = nullptr;
    assert(curl_easy_getinfo(original, CURLINFO_COOKIELIST, &cookies) ==
           CURLE_OK);
    assert(cookies != nullptr);
    curl_slist_free_all(cookies);

    auto waiting = std::async(std::launch::async, [&] {
      CurlHandleLease lease = pool.acquire();
      return lease.get();
    });
    assert(waiting.wait_for(50ms) == std::future_status::timeout);
    first = CurlHandleLease();
    CURL *reused = waiting.get();
    assert(reused == original);

    CurlHandleLease isolated = pool.acquire();
    assert(isolated.get() == original);
    cookies = nullptr;
    assert(curl_easy_getinfo(isolated.get(), CURLINFO_COOKIELIST, &cookies) ==
           CURLE_OK);
    assert(cookies == nullptr);
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
    assert(port > 0);
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
      assert(curl_easy_perform(request.get()) == CURLE_OK);
      curl_easy_setopt(request.get(), CURLOPT_PROXY, "http://127.0.0.1:1");
      curl_easy_setopt(request.get(), CURLOPT_NOPROXY, "");
    }
    curl_slist_free_all(headers);
    assert(first_response.find("POST|first-request|") == 0);
    assert(first_response.find("pool-cookie=secret") != std::string::npos);

    std::string second_response;
    {
      CurlHandleLease request = pool.acquire();
      curl_easy_setopt(request.get(), CURLOPT_URL, url.c_str());
      curl_easy_setopt(request.get(), CURLOPT_WRITEFUNCTION, collect);
      curl_easy_setopt(request.get(), CURLOPT_WRITEDATA, &second_response);
      assert(curl_easy_perform(request.get()) == CURLE_OK);
    }
    assert(second_response == "GET||");

    std::string head_response;
    {
      CurlHandleLease request = pool.acquire();
      curl_easy_setopt(request.get(), CURLOPT_URL, url.c_str());
      curl_easy_setopt(request.get(), CURLOPT_NOBODY, 1L);
      curl_easy_setopt(request.get(), CURLOPT_WRITEFUNCTION, collect);
      curl_easy_setopt(request.get(), CURLOPT_WRITEDATA, &head_response);
      assert(curl_easy_perform(request.get()) == CURLE_OK);
    }
    assert(head_response.empty());

    std::string after_head_response;
    {
      CurlHandleLease request = pool.acquire();
      curl_easy_setopt(request.get(), CURLOPT_URL, url.c_str());
      curl_easy_setopt(request.get(), CURLOPT_WRITEFUNCTION, collect);
      curl_easy_setopt(request.get(), CURLOPT_WRITEDATA,
                       &after_head_response);
      assert(curl_easy_perform(request.get()) == CURLE_OK);
    }
    assert(after_head_response == "GET||");

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
      assert(curl_easy_perform(request.get()) == CURLE_OK);
    }
    assert(patch_response == "PATCH||");

    std::string after_patch_response;
    {
      CurlHandleLease request = pool.acquire();
      curl_easy_setopt(request.get(), CURLOPT_URL, url.c_str());
      curl_easy_setopt(request.get(), CURLOPT_WRITEFUNCTION, collect);
      curl_easy_setopt(request.get(), CURLOPT_WRITEDATA,
                       &after_patch_response);
      assert(curl_easy_perform(request.get()) == CURLE_OK);
    }
    assert(after_patch_response == "GET||");
    server.stop();
    server_thread.join();
  }

  curl_global_cleanup();
  return 0;
}
