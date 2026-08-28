#include "handler/upload_async.h"

#include <atomic>
#include <utility>

#include <rapidjson/document.h>

#include "handler/proxy_policy.h"
#include "handler/settings.h"
#include "handler/upload.h"
#include "handler/webget.h"
#include "utils/ini_reader/ini_reader.h"
#include "utils/rapidjson_extra.h"
#include "utils/system.h"

namespace {

std::string asyncGistApiUrl(const std::string &path) {
  std::string base =
      trimWhitespace(getEnv("SUBCONVERTER_GIST_API_BASE"), true, true);
  if (base.empty())
    base = "https://api.github.com";
  while (endsWith(base, "/"))
    base.pop_back();
  return base + path;
}

class AsyncGistUploadState
    : public std::enable_shared_from_this<AsyncGistUploadState> {
public:
  AsyncGistUploadState(
      std::string name, std::string path, std::string content,
      bool write_manage_url, SettingsSnapshot settings,
      std::shared_ptr<RequestContext> request_context,
      AsyncUploadCompletion completion)
      : name_(std::move(name)), path_(std::move(path)),
        content_(std::move(content)),
        write_manage_url_(write_manage_url),
        settings_(std::move(settings)),
        request_context_(std::move(request_context)),
        completion_(std::move(completion)) {}

  void start() {
    if (!retained_.retain(content_.size())) {
      finish(AsyncUploadStatus::Capacity, 0);
      return;
    }
    // ConversionFlow invokes optional uploads from its already-admitted
    // compute worker. Preparing the small request descriptor here avoids
    // queueing back into the same executor before Curl multi can begin.
    prepare();
  }

private:
  void prepare() {
    if (request_context_->cancellationToken().isCancellationRequested()) {
      finish(AsyncUploadStatus::Cancelled, 0);
      return;
    }
    ScopedSettingsView settings_view(settings_);
    ScopedRequestContext request_scope(request_context_);
    INIReader ini;
    if (!fileExist("gistconf.ini") ||
        ini.parse_file("gistconf.ini") != 0 ||
        ini.enter_section("common") != 0) {
      finish(AsyncUploadStatus::ConfigFailed, 0);
      return;
    }
    token_ = ini.get("token");
    if (token_.empty()) {
      finish(AsyncUploadStatus::ConfigFailed, 0);
      return;
    }
    id_ = ini.get("id");
    username_ = ini.get("username");
    if (path_.empty()) {
      if (ini.item_exist("path"))
        path_ = ini.get(name_, "path");
      else
        path_ = name_;
    }
    http_method method = HTTP_POST;
    std::string url = asyncGistApiUrl("/gists");
    if (!id_.empty()) {
      method = HTTP_PATCH;
      url = asyncGistApiUrl("/gists/" + id_);
      if (write_manage_url_) {
        const std::string managed =
            "https://gist.githubusercontent.com/" + username_ + "/" +
            id_ + "/raw/" + path_;
        const std::string prefix = "#!MANAGED-CONFIG " + managed + "\n";
        if (!retained_.retain(prefix.size())) {
          finish(AsyncUploadStatus::Capacity, 0);
          return;
        }
        content_ = prefix + content_;
      }
    }
    if (network_started_.exchange(true, std::memory_order_acq_rel))
      return;
    AsyncFetchRequest request;
    request.method = method;
    request.url = std::move(url);
    request.proxy = parseProxy(settings_->proxyConfig,
                               settings_->proxyBypass);
    request.post_data = buildGistData(path_, content_);
    if (!retained_.retain(request.post_data.size())) {
      finish(AsyncUploadStatus::Capacity, 0);
      return;
    }
    request.has_post_data = true;
    request.request_headers = {{"Authorization", "token " + token_}};
    request.capture_content = true;
    // Gist creation succeeds with 201 rather than the generic fetch layer's
    // 200-only success convention. Preserve the response so this owner can
    // validate the method-specific status and parse the returned identity.
    request.keep_resp_on_fail = true;
    request.context = FetchContext::TrustedConfig;
    request.deadline = request_context_->deadline();
    request.cancellation = request_context_->cancellationToken();
    request.request_context = request_context_;
    request.retain_result_bytes = true;
    webGetAsync(
        std::move(request),
        [self = shared_from_this(), method](
            SharedAsyncFetchResult result) mutable {
          self->networkComplete(method, std::move(result));
        });
  }

  void networkComplete(http_method method,
                       SharedAsyncFetchResult result) noexcept {
    if (!result || result->failure == AsyncFetchFailure::Cancelled ||
        result->failure == AsyncFetchFailure::Deadline) {
      finish(AsyncUploadStatus::Cancelled,
             result ? result->status_code : 0);
      return;
    }
    const int expected = method == HTTP_POST ? 201 : 200;
    if (result->failure != AsyncFetchFailure::None ||
        result->status_code != expected) {
      finish(AsyncUploadStatus::RemoteFailed, result->status_code);
      return;
    }
    auto self = shared_from_this();
    const uint64_t bytes = result->content.size();
    (void)submitOwnedWebGetContinuation(
        RequestCostClass::Low, bytes,
        RequestContext::Clock::time_point::max(), {},
        [self, result = std::move(result)]() mutable {
          self->persist(std::move(result));
        },
        [self, expected](SchedulerSubmitStatus status,
                         std::exception_ptr error) {
          if (status != SchedulerSubmitStatus::Accepted || error)
            self->finish(AsyncUploadStatus::LocalStateFailed, expected);
        });
  }

  void persist(SharedAsyncFetchResult result) {
    rapidjson::Document json;
    json.Parse(result->content.data());
    GetMember(json, "id", id_);
    if (json.HasMember("owner"))
      GetMember(json["owner"], "login", username_);
    if (id_.empty() || username_.empty()) {
      finish(AsyncUploadStatus::RemoteFailed, result->status_code);
      return;
    }
    const std::string url =
        "https://gist.githubusercontent.com/" + username_ + "/" + id_ +
        "/raw/" + path_;
    INIReader ini;
    if (fileExist("gistconf.ini"))
      (void)ini.parse_file("gistconf.ini");
    (void)ini.enter_section("common");
    ini.erase_section();
    ini.set("token", token_);
    ini.set("id", id_);
    ini.set("username", username_);
    ini.set_current_section(path_);
    ini.erase_section();
    ini.set("type", name_);
    ini.set("url", url);
    const FileCommitResult persisted =
        static_cast<FileCommitResult>(ini.to_file("gistconf.ini"));
    finish(fileCommitFailed(persisted)
               ? AsyncUploadStatus::LocalStateFailed
               : AsyncUploadStatus::Success,
           result->status_code);
  }

  void finish(AsyncUploadStatus status, int remote_status) noexcept {
    if (completed_.exchange(true, std::memory_order_acq_rel))
      return;
    AsyncUploadCompletion completion = std::move(completion_);
    if (!completion)
      return;
    try {
      completion({status, remote_status});
    } catch (...) {
    }
  }

  const std::string name_;
  std::string path_;
  std::string content_;
  const bool write_manage_url_;
  const SettingsSnapshot settings_;
  const std::shared_ptr<RequestContext> request_context_;
  AsyncUploadCompletion completion_;
  std::string token_;
  std::string id_;
  std::string username_;
  RetainedResponseByteLease retained_;
  std::atomic<bool> network_started_{false};
  std::atomic<bool> completed_{false};
};

} // namespace

void uploadGistAsync(
    std::string name, std::string path, std::string content,
    bool write_manage_url, SettingsSnapshot settings,
    std::shared_ptr<RequestContext> request_context,
    AsyncUploadCompletion completion) {
  if (!settings || !request_context || !completion) {
    if (completion)
      completion({AsyncUploadStatus::Capacity, 0});
    return;
  }
  try {
    auto state = std::make_shared<AsyncGistUploadState>(
        std::move(name), std::move(path), std::move(content),
        write_manage_url, settings, request_context, completion);
    state->start();
  } catch (...) {
    completion({AsyncUploadStatus::Capacity, 0});
  }
}
