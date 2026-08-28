#include "handler/upload_async.h"

#include <atomic>
#include <deque>
#include <mutex>
#include <utility>
#include <vector>

#include <rapidjson/document.h>

#include "handler/proxy_policy.h"
#include "handler/settings.h"
#include "handler/upload.h"
#include "handler/webget.h"
#include "runtime/blocking_io_executor.h"
#include "utils/ini_reader/ini_reader.h"
#include "utils/rapidjson_extra.h"
#include "utils/system.h"

namespace {

struct GistPersistenceJob {
  std::function<AsyncUploadStatus(INIReader &)> apply;
  std::function<void(AsyncUploadStatus)> completion;
};

class GistPersistenceCoordinator {
public:
  void enqueue(GistPersistenceJob job) noexcept {
    bool schedule = false;
    try {
      std::lock_guard<std::mutex> lock(mutex_);
      pending_.emplace_back(std::move(job));
      if (!running_) {
        running_ = true;
        schedule = true;
      }
    } catch (...) {
      completeJob(job, AsyncUploadStatus::LocalStateFailed);
      return;
    }
    if (!schedule)
      return;
    (void)submitBlockingIo(
        {.cost = RequestCostClass::Low,
         .bytes = 0,
         .deadline = RequestContext::Clock::time_point::max(),
         .cancellation = {},
         .preferred_worker = {}},
        [this] { drain(); },
        [this](SchedulerSubmitStatus status, std::exception_ptr error) {
          if (status != SchedulerSubmitStatus::Accepted || error)
            failPending();
        });
  }

private:
  static void completeJob(GistPersistenceJob &job,
                          AsyncUploadStatus status) noexcept {
    if (!job.completion)
      return;
    try {
      job.completion(status);
    } catch (...) {
    }
  }

  void failPending() noexcept {
    std::deque<GistPersistenceJob> failed;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      failed.swap(pending_);
      running_ = false;
    }
    for (auto &job : failed)
      completeJob(job, AsyncUploadStatus::LocalStateFailed);
  }

  void drain() noexcept {
    for (;;) {
      std::deque<GistPersistenceJob> batch;
      {
        std::lock_guard<std::mutex> lock(mutex_);
        if (pending_.empty()) {
          running_ = false;
          return;
        }
        batch.swap(pending_);
      }

      std::vector<AsyncUploadStatus> statuses(
          batch.size(), AsyncUploadStatus::LocalStateFailed);
      bool commit = false;
      bool committed = false;
      try {
        INIReader ini;
        if (fileExist("gistconf.ini"))
          (void)ini.parse_file("gistconf.ini");
        for (size_t index = 0; index < batch.size(); ++index) {
          if (!batch[index].apply)
            continue;
          statuses[index] = batch[index].apply(ini);
          commit = commit || statuses[index] == AsyncUploadStatus::Success;
        }
        if (commit) {
          const FileCommitResult persisted =
              static_cast<FileCommitResult>(ini.to_file("gistconf.ini"));
          committed = !fileCommitFailed(persisted);
        }
      } catch (...) {
        committed = false;
      }
      for (size_t index = 0; index < batch.size(); ++index) {
        AsyncUploadStatus status = statuses[index];
        if (status == AsyncUploadStatus::Success && !committed)
          status = AsyncUploadStatus::LocalStateFailed;
        completeJob(batch[index], status);
      }
    }
  }

  std::mutex mutex_;
  std::deque<GistPersistenceJob> pending_;
  bool running_ = false;
};

GistPersistenceCoordinator gist_persistence;

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
    auto self = shared_from_this();
    (void)submitOwnedWebGetContinuation(
        RequestCostClass::Low, content_.size(),
        request_context_->deadline(),
        request_context_->cancellationToken(),
        [self] { self->prepare(); },
        [self](SchedulerSubmitStatus status, std::exception_ptr error) {
          if (status == SchedulerSubmitStatus::Cancelled ||
              status == SchedulerSubmitStatus::Deadline)
            self->finish(AsyncUploadStatus::Cancelled, 0);
          else if (status != SchedulerSubmitStatus::Accepted || error)
            self->finish(AsyncUploadStatus::Capacity, 0);
        });
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
    const int remote_status = result->status_code;
    gist_persistence.enqueue(
        {[self, result = std::move(result)](INIReader &ini) mutable {
           return self->preparePersistence(ini, std::move(result));
         },
         [self, remote_status](AsyncUploadStatus status) {
           self->finish(status, remote_status);
         }});
  }

  AsyncUploadStatus preparePersistence(INIReader &ini,
                                       SharedAsyncFetchResult result) {
    rapidjson::Document json;
    json.Parse(result->content.data());
    GetMember(json, "id", id_);
    if (json.HasMember("owner"))
      GetMember(json["owner"], "login", username_);
    if (id_.empty() || username_.empty()) {
      return AsyncUploadStatus::RemoteFailed;
    }
    const std::string url =
        "https://gist.githubusercontent.com/" + username_ + "/" + id_ +
        "/raw/" + path_;
    (void)ini.enter_section("common");
    ini.erase_section();
    ini.set("token", token_);
    ini.set("id", id_);
    ini.set("username", username_);
    ini.set_current_section(path_);
    ini.erase_section();
    ini.set("type", name_);
    ini.set("url", url);
    return AsyncUploadStatus::Success;
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
