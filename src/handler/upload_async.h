#ifndef UPLOAD_ASYNC_H_INCLUDED
#define UPLOAD_ASYNC_H_INCLUDED

#include <functional>
#include <memory>
#include <string>

#include "handler/settings_view.h"
#include "server/request_context.h"

enum class AsyncUploadStatus {
  Success,
  Cancelled,
  ConfigFailed,
  RemoteFailed,
  LocalStateFailed,
  Capacity,
};

struct AsyncUploadResult {
  AsyncUploadStatus status = AsyncUploadStatus::Capacity;
  int remote_status = 0;
};

using AsyncUploadCompletion = std::function<void(AsyncUploadResult)>;

void uploadGistAsync(
    std::string name, std::string path, std::string content,
    bool write_manage_url, SettingsSnapshot settings,
    std::shared_ptr<RequestContext> request_context,
    AsyncUploadCompletion completion);

#endif // UPLOAD_ASYNC_H_INCLUDED
