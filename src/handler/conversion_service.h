#ifndef CONVERSION_SERVICE_H_INCLUDED
#define CONVERSION_SERVICE_H_INCLUDED

#include <functional>
#include <string>
#include <utility>

#include "server/webserver.h"
#include "utils/map_extra.h"
#include "utils/cooperative_cpu.h"

class ConversionResult {
public:
  ConversionResult(int status_code, std::string content_type,
                   string_icase_map headers, std::string body)
      : status_code_(status_code), content_type_(std::move(content_type)),
        headers_(std::move(headers)), body_(std::move(body)) {}
  ConversionResult(int status_code, std::string content_type,
                   string_icase_map headers, shared_response_body body)
      : status_code_(status_code), content_type_(std::move(content_type)),
        headers_(std::move(headers)), shared_body_(std::move(body)) {}

  int statusCode() const noexcept { return status_code_; }
  const std::string &contentType() const noexcept { return content_type_; }
  const string_icase_map &headers() const noexcept { return headers_; }
  const std::string &body() const noexcept {
    return shared_body_ ? shared_body_->content : body_;
  }
  bool hasSharedBody() const noexcept {
    return static_cast<bool>(shared_body_);
  }

  std::string releaseContentType() && noexcept {
    return std::move(content_type_);
  }
  string_icase_map releaseHeaders() && noexcept {
    return std::move(headers_);
  }
  std::string releaseBody() && noexcept { return std::move(body_); }
  shared_response_body releaseSharedBody() && noexcept {
    return std::move(shared_body_);
  }

private:
  int status_code_;
  std::string content_type_;
  string_icase_map headers_;
  std::string body_;
  shared_response_body shared_body_;
};

class ConversionService {
public:
  using Completion = std::function<void(ConversionResult)>;

  ConversionResult convertSubscription(Request &request,
                                       bool track_statistics) const;
  void convertSubscriptionAsync(Request request, bool track_statistics,
                                Completion completion) const;
};

struct ResponseMicroCacheSnapshot {
  uint64_t entries = 0;
  uint64_t bytes = 0;
  uint64_t max_bytes = 0;
};

const ConversionService &defaultConversionService();
WorkloadSchedulerSnapshot conversionSchedulerSnapshot();
WorkloadSchedulerSnapshot legacyRequestFlowSnapshot();
CpuPermitSnapshot conversionCpuPermitSnapshot();
void setConversionCpuPermitLimit(uint64_t limit) noexcept;
ResponseMicroCacheSnapshot responseMicroCacheSnapshot();
void requestConversionSchedulerShutdown() noexcept;
void shutdownConversionScheduler() noexcept;

#endif // CONVERSION_SERVICE_H_INCLUDED
