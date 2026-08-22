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
  // Completion may run synchronously or from handler, flow-worker, shutdown,
  // or request-cancellation threads. Transport adapters must marshal socket
  // work back to the connection executor.
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

struct SubscriptionSingleflightSnapshot {
  uint64_t active_owners = 0;
  uint64_t waiting_followers = 0;
  uint64_t owners_created_total = 0;
  uint64_t followers_attached_total = 0;
  uint64_t followers_cancelled_total = 0;
  uint64_t owners_cancelled_no_consumers_total = 0;
  uint64_t owner_flow_rejected_total = 0;
};

struct SubscriptionOwnerAdmissionSnapshot {
  std::string source = "not_initialized";
  uint64_t waiting_entries = 0;
  uint64_t waiting_bytes = 0;
  uint64_t active = 0;
  uint64_t accepted_total = 0;
  uint64_t rejected_total = 0;
  uint64_t cancelled_total = 0;
  uint64_t max_wait_entries = 0;
  uint64_t max_wait_bytes = 0;
  uint64_t oldest_wait_ms = 0;
};

const ConversionService &defaultConversionService();
WorkloadSchedulerSnapshot conversionSchedulerSnapshot();
WorkloadSchedulerSnapshot legacyRequestFlowSnapshot();
CpuPermitSnapshot conversionCpuPermitSnapshot();
void setConversionCpuPermitLimit(uint64_t limit) noexcept;
ResponseMicroCacheSnapshot responseMicroCacheSnapshot();
SubscriptionSingleflightSnapshot subscriptionSingleflightSnapshot() noexcept;
SubscriptionOwnerAdmissionSnapshot subscriptionOwnerAdmissionSnapshot();
void requestConversionSchedulerShutdown() noexcept;
void shutdownConversionScheduler() noexcept;

#endif // CONVERSION_SERVICE_H_INCLUDED
