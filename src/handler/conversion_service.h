#ifndef CONVERSION_SERVICE_H_INCLUDED
#define CONVERSION_SERVICE_H_INCLUDED

#include <string>
#include <utility>

#include "server/webserver.h"
#include "utils/map_extra.h"

class ConversionResult {
public:
  ConversionResult(int status_code, std::string content_type,
                   string_icase_map headers, std::string body)
      : status_code_(status_code), content_type_(std::move(content_type)),
        headers_(std::move(headers)), body_(std::move(body)) {}

  int statusCode() const noexcept { return status_code_; }
  const std::string &contentType() const noexcept { return content_type_; }
  const string_icase_map &headers() const noexcept { return headers_; }
  const std::string &body() const noexcept { return body_; }

  std::string releaseContentType() && noexcept {
    return std::move(content_type_);
  }
  string_icase_map releaseHeaders() && noexcept {
    return std::move(headers_);
  }
  std::string releaseBody() && noexcept { return std::move(body_); }

private:
  int status_code_;
  std::string content_type_;
  string_icase_map headers_;
  std::string body_;
};

class ConversionService {
public:
  ConversionResult convertSubscription(Request &request,
                                       bool track_statistics) const;
};

const ConversionService &defaultConversionService();

#endif // CONVERSION_SERVICE_H_INCLUDED
