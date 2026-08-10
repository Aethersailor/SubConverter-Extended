#include "handler/dashboard_auth.h"

#include <algorithm>
#include <atomic>
#include <string>

#include "handler/dashboard_auth_limiter.h"
#include "handler/dashboard_page.h"
#include "handler/settings.h"
#include "handler/statistics.h"
#include "utils/base64/base64.h"
#include "utils/logger.h"
#include "utils/string.h"

namespace {

dashboard_auth::FailureLimiter g_failure_limiter;
std::atomic_bool g_misconfig_logged{false};

std::string headerValue(const Request &request, const std::string &name) {
  auto iter = request.headers.find(name);
  if (iter == request.headers.end())
    return "";
  return trimWhitespace(iter->second, true, true);
}

bool constantTimeEquals(const std::string &lhs, const std::string &rhs) {
  unsigned char diff = static_cast<unsigned char>(lhs.size() ^ rhs.size());
  size_t length = std::max(lhs.size(), rhs.size());
  for (size_t i = 0; i < length; ++i) {
    unsigned char left =
        i < lhs.size() ? static_cast<unsigned char>(lhs[i]) : 0;
    unsigned char right =
        i < rhs.size() ? static_cast<unsigned char>(rhs[i]) : 0;
    diff |= static_cast<unsigned char>(left ^ right);
  }
  return diff == 0;
}

bool validBasicAuth(const Request &request) {
  std::string auth = headerValue(request, "Authorization");
  if (auth.size() <= 6 || toLower(auth.substr(0, 6)) != "basic ")
    return false;
  std::string supplied = "Basic " + trimWhitespace(auth.substr(6), true, true);
  static const std::string expected =
      "Basic " + base64Encode(global.dashboardAuthUsername + ":" +
                              global.dashboardAuthPassword);
  return constantTimeEquals(supplied, expected);
}

void applyNoStoreHeaders(Response &response) {
  response.headers["Cache-Control"] =
      "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, "
      "s-maxage=0";
  response.headers["Pragma"] = "no-cache";
  response.headers["Expires"] = "0";
  response.headers["Surrogate-Control"] = "no-store";
  response.headers["X-Accel-Expires"] = "0";
}

std::string unauthorized(Response &response) {
  response.status_code = 401;
  response.content_type = "text/plain; charset=utf-8";
  applyNoStoreHeaders(response);
  response.headers["WWW-Authenticate"] =
      "Basic realm=\"SubConverter-Extended Dashboard\", charset=\"UTF-8\"";
  response.headers["X-Robots-Tag"] =
      "noindex, nofollow, noarchive, nosnippet, noimageindex";
  return "Unauthorized: missing or invalid dashboard credentials.\n"
         "未授权：Dashboard 用户名或密码缺失或无效。\n";
}

std::string locked(Response &response, int64_t retry_after) {
  response.status_code = 429;
  response.content_type = "text/plain; charset=utf-8";
  applyNoStoreHeaders(response);
  response.headers["Retry-After"] = std::to_string(std::max<int64_t>(
      1, retry_after));
  response.headers["X-Robots-Tag"] =
      "noindex, nofollow, noarchive, nosnippet, noimageindex";
  return "Too many failed dashboard login attempts. Try again later.\n"
         "Dashboard 登录失败次数过多，请稍后再试。\n";
}

std::string misconfigured(Response &response) {
  bool expected = false;
  if (g_misconfig_logged.compare_exchange_strong(expected, true)) {
    writeLog(LOG_LEVEL_WARNING,
             "Dashboard 认证已启用，但用户名或密码为空，已拒绝访问。");
  }
  response.status_code = 503;
  response.content_type = "text/plain; charset=utf-8";
  applyNoStoreHeaders(response);
  response.headers["X-Robots-Tag"] =
      "noindex, nofollow, noarchive, nosnippet, noimageindex";
  return "Dashboard authentication is enabled but not configured.\n"
         "Dashboard 认证已启用，但用户名或密码未配置。\n";
}

bool authorize(Request &request, Response &response, std::string &body) {
  if (!global.dashboardAuthEnabled)
    return true;

  if (global.dashboardAuthUsername.empty() ||
      global.dashboardAuthPassword.empty()) {
    body = misconfigured(response);
    return false;
  }

  bool ok = validBasicAuth(request);
  const dashboard_auth::FailureLimiter::Decision decision =
      g_failure_limiter.evaluate(
          request.client_address, ok, global.dashboardAuthMaxFailures,
          global.dashboardAuthWindowSeconds, global.dashboardAuthLockSeconds);
  if (decision.result == dashboard_auth::FailureLimiter::Result::Allowed)
    return true;
  if (decision.result == dashboard_auth::FailureLimiter::Result::Locked)
    body = locked(response, decision.retry_after_seconds);
  else
    body = unauthorized(response);
  return false;
}

} // namespace

namespace dashboard_auth {

std::string page(RESPONSE_CALLBACK_ARGS) {
  std::string body;
  if (!authorize(request, response, body))
    return body;
  return dashboard_page::page(request, response);
}

std::string data(RESPONSE_CALLBACK_ARGS) {
  std::string body;
  if (!authorize(request, response, body))
    return body;
  return statistics::dashboardData(request, response);
}

} // namespace dashboard_auth
