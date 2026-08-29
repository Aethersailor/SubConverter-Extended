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

bool validBasicAuth(const Request &request, const Settings &settings) {
  return dashboard_auth::validAuthorizationHeader(
      headerValue(request, "Authorization"), settings);
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
  const SettingsSnapshot settings_snapshot =
      captureEffectiveSettingsSnapshot();
  if (!settings_snapshot) {
    body = misconfigured(response);
    return false;
  }
  const Settings &settings = *settings_snapshot;
  if (!settings.dashboardAuthEnabled)
    return true;

  if (settings.dashboardAuthUsername.empty() ||
      settings.dashboardAuthPassword.empty()) {
    body = misconfigured(response);
    return false;
  }

  bool ok = validBasicAuth(request, settings);
  const dashboard_auth::FailureLimiter::Decision decision =
      g_failure_limiter.evaluate(
          request.client_address, ok, settings.dashboardAuthMaxFailures,
          settings.dashboardAuthWindowSeconds,
          settings.dashboardAuthLockSeconds);
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
