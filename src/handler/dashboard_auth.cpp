#include "handler/dashboard_auth.h"

#include <algorithm>
#include <atomic>
#include <ctime>
#include <map>
#include <mutex>
#include <string>

#include "handler/dashboard_page.h"
#include "handler/settings.h"
#include "handler/statistics.h"
#include "utils/base64/base64.h"
#include "utils/logger.h"
#include "utils/string.h"

namespace {

struct FailureState {
  int failures = 0;
  int64_t window_start = 0;
  int64_t locked_until = 0;
};

std::mutex g_auth_mutex;
std::map<std::string, FailureState> g_failures;
std::atomic_bool g_misconfig_logged{false};

int64_t nowSeconds() { return static_cast<int64_t>(std::time(nullptr)); }

std::string headerValue(const Request &request, const std::string &name) {
  auto iter = request.headers.find(name);
  if (iter == request.headers.end())
    return "";
  return trimWhitespace(iter->second, true, true);
}

std::string firstForwardedValue(std::string value) {
  size_t comma = value.find(',');
  if (comma != std::string::npos)
    value = value.substr(0, comma);
  return trimWhitespace(value, true, true);
}

std::string sourceKey(const Request &request) {
  std::string forwarded = headerValue(request, "CF-Connecting-IP");
  if (forwarded.empty())
    forwarded = headerValue(request, "True-Client-IP");
  if (forwarded.empty())
    forwarded = headerValue(request, "X-Real-IP");
  if (forwarded.empty())
    forwarded = firstForwardedValue(headerValue(request, "X-Forwarded-For"));
  if (forwarded.empty())
    forwarded = headerValue(request, "X-Client-IP");
  if (!forwarded.empty())
    return forwarded;
  if (!request.remote_addr.empty())
    return request.remote_addr;
  return "unknown";
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
  std::string expected =
      "Basic " + base64Encode(global.dashboardAuthUsername + ":" +
                              global.dashboardAuthPassword);
  return constantTimeEquals(supplied, expected);
}

void cleanupFailuresLocked(int64_t now) {
  for (auto iter = g_failures.begin(); iter != g_failures.end();) {
    const FailureState &state = iter->second;
    bool lock_expired = state.locked_until <= now;
    bool window_expired =
        now - state.window_start > global.dashboardAuthWindowSeconds;
    if (lock_expired && window_expired)
      iter = g_failures.erase(iter);
    else
      ++iter;
  }
  while (g_failures.size() > 4096)
    g_failures.erase(g_failures.begin());
}

int64_t lockedUntilLocked(const std::string &key, int64_t now) {
  auto iter = g_failures.find(key);
  if (iter == g_failures.end())
    return 0;
  if (iter->second.locked_until > now)
    return iter->second.locked_until;
  return 0;
}

void recordFailureLocked(const std::string &key, int64_t now) {
  FailureState &state = g_failures[key];
  if (state.window_start <= 0 ||
      now - state.window_start > global.dashboardAuthWindowSeconds) {
    state.window_start = now;
    state.failures = 0;
    state.locked_until = 0;
  }
  state.failures++;
  if (state.failures >= global.dashboardAuthMaxFailures)
    state.locked_until = now + global.dashboardAuthLockSeconds;
}

void recordSuccessLocked(const std::string &key) { g_failures.erase(key); }

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
    writeLog(0,
             "Dashboard 认证已启用，但用户名或密码为空，已拒绝访问。",
             LOG_LEVEL_WARNING);
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

  int64_t now = nowSeconds();
  std::string key = sourceKey(request);

  {
    std::lock_guard<std::mutex> lock(g_auth_mutex);
    cleanupFailuresLocked(now);
    int64_t locked_until = lockedUntilLocked(key, now);
    if (locked_until > now) {
      body = locked(response, locked_until - now);
      return false;
    }
  }

  bool ok = validBasicAuth(request);

  std::lock_guard<std::mutex> lock(g_auth_mutex);
  if (ok) {
    recordSuccessLocked(key);
    return true;
  }

  recordFailureLocked(key, now);
  int64_t locked_until = lockedUntilLocked(key, now);
  if (locked_until > now)
    body = locked(response, locked_until - now);
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
