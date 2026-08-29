#ifndef DASHBOARD_AUTH_H_INCLUDED
#define DASHBOARD_AUTH_H_INCLUDED

#include <algorithm>
#include <string>

#include "handler/settings.h"
#include "handler/settings_view.h"
#include "server/webserver.h"
#include "utils/base64/base64.h"
#include "utils/string.h"

namespace dashboard_auth {

inline bool validAuthorizationHeader(const std::string &authorization,
                                     const Settings &settings) {
  constexpr size_t kMaximumAuthorizationBytes = 1024;
  if (settings.dashboardAuthUsername.empty() ||
      settings.dashboardAuthPassword.empty() || authorization.size() == 0 ||
      authorization.size() > kMaximumAuthorizationBytes)
    return false;
  std::string auth = trimWhitespace(authorization, true, true);
  if (auth.size() <= 6 || toLower(auth.substr(0, 6)) != "basic ")
    return false;
  const std::string supplied =
      "Basic " + trimWhitespace(auth.substr(6), true, true);
  const std::string expected =
      "Basic " + base64Encode(settings.dashboardAuthUsername + ":" +
                              settings.dashboardAuthPassword);
  if (expected.size() > kMaximumAuthorizationBytes)
    return false;
  size_t diff = supplied.size() ^ expected.size();
  const size_t length = std::max(supplied.size(), expected.size());
  for (size_t i = 0; i < length; ++i) {
    const unsigned char left =
        i < supplied.size() ? static_cast<unsigned char>(supplied[i]) : 0;
    const unsigned char right =
        i < expected.size() ? static_cast<unsigned char>(expected[i]) : 0;
    diff |= static_cast<size_t>(left ^ right);
  }
  return diff == 0;
}

inline bool validAuthorizationHeader(const std::string &authorization) {
  const SettingsSnapshot settings = captureSettingsSnapshot();
  return settings && validAuthorizationHeader(authorization, *settings);
}

std::string page(RESPONSE_CALLBACK_ARGS);
std::string data(RESPONSE_CALLBACK_ARGS);

} // namespace dashboard_auth

#endif // DASHBOARD_AUTH_H_INCLUDED
