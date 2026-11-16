#ifndef SUBSCRIPTION_USERINFO_H_INCLUDED
#define SUBSCRIPTION_USERINFO_H_INCLUDED

#include <string_view>

struct SubscriptionUserInfoFields {
  std::string_view upload;
  std::string_view download;
  std::string_view total;
  std::string_view expire;
};

inline SubscriptionUserInfoFields parseSubscriptionUserInfoFields(
    std::string_view header) {
  const auto trim_field = [](std::string_view field) {
    const auto first = field.find_first_not_of(" \t");
    if (first == std::string_view::npos)
      return std::string_view{};
    return field.substr(first, field.find_last_not_of(" \t") - first + 1);
  };

  SubscriptionUserInfoFields result;
  while (!header.empty()) {
    const auto end = header.find(';');
    const auto field = header.substr(0, end);
    header.remove_prefix(end == std::string_view::npos ? header.size() : end + 1);
    const auto separator = field.find('=');
    if (separator == std::string_view::npos)
      continue;

    const auto key = trim_field(field.substr(0, separator));
    if (key == "upload")
      result.upload = trim_field(field.substr(separator + 1));
    else if (key == "download")
      result.download = trim_field(field.substr(separator + 1));
    else if (key == "total")
      result.total = trim_field(field.substr(separator + 1));
    else if (key == "expire")
      result.expire = trim_field(field.substr(separator + 1));
  }
  return result;
}

#endif // SUBSCRIPTION_USERINFO_H_INCLUDED
