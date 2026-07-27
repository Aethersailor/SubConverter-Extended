#include "handler/sub_request_key.h"

#include <algorithm>
#include <cctype>
#include <cstddef>

#include "utils/md5/md5_interface.h"
#include "version.h"

namespace {

class SubRequestKeyBuilder {
public:
  bool append(const std::string &name, const std::string &value) {
    static constexpr size_t kMaxIdentitySize = 2 * 1024 * 1024;
    size_t extra_size = name.size() + value.size() + 32;
    if (size_ + extra_size > kMaxIdentitySize)
      return false;

    std::string value_size = std::to_string(value.size());
    process(name);
    process(":", 1);
    process(value_size);
    process(":", 1);
    process(value);
    process("\n", 1);
    size_ += name.size() + value_size.size() + value.size() + 3;
    return true;
  }

  std::string finish() {
    char digest[MD5_STRING_SIZE];
    md5_.finish();
    md5_.get_string(digest);
    return digest;
  }

private:
  void process(const std::string &value) {
    process(value.data(), value.size());
  }
  void process(const char *value, size_t size) {
    md5_.process(value, static_cast<uint32_t>(size));
  }

  md5::md5_t md5_;
  size_t size_ = 0;
};

std::string lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char ch) {
                   return static_cast<char>(std::tolower(ch));
                 });
  return value;
}

std::string trimHeaderName(const std::string &value) {
  size_t begin = value.find_first_not_of(" \t\r\n");
  if (begin == std::string::npos)
    return "";
  size_t end = value.find_last_not_of(" \t\r\n");
  return value.substr(begin, end - begin + 1);
}

bool appendHeader(SubRequestKeyBuilder &identity, const Request &request,
                  const std::string &name) {
  auto header = request.headers.find(name);
  const std::string value =
      header == request.headers.end() ? std::string() : header->second;
  return identity.append("header_name", lower(name)) &&
         identity.append("header_value", value);
}

} // namespace

std::string buildSubRequestKey(
    const Request &request, const std::string &age_recipient_fingerprint,
    uint64_t config_generation, const std::string &managed_config_prefix) {
  SubRequestKeyBuilder identity;
  if (!identity.append("version", VERSION) ||
      !identity.append("config_generation",
                       std::to_string(config_generation)) ||
      !identity.append("managed_config_prefix", managed_config_prefix) ||
      !identity.append("method", request.method) ||
      !identity.append("path", request.url) ||
      !identity.append("age_recipient_fingerprint",
                       age_recipient_fingerprint))
    return "";

  for (const auto &arg : request.argument) {
    if (!identity.append("arg_name", arg.first) ||
        !identity.append("arg_value", arg.second))
      return "";
  }

  if (!appendHeader(identity, request, "User-Agent"))
    return "";
  std::string selected;
  auto selected_arg = request.argument.find("provider_headers");
  if (selected_arg != request.argument.end())
    selected = selected_arg->second;
  size_t begin = 0;
  while (begin <= selected.size()) {
    size_t end = selected.find(',', begin);
    std::string name = trimHeaderName(
        selected.substr(begin, end == std::string::npos
                                   ? std::string::npos
                                   : end - begin));
    if (!name.empty() && !appendHeader(identity, request, name))
      return "";
    if (end == std::string::npos)
      break;
    begin = end + 1;
  }
  return identity.finish();
}
