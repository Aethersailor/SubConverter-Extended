#ifndef SUB_REQUEST_KEY_H_INCLUDED
#define SUB_REQUEST_KEY_H_INCLUDED

#include <cstdint>
#include <string>

#include "server/webserver.h"

std::string buildSubRequestKey(
    const Request &request, const std::string &age_recipient_fingerprint,
    uint64_t config_generation, const std::string &managed_config_prefix);

#endif // SUB_REQUEST_KEY_H_INCLUDED
