#ifndef USER_AGENT_H_INCLUDED
#define USER_AGENT_H_INCLUDED

#include <string>

#include "utils/tribool.h"

struct UserAgentMatch {
  bool matched = false;
  std::string family;
};

UserAgentMatch matchUserAgent(const std::string &user_agent,
                              std::string &target,
                              tribool &clash_new_name,
                              int &surge_ver);

#endif // USER_AGENT_H_INCLUDED
