#ifndef DASHBOARD_AUTH_H_INCLUDED
#define DASHBOARD_AUTH_H_INCLUDED

#include <string>

#include "server/webserver.h"

namespace dashboard_auth {

std::string page(RESPONSE_CALLBACK_ARGS);
std::string data(RESPONSE_CALLBACK_ARGS);

} // namespace dashboard_auth

#endif // DASHBOARD_AUTH_H_INCLUDED
