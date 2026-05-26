#ifndef DASHBOARD_PAGE_H_INCLUDED
#define DASHBOARD_PAGE_H_INCLUDED

#include <string>

#include "server/webserver.h"

namespace dashboard_page {

std::string page(Request &request, Response &response);

} // namespace dashboard_page

#endif // DASHBOARD_PAGE_H_INCLUDED
