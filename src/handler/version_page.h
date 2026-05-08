#ifndef VERSION_PAGE_H_INCLUDED
#define VERSION_PAGE_H_INCLUDED

#include <string>

#include "server/webserver.h"

namespace version_page {

std::string faviconDark(Request &, Response &response);
std::string faviconLight(Request &, Response &response);
std::string page(Request &, Response &response);

} // namespace version_page

#endif // VERSION_PAGE_H_INCLUDED
