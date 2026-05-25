#ifndef DEBUG_PAGE_H_INCLUDED
#define DEBUG_PAGE_H_INCLUDED

#include <string>

#include "server/webserver.h"

namespace debug_page {

std::string page(Request &, Response &response);

} // namespace debug_page

#endif // DEBUG_PAGE_H_INCLUDED
