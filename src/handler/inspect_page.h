#ifndef INSPECT_PAGE_H_INCLUDED
#define INSPECT_PAGE_H_INCLUDED

#include <string>

#include "server/webserver.h"

namespace inspect_page {

std::string page(Request &, Response &response);

} // namespace inspect_page

#endif // INSPECT_PAGE_H_INCLUDED
