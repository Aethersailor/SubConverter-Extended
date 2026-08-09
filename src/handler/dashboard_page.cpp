#include "handler/dashboard_page.h"
#include "generated/dashboard_page.html.inc"

namespace dashboard_page {

std::string page(Request &, Response &response) {
  response.headers["Cache-Control"] =
      "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, "
      "s-maxage=0";
  response.headers["Pragma"] = "no-cache";
  response.headers["Expires"] = "0";
  response.headers["Surrogate-Control"] = "no-store";
  response.headers["X-Accel-Expires"] = "0";
  response.headers["X-Robots-Tag"] =
      "noindex, nofollow, noarchive, nosnippet, noimageindex";

  return std::string(
      reinterpret_cast<const char *>(dashboard_resource::kDashboardHtml),
      sizeof(dashboard_resource::kDashboardHtml));
}

} // namespace dashboard_page
