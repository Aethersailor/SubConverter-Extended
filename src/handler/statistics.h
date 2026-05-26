#ifndef STATISTICS_H_INCLUDED
#define STATISTICS_H_INCLUDED

#include <cstdint>
#include <string>

#include "server/webserver.h"

namespace statistics {

void initialize();
void shutdown();
bool isEnabled();
void tick();

void recordSubscriptionConversion(const Request &request,
                                  uint64_t rule_conversions);

std::string dashboardData(RESPONSE_CALLBACK_ARGS);

} // namespace statistics

#endif // STATISTICS_H_INCLUDED
