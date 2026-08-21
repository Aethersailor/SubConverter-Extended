#ifndef STATISTICS_H_INCLUDED
#define STATISTICS_H_INCLUDED

#include <cstdint>
#include <string>

#include "server/webserver.h"

namespace statistics {

struct SubscriptionConversionMetadata {
  uint16_t country = UINT16_MAX;
  uint16_t china_region = UINT16_MAX;
  bool eligible = false;
};

void initialize();
void shutdown();
bool isEnabled();
void tick();

void recordSubscriptionConversion(const Request &request,
                                  uint64_t rule_conversions);
SubscriptionConversionMetadata
prepareSubscriptionConversionMetadata(const Request &request);
void recordSubscriptionConversion(const SubscriptionConversionMetadata &metadata,
                                  uint64_t rule_conversions);

std::string dashboardData(RESPONSE_CALLBACK_ARGS);

} // namespace statistics

#endif // STATISTICS_H_INCLUDED
