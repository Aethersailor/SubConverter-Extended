#ifndef RESOURCE_CONTROL_H_INCLUDED
#define RESOURCE_CONTROL_H_INCLUDED

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

struct Settings;

enum class ResourceControlMode {
  Compat,
  Adaptive,
  ForceMax,
};

inline const char *resourceControlModeName(ResourceControlMode mode) noexcept {
  switch (mode) {
  case ResourceControlMode::Compat:
    return "compat";
  case ResourceControlMode::Adaptive:
    return "adaptive";
  case ResourceControlMode::ForceMax:
    return "force_max";
  }
  return "invalid";
}

inline std::optional<ResourceControlMode>
parseResourceControlMode(std::string_view value) noexcept {
  if (value == "compat")
    return ResourceControlMode::Compat;
  if (value == "adaptive")
    return ResourceControlMode::Adaptive;
  if (value == "force_max")
    return ResourceControlMode::ForceMax;
  return std::nullopt;
}

inline std::size_t parseCpuSetCount(std::string_view value) noexcept {
  std::size_t count = 0;
  std::size_t offset = 0;
  while (offset < value.size()) {
    while (offset < value.size() &&
           (value[offset] == ' ' || value[offset] == '\t' ||
            value[offset] == ','))
      ++offset;
    if (offset == value.size())
      break;
    uint64_t first = 0;
    bool have_first = false;
    while (offset < value.size() && value[offset] >= '0' &&
           value[offset] <= '9') {
      have_first = true;
      first = first * 10 + static_cast<unsigned>(value[offset++] - '0');
    }
    if (!have_first)
      return 0;
    uint64_t last = first;
    if (offset < value.size() && value[offset] == '-') {
      ++offset;
      last = 0;
      bool have_last = false;
      while (offset < value.size() && value[offset] >= '0' &&
             value[offset] <= '9') {
        have_last = true;
        last = last * 10 + static_cast<unsigned>(value[offset++] - '0');
      }
      if (!have_last || last < first)
        return 0;
    }
    if (last - first + 1 > static_cast<uint64_t>(SIZE_MAX - count))
      return 0;
    count += static_cast<std::size_t>(last - first + 1);
    while (offset < value.size() &&
           (value[offset] == ' ' || value[offset] == '\t'))
      ++offset;
    if (offset < value.size() && value[offset] != ',')
      return 0;
  }
  return count;
}

inline double computeEffectiveCpu(double affinity, double cpuset,
                                  double quota,
                                  double fallback) noexcept {
  double result = 0.0;
  for (double candidate : {affinity, cpuset, quota}) {
    if (candidate <= 0.0 || !std::isfinite(candidate))
      continue;
    result = result <= 0.0 ? candidate : std::min(result, candidate);
  }
  if (result <= 0.0 || !std::isfinite(result))
    result = fallback > 0.0 && std::isfinite(fallback) ? fallback : 1.0;
  return std::max(1.0, result);
}

struct ResourcePermitBudget {
  uint32_t cpu_permits = 1;
  uint32_t active_flows = 16;
  uint32_t outbound_connections = 16;
};

inline ResourcePermitBudget
computeConservativeResourceBudget(double effective_cpu,
                                  uint32_t configured_cpu_cap) noexcept {
  const double finite_cpu =
      effective_cpu > 0.0 && std::isfinite(effective_cpu) ? effective_cpu : 1.0;
  uint64_t cpu = static_cast<uint64_t>(std::floor(finite_cpu));
  cpu = std::max<uint64_t>(1, cpu);
  if (configured_cpu_cap != 0)
    cpu = std::min<uint64_t>(cpu, configured_cpu_cap);
  cpu = std::min<uint64_t>(cpu, UINT32_MAX);
  const uint64_t scaled = std::min<uint64_t>(UINT32_MAX, cpu * 16);
  return {static_cast<uint32_t>(cpu), static_cast<uint32_t>(scaled),
          static_cast<uint32_t>(scaled)};
}

struct ResourceControlSnapshot {
  std::string mode = "compat";
  std::string source = "builtin-default";
  std::string controller_state = "compat";
  std::string hardware_fingerprint;
  uint64_t sample_count = 0;
  uint64_t affinity_cpus = 0;
  uint64_t cpuset_cpus = 0;
  uint64_t cpu_quota_millis = 0;
  uint64_t effective_cpu_millis = 1000;
  uint64_t memory_current_bytes = 0;
  uint64_t memory_high_bytes = 0;
  uint64_t memory_max_bytes = 0;
  uint64_t swap_current_bytes = 0;
  uint64_t host_total_memory_bytes = 0;
  uint64_t host_available_memory_bytes = 0;
  uint64_t nofile_soft = 0;
  uint64_t nofile_hard = 0;
  uint64_t pids_current = 0;
  uint64_t pids_max = 0;
  uint64_t memory_psi_some_milli_percent = 0;
  uint64_t memory_psi_full_milli_percent = 0;
  uint64_t io_psi_some_milli_percent = 0;
  uint64_t suggested_cpu_permits = 1;
  uint64_t configured_cpu_cap = 1;
  uint64_t suggested_active_flows = 16;
  uint64_t suggested_outbound_connections = 16;
  bool hardware_complete = false;
  bool curve_valid = false;
  bool permits_applied = false;
  bool pressure_fallback = false;
};

inline bool resourceCurveMatches(
    const ResourceControlSnapshot &snapshot,
    std::string_view validated_hardware_fingerprint) noexcept {
  return !validated_hardware_fingerprint.empty() &&
         snapshot.hardware_complete &&
         snapshot.hardware_fingerprint == validated_hardware_fingerprint;
}

void configureResourceControl(Settings &settings);
ResourceControlSnapshot resourceControlSnapshot();
void startResourceControlRuntime();
void shutdownResourceControlRuntime() noexcept;

#endif // RESOURCE_CONTROL_H_INCLUDED
