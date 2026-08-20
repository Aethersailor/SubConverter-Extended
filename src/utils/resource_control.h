#ifndef RESOURCE_CONTROL_H_INCLUDED
#define RESOURCE_CONTROL_H_INCLUDED

#include <algorithm>
#include <climits>
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

inline uint64_t computeForceMaxAdmissionEntries(
    uint64_t memory_bytes, uint64_t nofile_soft,
    uint64_t outbound_connections) noexcept {
  uint64_t result = memory_bytes == 0
                        ? UINT64_C(2048)
                        : std::max<uint64_t>(
                              64, memory_bytes / 8 /
                                      (UINT64_C(64) * 1024));
  result = std::min<uint64_t>(result, INT_MAX);
  if (nofile_soft != 0) {
    const uint64_t reserved = std::min<uint64_t>(
        nofile_soft, std::max<uint64_t>(64, outbound_connections + 64));
    const uint64_t fd_bound =
        nofile_soft > reserved ? nofile_soft - reserved
                               : std::max<uint64_t>(1, nofile_soft / 2);
    result = std::min(result, fd_bound);
  }
  return std::max<uint64_t>(1, result);
}

inline uint64_t computeForceMaxRequestByteLimit(
    uint64_t memory_bytes) noexcept {
  if (memory_bytes == 0)
    return UINT64_C(64) * 1024 * 1024;
  return std::max<uint64_t>(memory_bytes / 16,
                            UINT64_C(64) * 1024 * 1024);
}

inline uint64_t computeForceMaxRetainedByteLimit(
    uint64_t memory_bytes) noexcept {
  if (memory_bytes == 0)
    return UINT64_C(64) * 1024 * 1024;
  return std::max<uint64_t>(memory_bytes / 4,
                            UINT64_C(64) * 1024 * 1024);
}

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

inline uint64_t governorDecreaseCpuPermits(uint64_t current) noexcept {
  current = std::max<uint64_t>(1, current);
  if (current == 1)
    return 1;
  return std::max<uint64_t>(1, current - std::max<uint64_t>(1, current / 4));
}

inline uint64_t governorRecoverCpuPermits(uint64_t current,
                                          uint64_t maximum) noexcept {
  maximum = std::max<uint64_t>(1, maximum);
  return std::min<uint64_t>(maximum, std::max<uint64_t>(1, current) + 1);
}

struct ResourceGovernorState {
  uint64_t current_permits = 1;
  uint32_t stable_samples = 0;
  uint32_t idle_samples = 0;
};

struct ResourceGovernorInput {
  uint64_t maximum_permits = 1;
  bool force_max = false;
  bool telemetry_valid = true;
  bool memory_pressure = false;
  bool memory_event = false;
  bool active = false;
};

struct ResourceGovernorDecision {
  uint64_t permits = 1;
  const char *state = "max_ready";
  const char *reason = "hardware_limit_idle";
  bool pressure_fallback = false;
};

inline ResourceGovernorDecision governorStep(
    ResourceGovernorState &state,
    const ResourceGovernorInput &input) noexcept {
  const uint64_t maximum = std::max<uint64_t>(1, input.maximum_permits);
  state.current_permits =
      std::clamp<uint64_t>(state.current_permits, 1, maximum);
  ResourceGovernorDecision decision;
  if (!input.telemetry_valid) {
    state.current_permits =
        governorDecreaseCpuPermits(state.current_permits);
    state.stable_samples = 0;
    state.idle_samples = 0;
    decision.state = "pressure_guarded";
    decision.reason = "telemetry_unavailable";
    decision.pressure_fallback = true;
  } else if (input.memory_pressure || input.memory_event) {
    state.current_permits =
        governorDecreaseCpuPermits(state.current_permits);
    state.stable_samples = 0;
    state.idle_samples = 0;
    decision.state = "pressure_guarded";
    decision.reason = input.memory_event ? "memory_event"
                                         : "memory_pressure";
    decision.pressure_fallback = true;
  } else if (state.current_permits < maximum) {
    if (input.force_max || input.active) {
      if (++state.stable_samples >= 2) {
        state.current_permits = governorRecoverCpuPermits(
            state.current_permits, maximum);
        state.stable_samples = 0;
      }
      state.idle_samples = 0;
      decision.state = "recovering";
      decision.reason = input.active ? "stable_throughput"
                                     : "force_max_idle_restore";
    } else {
      state.stable_samples = 0;
      if (++state.idle_samples >= 30 && state.current_permits > 1) {
        --state.current_permits;
        state.idle_samples = 0;
      }
      decision.state = "idle_reduced";
      decision.reason = "adaptive_idle";
    }
  } else {
    state.stable_samples = 0;
    decision.state = "max_ready";
    decision.reason = input.active ? "hardware_limit_active"
                                   : "hardware_limit_idle";
    if (!input.force_max && !input.active &&
        ++state.idle_samples >= 30 && state.current_permits > 1) {
      --state.current_permits;
      state.idle_samples = 0;
      decision.state = "idle_reduced";
      decision.reason = "adaptive_idle";
    } else if (input.active) {
      state.idle_samples = 0;
    }
  }
  decision.permits = state.current_permits;
  return decision;
}

struct ResourceControlSnapshot {
  std::string mode = "compat";
  std::string effective_mode = "compat";
  std::string source = "builtin-default";
  std::string controller_state = "compat";
  std::string controller_reason = "compat";
  std::string hardware_fingerprint;
  uint64_t sample_count = 0;
  uint64_t sample_age_ms = 0;
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
  uint64_t open_fds = 0;
  uint64_t memory_peak_bytes = 0;
  uint64_t memory_events_high = 0;
  uint64_t memory_events_max = 0;
  uint64_t memory_events_oom = 0;
  uint64_t memory_events_oom_kill = 0;
  uint64_t memory_events_sock_throttled = 0;
  uint64_t cpu_psi_some_milli_percent = 0;
  uint64_t cpu_psi_full_milli_percent = 0;
  uint64_t memory_psi_some_milli_percent = 0;
  uint64_t memory_psi_full_milli_percent = 0;
  uint64_t io_psi_some_milli_percent = 0;
  uint64_t suggested_cpu_permits = 1;
  uint64_t max_cpu_permits = 1;
  uint64_t configured_cpu_cap = 1;
  uint64_t suggested_active_flows = 16;
  uint64_t suggested_outbound_connections = 16;
  uint64_t configured_pending_connections = 0;
  uint64_t configured_server_threads = 0;
  uint64_t configured_deadline_ms = 0;
  std::string hardware_pin;
  bool cpu_pressure_available = false;
  bool memory_pressure_available = false;
  bool io_pressure_available = false;
  bool memory_events_available = false;
  bool memory_events_supported = false;
  bool memory_events_sample_valid = false;
  bool open_fds_available = false;
  bool cgroup_scope_known = true;
  bool hardware_detected = false;
  bool hardware_pin_matched = false;
  bool startup_budget_applied = false;
  // Deprecated compatibility aliases. New code must use the explicit fields
  // above; no persisted capacity curve is learned or loaded.
  bool hardware_complete = false;
  bool curve_valid = false;
  bool permits_applied = false;
  bool pressure_fallback = false;
};

inline bool hardwarePinMatches(
    const ResourceControlSnapshot &snapshot,
    std::string_view configured_hardware_pin) noexcept {
  return configured_hardware_pin.empty() ||
         (snapshot.hardware_detected &&
          snapshot.hardware_fingerprint == configured_hardware_pin);
}

void configureResourceControl(Settings &settings);
ResourceControlSnapshot resourceControlSnapshot();
void startResourceControlRuntime();
void shutdownResourceControlRuntime() noexcept;

#endif // RESOURCE_CONTROL_H_INCLUDED
