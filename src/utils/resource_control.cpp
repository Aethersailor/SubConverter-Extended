#include "utils/resource_control.h"

#include <atomic>
#include <chrono>
#include <climits>
#include <condition_variable>
#include <fstream>
#include <iomanip>
#include <limits>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <utility>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <sys/resource.h>
#ifdef __linux__
#include <sched.h>
#include <sys/sysinfo.h>
#endif
#endif

#include "handler/conversion_service.h"
#include "handler/settings.h"
#include "server/webserver.h"
#include "utils/logger.h"
#include "utils/string.h"

namespace {

using Clock = std::chrono::steady_clock;

struct ResourceControllerRuntime {
  std::mutex mutex;
  std::condition_variable condition;
  ResourceControlSnapshot snapshot;
  std::thread thread;
  bool running = false;
  bool stopping = false;
};

ResourceControllerRuntime runtime;

#ifdef __linux__
std::string readFirstLine(const char *path) {
  std::ifstream file(path);
  std::string value;
  if (file)
    std::getline(file, value);
  return trimWhitespace(value, true, true);
}

uint64_t parseFiniteBytes(const std::string &value) noexcept {
  if (value.empty() || value == "max")
    return 0;
  try {
    std::size_t consumed = 0;
    const unsigned long long parsed = std::stoull(value, &consumed, 10);
    return consumed == value.size() ? static_cast<uint64_t>(parsed) : 0;
  } catch (...) {
    return 0;
  }
}

uint64_t parsePsiAvg10(const char *path, const char *kind) noexcept {
  std::ifstream file(path);
  std::string line;
  while (std::getline(file, line)) {
    if (!startsWith(line, kind))
      continue;
    const std::size_t marker = line.find("avg10=");
    if (marker == std::string::npos)
      return 0;
    try {
      return static_cast<uint64_t>(
          std::max(0.0, std::stod(line.substr(marker + 6))) * 1000.0);
    } catch (...) {
      return 0;
    }
  }
  return 0;
}
#endif

double detectAffinityCpus() noexcept {
#ifdef _WIN32
  DWORD_PTR process_mask = 0;
  DWORD_PTR system_mask = 0;
  if (!GetProcessAffinityMask(GetCurrentProcess(), &process_mask, &system_mask))
    return 0.0;
  uint64_t count = 0;
  while (process_mask != 0) {
    count += process_mask & 1;
    process_mask >>= 1;
  }
  return static_cast<double>(count);
#elif defined(__linux__)
  cpu_set_t set;
  CPU_ZERO(&set);
  if (sched_getaffinity(0, sizeof(set), &set) != 0)
    return 0.0;
  return static_cast<double>(CPU_COUNT(&set));
#else
  return 0.0;
#endif
}

double detectCpuSetCpus() noexcept {
#ifdef __linux__
  std::string value = readFirstLine("/sys/fs/cgroup/cpuset.cpus.effective");
  if (value.empty())
    value = readFirstLine("/sys/fs/cgroup/cpuset.cpus");
  if (value.empty())
    value = readFirstLine("/sys/fs/cgroup/cpuset/cpuset.cpus");
  return static_cast<double>(parseCpuSetCount(value));
#else
  return 0.0;
#endif
}

double detectCpuQuota() noexcept {
#ifdef _WIN32
  BOOL in_job = FALSE;
  JOBOBJECT_CPU_RATE_CONTROL_INFORMATION control{};
  if (!IsProcessInJob(GetCurrentProcess(), nullptr, &in_job) || !in_job ||
      !QueryInformationJobObject(nullptr, JobObjectCpuRateControlInformation,
                                &control, sizeof(control), nullptr) ||
      (control.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_ENABLE) == 0 ||
      (control.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP) == 0 ||
      control.CpuRate == 0)
    return 0.0;
  const double affinity = detectAffinityCpus();
  return affinity > 0.0
             ? affinity * static_cast<double>(control.CpuRate) / 10000.0
             : 0.0;
#elif defined(__linux__)
  const std::string value = readFirstLine("/sys/fs/cgroup/cpu.max");
  if (!value.empty()) {
    std::istringstream stream(value);
    std::string quota_text;
    uint64_t period = 0;
    stream >> quota_text >> period;
    if (!stream || quota_text == "max" || period == 0)
      return 0.0;
    try {
      const double quota = static_cast<double>(std::stoull(quota_text));
      return quota > 0.0 ? quota / static_cast<double>(period) : 0.0;
    } catch (...) {
      return 0.0;
    }
  }
  const std::string quota_text =
      readFirstLine("/sys/fs/cgroup/cpu/cpu.cfs_quota_us");
  const std::string period_text =
      readFirstLine("/sys/fs/cgroup/cpu/cpu.cfs_period_us");
  try {
    const int64_t quota = std::stoll(quota_text);
    const uint64_t period = std::stoull(period_text);
    return quota > 0 && period != 0
               ? static_cast<double>(quota) / static_cast<double>(period)
               : 0.0;
  } catch (...) {
    return 0.0;
  }
#else
  return 0.0;
#endif
}

void detectMemory(ResourceControlSnapshot &snapshot) noexcept {
#ifdef _WIN32
  MEMORYSTATUSEX status{};
  status.dwLength = sizeof(status);
  if (GlobalMemoryStatusEx(&status))
    snapshot.host_total_memory_bytes = status.ullTotalPhys;
  if (status.ullAvailPhys != 0)
    snapshot.host_available_memory_bytes = status.ullAvailPhys;
  BOOL in_job = FALSE;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit{};
  if (IsProcessInJob(GetCurrentProcess(), nullptr, &in_job) && in_job &&
      QueryInformationJobObject(nullptr, JobObjectExtendedLimitInformation,
                                &limit, sizeof(limit), nullptr) &&
      (limit.BasicLimitInformation.LimitFlags &
       JOB_OBJECT_LIMIT_PROCESS_MEMORY))
    snapshot.memory_max_bytes = limit.ProcessMemoryLimit;
#else
#ifdef __linux__
  snapshot.memory_current_bytes =
      parseFiniteBytes(readFirstLine("/sys/fs/cgroup/memory.current"));
  if (snapshot.memory_current_bytes == 0)
    snapshot.memory_current_bytes = parseFiniteBytes(
        readFirstLine("/sys/fs/cgroup/memory/memory.usage_in_bytes"));
  snapshot.memory_high_bytes =
      parseFiniteBytes(readFirstLine("/sys/fs/cgroup/memory.high"));
  snapshot.memory_max_bytes =
      parseFiniteBytes(readFirstLine("/sys/fs/cgroup/memory.max"));
  snapshot.swap_current_bytes =
      parseFiniteBytes(readFirstLine("/sys/fs/cgroup/memory.swap.current"));
  if (snapshot.swap_current_bytes == 0) {
    const uint64_t memory_and_swap = parseFiniteBytes(
        readFirstLine("/sys/fs/cgroup/memory/memory.memsw.usage_in_bytes"));
    if (memory_and_swap > snapshot.memory_current_bytes)
      snapshot.swap_current_bytes =
          memory_and_swap - snapshot.memory_current_bytes;
  }
  snapshot.pids_current =
      parseFiniteBytes(readFirstLine("/sys/fs/cgroup/pids.current"));
  snapshot.pids_max = parseFiniteBytes(readFirstLine("/sys/fs/cgroup/pids.max"));
  if (snapshot.pids_current == 0)
    snapshot.pids_current = parseFiniteBytes(
        readFirstLine("/sys/fs/cgroup/pids/pids.current"));
  if (snapshot.pids_max == 0)
    snapshot.pids_max =
        parseFiniteBytes(readFirstLine("/sys/fs/cgroup/pids/pids.max"));
  snapshot.memory_psi_some_milli_percent =
      parsePsiAvg10("/proc/pressure/memory", "some");
  snapshot.memory_psi_full_milli_percent =
      parsePsiAvg10("/proc/pressure/memory", "full");
  snapshot.io_psi_some_milli_percent =
      parsePsiAvg10("/proc/pressure/io", "some");
  if (snapshot.memory_high_bytes == 0)
    snapshot.memory_high_bytes = parseFiniteBytes(
        readFirstLine("/sys/fs/cgroup/memory/memory.soft_limit_in_bytes"));
  if (snapshot.memory_max_bytes == 0)
    snapshot.memory_max_bytes = parseFiniteBytes(
        readFirstLine("/sys/fs/cgroup/memory/memory.limit_in_bytes"));
#endif
#ifdef __linux__
  struct sysinfo info {};
  if (sysinfo(&info) == 0)
    snapshot.host_total_memory_bytes =
        static_cast<uint64_t>(info.totalram) * info.mem_unit;
  if (info.freeram != 0)
    snapshot.host_available_memory_bytes =
        static_cast<uint64_t>(info.freeram) * info.mem_unit;
  if (snapshot.host_total_memory_bytes != 0 &&
      snapshot.memory_max_bytes > snapshot.host_total_memory_bytes * 16)
    snapshot.memory_max_bytes = 0;
  if (snapshot.host_total_memory_bytes != 0 &&
      snapshot.memory_high_bytes > snapshot.host_total_memory_bytes * 16)
    snapshot.memory_high_bytes = 0;
#endif
#endif
}

void detectFileLimits(ResourceControlSnapshot &snapshot) noexcept {
#ifndef _WIN32
  struct rlimit limit {};
  if (getrlimit(RLIMIT_NOFILE, &limit) == 0) {
    snapshot.nofile_soft = limit.rlim_cur == RLIM_INFINITY
                               ? 0
                               : static_cast<uint64_t>(limit.rlim_cur);
    snapshot.nofile_hard = limit.rlim_max == RLIM_INFINITY
                               ? 0
                               : static_cast<uint64_t>(limit.rlim_max);
  }
#else
  (void)snapshot;
#endif
}

std::string fingerprint(const ResourceControlSnapshot &snapshot) {
  const std::string material =
      std::to_string(snapshot.affinity_cpus) + ":" +
      std::to_string(snapshot.cpuset_cpus) + ":" +
      std::to_string(snapshot.cpu_quota_millis) + ":" +
      std::to_string(snapshot.memory_max_bytes != 0
                         ? snapshot.memory_max_bytes
                         : snapshot.host_total_memory_bytes) + ":" +
      std::to_string(snapshot.memory_high_bytes) + ":" +
      std::to_string(snapshot.pids_max) + ":" +
      std::to_string(snapshot.nofile_soft);
  uint64_t value = UINT64_C(1469598103934665603);
  for (unsigned char byte : material) {
    value ^= byte;
    value *= UINT64_C(1099511628211);
  }
  std::ostringstream result;
  result << std::hex << std::nouppercase << std::setfill('0') << std::setw(16)
         << value;
  return result.str();
}

ResourceControlSnapshot discover(const Settings &settings,
                                 ResourceControlMode mode) {
  ResourceControlSnapshot snapshot;
  snapshot.mode = resourceControlModeName(mode);
  snapshot.source = settings.resourceControlSource;
  const double affinity = detectAffinityCpus();
  const double cpuset = detectCpuSetCpus();
  const double quota = detectCpuQuota();
  const double fallback =
      static_cast<double>(std::max(1U, std::thread::hardware_concurrency()));
  const double effective =
      computeEffectiveCpu(affinity, cpuset, quota, fallback);
  snapshot.affinity_cpus = static_cast<uint64_t>(affinity);
  snapshot.cpuset_cpus = static_cast<uint64_t>(cpuset);
  snapshot.cpu_quota_millis =
      quota > 0.0 ? static_cast<uint64_t>(std::llround(quota * 1000.0)) : 0;
  snapshot.effective_cpu_millis =
      static_cast<uint64_t>(std::llround(effective * 1000.0));
  detectMemory(snapshot);
  detectFileLimits(snapshot);
  const ResourcePermitBudget budget = computeConservativeResourceBudget(
      effective, static_cast<uint32_t>(std::max(1, settings.maxConcurThreads)));
  snapshot.suggested_cpu_permits = budget.cpu_permits;
  snapshot.configured_cpu_cap =
      static_cast<uint64_t>(std::max(1, settings.maxConcurThreads));
  snapshot.suggested_active_flows = budget.active_flows;
  snapshot.suggested_outbound_connections = budget.outbound_connections;
  snapshot.hardware_complete = affinity > 0.0 &&
                               (snapshot.memory_max_bytes > 0 ||
                                snapshot.host_total_memory_bytes > 0);
  snapshot.controller_state =
      mode == ResourceControlMode::Compat
          ? "compat"
          : mode == ResourceControlMode::ForceMax ? "force_max_fallback"
                                                   : "idle";
  snapshot.hardware_fingerprint = fingerprint(snapshot);
  return snapshot;
}

bool memoryPressure(ResourceControlSnapshot &snapshot) noexcept {
#ifdef __linux__
  snapshot.memory_current_bytes =
      parseFiniteBytes(readFirstLine("/sys/fs/cgroup/memory.current"));
  if (snapshot.memory_current_bytes == 0)
    snapshot.memory_current_bytes = parseFiniteBytes(
        readFirstLine("/sys/fs/cgroup/memory/memory.usage_in_bytes"));
  snapshot.swap_current_bytes =
      parseFiniteBytes(readFirstLine("/sys/fs/cgroup/memory.swap.current"));
  if (snapshot.swap_current_bytes == 0) {
    const uint64_t memory_and_swap = parseFiniteBytes(
        readFirstLine("/sys/fs/cgroup/memory/memory.memsw.usage_in_bytes"));
    if (memory_and_swap > snapshot.memory_current_bytes)
      snapshot.swap_current_bytes =
          memory_and_swap - snapshot.memory_current_bytes;
  }
  snapshot.memory_psi_some_milli_percent =
      parsePsiAvg10("/proc/pressure/memory", "some");
  snapshot.memory_psi_full_milli_percent =
      parsePsiAvg10("/proc/pressure/memory", "full");
  snapshot.io_psi_some_milli_percent =
      parsePsiAvg10("/proc/pressure/io", "some");
#endif
  const uint64_t boundary = snapshot.memory_high_bytes != 0
                                ? snapshot.memory_high_bytes
                                : snapshot.memory_max_bytes;
  const bool near_boundary =
      boundary != 0 && snapshot.memory_current_bytes != 0 &&
      snapshot.memory_current_bytes >= boundary - boundary / 10;
  return near_boundary || snapshot.swap_current_bytes != 0;
}

void controllerLoop() noexcept {
  uint64_t previous_accepted = requestAdmissionSnapshot().accepted;
  uint64_t previous_arrivals = 0;
  std::unique_lock<std::mutex> lock(runtime.mutex);
  while (!runtime.stopping) {
    if (runtime.condition.wait_for(lock, std::chrono::seconds(1),
                                   [] { return runtime.stopping; }))
      break;
    ResourceControlSnapshot next = runtime.snapshot;
    const ResourcePermitBudget baseline = computeConservativeResourceBudget(
        static_cast<double>(next.effective_cpu_millis) / 1000.0,
        static_cast<uint32_t>(std::min<uint64_t>(next.configured_cpu_cap,
                                                 UINT32_MAX)));
    next.suggested_cpu_permits = baseline.cpu_permits;
    next.suggested_active_flows = baseline.active_flows;
    next.suggested_outbound_connections = baseline.outbound_connections;
    lock.unlock();
    try {
      const RequestAdmissionSnapshot admission = requestAdmissionSnapshot();
      const WorkloadSchedulerSnapshot scheduler = conversionSchedulerSnapshot();
      const uint64_t arrivals = admission.accepted - previous_accepted;
      previous_accepted = admission.accepted;
      const bool pressure = memoryPressure(next);
      const uint64_t effective_cpus =
          std::max<uint64_t>(1, next.effective_cpu_millis / 1000);
      if (pressure) {
        next.controller_state = "cooldown";
        next.pressure_fallback = true;
        next.suggested_cpu_permits =
            std::max<uint64_t>(1, next.suggested_cpu_permits / 2);
      } else if (scheduler.queued_entries > effective_cpus ||
                 arrivals >= effective_cpus * 2) {
        next.controller_state = "burst";
        next.pressure_fallback = false;
      } else if (arrivals > previous_arrivals + 2 && arrivals > 1) {
        next.controller_state = "warm";
        next.pressure_fallback = false;
      } else if (arrivals != 0 || scheduler.active != 0 ||
                 scheduler.queued_entries != 0) {
        next.controller_state = "normal";
        next.pressure_fallback = false;
      } else if (next.controller_state == "burst" ||
                 next.controller_state == "warm" ||
                 next.controller_state == "normal") {
        next.controller_state = "cooldown";
        next.pressure_fallback = false;
      } else {
        next.controller_state = "idle";
        next.pressure_fallback = false;
      }
      previous_arrivals = arrivals;
      ++next.sample_count;
    } catch (...) {
      next.controller_state = "force_max_fallback";
      next.pressure_fallback = true;
    }
    lock.lock();
    runtime.snapshot = std::move(next);
  }
}

} // namespace

void configureResourceControl(Settings &settings) {
  const std::string normalized =
      toLower(trimWhitespace(settings.resourceControl, true, true));
  const std::optional<ResourceControlMode> parsed =
      parseResourceControlMode(normalized);
  if (!parsed)
    throw std::invalid_argument(
        "advanced.resource_control must be compat, adaptive, or force_max");
  settings.resourceControl = normalized;
  ResourceControlSnapshot snapshot = discover(settings, *parsed);
  {
    std::lock_guard<std::mutex> lock(runtime.mutex);
    if (runtime.running && runtime.snapshot.mode != snapshot.mode)
      throw std::invalid_argument(
          "advanced.resource_control changes require a process restart");
  }
  if (*parsed == ResourceControlMode::ForceMax) {
    settings.maxConcurThreads = static_cast<int>(
        std::min<uint64_t>(snapshot.suggested_cpu_permits, INT_MAX));
    settings.maxServerThreads =
        std::max(settings.maxServerThreads, settings.maxConcurThreads);
    snapshot.permits_applied = true;
  }
  uint64_t admission_entries =
      *parsed == ResourceControlMode::Compat
          ? UINT64_C(2048)
          : static_cast<uint64_t>(std::clamp(settings.maxPendingConns, 1, 2048));
  if (*parsed == ResourceControlMode::ForceMax)
    admission_entries =
        std::min<uint64_t>(admission_entries, snapshot.suggested_active_flows);
  configureRequestAdmissionLimits(admission_entries,
                                  UINT64_C(64) * 1024 * 1024);
  {
    std::lock_guard<std::mutex> lock(runtime.mutex);
    runtime.snapshot = snapshot;
  }
  writeLog(LOG_LEVEL_INFO,
           "RESOURCE_CONTROL_EFFECTIVE mode=" + snapshot.mode +
               " source=" + snapshot.source + " state=" +
               snapshot.controller_state + " cpu_millis=" +
               std::to_string(snapshot.effective_cpu_millis) +
               " affinity=" + std::to_string(snapshot.affinity_cpus) +
               " cpuset=" + std::to_string(snapshot.cpuset_cpus) +
               " quota_millis=" +
               std::to_string(snapshot.cpu_quota_millis) +
               " memory_max=" +
               std::to_string(snapshot.memory_max_bytes) +
               " cpu_permits=" +
               std::to_string(snapshot.suggested_cpu_permits) +
               " curve_valid=false applied=" +
               (snapshot.permits_applied ? "true" : "false") +
               " hardware=" + snapshot.hardware_fingerprint);
}

ResourceControlSnapshot resourceControlSnapshot() {
  std::lock_guard<std::mutex> lock(runtime.mutex);
  return runtime.snapshot;
}

void startResourceControlRuntime() {
  std::lock_guard<std::mutex> lock(runtime.mutex);
  if (runtime.running)
    return;
  if (runtime.snapshot.mode != "adaptive" &&
      runtime.snapshot.mode != "force_max")
    return;
  (void)conversionSchedulerSnapshot();
  if (runtime.snapshot.mode == "adaptive") {
    runtime.stopping = false;
    runtime.thread = std::thread(controllerLoop);
  }
  runtime.running = true;
}

void shutdownResourceControlRuntime() noexcept {
  {
    std::lock_guard<std::mutex> lock(runtime.mutex);
    if (!runtime.running)
      return;
    runtime.stopping = true;
  }
  runtime.condition.notify_all();
  if (runtime.thread.joinable())
    runtime.thread.join();
  std::lock_guard<std::mutex> lock(runtime.mutex);
  runtime.running = false;
}
