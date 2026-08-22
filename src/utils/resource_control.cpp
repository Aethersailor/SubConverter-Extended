#include "utils/resource_control.h"

#include <atomic>
#include <chrono>
#include <climits>
#include <condition_variable>
#include <filesystem>
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
#include <psapi.h>
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
  Clock::time_point sampled_at = Clock::now();
  std::thread thread;
  bool configuration_frozen = false;
  bool running = false;
  bool stopping = false;
};

ResourceControllerRuntime runtime;

#ifdef __linux__
std::string readFirstLine(const std::filesystem::path &path) {
  std::ifstream file(path);
  std::string value;
  if (file)
    std::getline(file, value);
  return trimWhitespace(value, true, true);
}

bool readableFile(const std::filesystem::path &path) noexcept {
  std::ifstream file(path);
  return file.good();
}

uint64_t linuxAvailableMemoryBytes() noexcept {
  try {
    std::ifstream file("/proc/meminfo");
    std::string name;
    uint64_t value = 0;
    std::string unit;
    while (file >> name >> value >> unit) {
      if (name == "MemAvailable:")
        return value <= UINT64_MAX / 1024 ? value * 1024 : 0;
    }
  } catch (...) {
  }
  return 0;
}

std::string selfCgroupRelativePath(const char *controller) noexcept {
  try {
    std::ifstream file("/proc/self/cgroup");
    std::string line;
    while (std::getline(file, line)) {
      const std::size_t first = line.find(':');
      const std::size_t second = first == std::string::npos
                                     ? std::string::npos
                                     : line.find(':', first + 1);
      if (second == std::string::npos)
        continue;
      const std::string controllers =
          line.substr(first + 1, second - first - 1);
      if (controller == nullptr) {
        if (line.substr(0, first) != "0" || !controllers.empty())
          continue;
      } else {
        bool matched = false;
        for (const std::string &name : split(controllers, ",")) {
          if (name == controller) {
            matched = true;
            break;
          }
        }
        if (!matched)
          continue;
      }
      return line.substr(second + 1);
    }
  } catch (...) {
  }
  return {};
}

std::filesystem::path cgroupPath(const char *root,
                                 const std::string &membership) noexcept {
  try {
    std::string relative = membership;
    while (!relative.empty() && relative.front() == '/')
      relative.erase(relative.begin());
    std::filesystem::path candidate(root);
    if (!relative.empty())
      candidate /= relative;
    std::error_code error;
    return std::filesystem::exists(candidate, error) && !error
               ? candidate
               : std::filesystem::path();
  } catch (...) {
    return {};
  }
}

const std::filesystem::path &cgroupV2Base() noexcept {
  static const std::filesystem::path base = []() noexcept {
    const std::string membership = selfCgroupRelativePath(nullptr);
    if (membership.empty())
      return std::filesystem::path();
    return cgroupPath("/sys/fs/cgroup", membership);
  }();
  return base;
}

const std::filesystem::path &cgroupV1Base(const char *controller) noexcept {
  static const std::filesystem::path memory = []() noexcept {
    const std::string membership = selfCgroupRelativePath("memory");
    if (membership.empty())
      return std::filesystem::path();
    return cgroupPath("/sys/fs/cgroup/memory", membership);
  }();
  static const std::filesystem::path pids = []() noexcept {
    const std::string membership = selfCgroupRelativePath("pids");
    if (membership.empty())
      return std::filesystem::path();
    return cgroupPath("/sys/fs/cgroup/pids", membership);
  }();
  static const std::filesystem::path cpuset = []() noexcept {
    const std::string membership = selfCgroupRelativePath("cpuset");
    if (membership.empty())
      return std::filesystem::path();
    return cgroupPath("/sys/fs/cgroup/cpuset", membership);
  }();
  static const std::filesystem::path cpu = []() noexcept {
    const std::string membership = selfCgroupRelativePath("cpu");
    if (membership.empty())
      return std::filesystem::path();
    for (const char *root : {"/sys/fs/cgroup/cpu,cpuacct",
                             "/sys/fs/cgroup/cpuacct,cpu",
                             "/sys/fs/cgroup/cpu"}) {
      const std::filesystem::path candidate = cgroupPath(root, membership);
      if (!candidate.empty())
        return candidate;
    }
    return std::filesystem::path();
  }();
  if (std::string_view(controller) == "memory")
    return memory;
  if (std::string_view(controller) == "pids")
    return pids;
  if (std::string_view(controller) == "cpuset")
    return cpuset;
  return cpu;
}

std::filesystem::path cgroupV1File(const char *controller, const char *name) {
  const std::filesystem::path &base = cgroupV1Base(controller);
  return base.empty() ? std::filesystem::path() : base / name;
}

std::filesystem::path cgroupV2File(const char *name) {
  const std::filesystem::path &base = cgroupV2Base();
  return base.empty() ? std::filesystem::path() : base / name;
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

uint64_t parsePsiAvg10(const std::filesystem::path &path,
                       const char *kind) noexcept {
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

uint64_t parsePsiAvg10WithFallback(const std::filesystem::path &cgroup_path,
                                   const char *system_path,
                                   const char *kind) noexcept {
  std::ifstream cgroup(cgroup_path);
  if (cgroup.good())
    return parsePsiAvg10(cgroup_path, kind);
  return parsePsiAvg10(system_path, kind);
}

uint64_t parseFlatCounter(const std::filesystem::path &path,
                          const char *key) noexcept {
  std::ifstream file(path);
  std::string name;
  uint64_t value = 0;
  while (file >> name >> value) {
    if (name == key)
      return value;
  }
  return 0;
}

uint64_t countOpenFileDescriptors() noexcept {
  try {
    uint64_t count = 0;
    for (const auto &entry :
         std::filesystem::directory_iterator("/proc/self/fd")) {
      (void)entry;
      ++count;
    }
    return count;
  } catch (...) {
    return 0;
  }
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
  std::string value = readFirstLine(cgroupV2File("cpuset.cpus.effective"));
  if (value.empty())
    value = readFirstLine(cgroupV2File("cpuset.cpus"));
  if (value.empty())
    value = readFirstLine(cgroupV1File("cpuset", "cpuset.cpus"));
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
  const std::string value = readFirstLine(cgroupV2File("cpu.max"));
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
      readFirstLine(cgroupV1File("cpu", "cpu.cfs_quota_us"));
  const std::string period_text =
      readFirstLine(cgroupV1File("cpu", "cpu.cfs_period_us"));
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

#ifdef _WIN32
bool sampleWindowsMemory(ResourceControlSnapshot &snapshot) noexcept {
  MEMORYSTATUSEX status{};
  status.dwLength = sizeof(status);
  const bool host_valid = GlobalMemoryStatusEx(&status) != FALSE;

  BOOL in_job = FALSE;
  const bool job_membership_valid =
      IsProcessInJob(GetCurrentProcess(), nullptr, &in_job) != FALSE;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION job{};
  const bool job_valid = !job_membership_valid || !in_job ||
      QueryInformationJobObject(nullptr, JobObjectExtendedLimitInformation,
                                &job, sizeof(job), nullptr) != FALSE;

  uint64_t memory_limit = 0;
  const auto include_limit = [&memory_limit](uint64_t value) {
    if (value != 0)
      memory_limit = memory_limit == 0 ? value
                                       : std::min(memory_limit, value);
  };
  if (job_membership_valid && in_job && job_valid) {
    if (job.BasicLimitInformation.LimitFlags &
        JOB_OBJECT_LIMIT_PROCESS_MEMORY)
      include_limit(job.ProcessMemoryLimit);
    if (job.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_JOB_MEMORY)
      include_limit(job.JobMemoryLimit);
  }

  PROCESS_MEMORY_COUNTERS_EX process{};
  process.cb = sizeof(process);
  const bool process_valid =
      K32GetProcessMemoryInfo(
          GetCurrentProcess(),
          reinterpret_cast<PROCESS_MEMORY_COUNTERS *>(&process),
          sizeof(process)) != FALSE;

  snapshot.host_total_memory_bytes =
      host_valid ? status.ullTotalPhys : 0;
  snapshot.host_available_memory_bytes =
      host_valid ? status.ullAvailPhys : 0;
  snapshot.memory_max_bytes = memory_limit;
  snapshot.memory_current_bytes = 0;
  if (!job_membership_valid || !job_valid)
    return false;
  if (memory_limit != 0) {
    snapshot.memory_peak_bytes =
        static_cast<uint64_t>(job.PeakJobMemoryUsed);
    if (!process_valid)
      return false;
    snapshot.memory_current_bytes = process.PrivateUsage;
    return snapshot.memory_current_bytes != 0;
  }
  if (!host_valid || status.ullAvailPhys > status.ullTotalPhys)
    return false;
  snapshot.memory_current_bytes = status.ullTotalPhys - status.ullAvailPhys;
  return true;
}
#endif

void detectMemory(ResourceControlSnapshot &snapshot) noexcept {
#ifdef _WIN32
  (void)sampleWindowsMemory(snapshot);
#else
#ifdef __linux__
  const bool cgroup_v2_member =
      !selfCgroupRelativePath(nullptr).empty();
  const bool cgroup_v1_memory_member =
      !selfCgroupRelativePath("memory").empty();
  snapshot.cgroup_scope_known =
      cgroup_v2_member ? !cgroupV2Base().empty()
                       : !cgroup_v1_memory_member ||
                             !cgroupV1Base("memory").empty();
  snapshot.memory_events_supported = cgroup_v2_member;
  snapshot.memory_events_available =
      readableFile(cgroupV2File("memory.events"));
  snapshot.memory_events_sample_valid =
      snapshot.memory_events_available;
  snapshot.cpu_pressure_available =
      readableFile(cgroupV2File("cpu.pressure")) ||
      readableFile("/proc/pressure/cpu");
  snapshot.memory_pressure_available =
      readableFile(cgroupV2File("memory.pressure")) ||
      readableFile("/proc/pressure/memory");
  snapshot.io_pressure_available =
      readableFile(cgroupV2File("io.pressure")) ||
      readableFile("/proc/pressure/io");
  snapshot.memory_current_bytes =
      parseFiniteBytes(readFirstLine(cgroupV2File("memory.current")));
  if (snapshot.memory_current_bytes == 0)
    snapshot.memory_current_bytes = parseFiniteBytes(
        readFirstLine(cgroupV1File("memory", "memory.usage_in_bytes")));
  snapshot.memory_high_bytes =
      parseFiniteBytes(readFirstLine(cgroupV2File("memory.high")));
  snapshot.memory_max_bytes =
      parseFiniteBytes(readFirstLine(cgroupV2File("memory.max")));
  snapshot.swap_current_bytes =
      parseFiniteBytes(readFirstLine(cgroupV2File("memory.swap.current")));
  if (snapshot.swap_current_bytes == 0) {
    const uint64_t memory_and_swap = parseFiniteBytes(
        readFirstLine(
            cgroupV1File("memory", "memory.memsw.usage_in_bytes")));
    if (memory_and_swap > snapshot.memory_current_bytes)
      snapshot.swap_current_bytes =
          memory_and_swap - snapshot.memory_current_bytes;
  }
  snapshot.pids_current =
      parseFiniteBytes(readFirstLine(cgroupV2File("pids.current")));
  snapshot.pids_max =
      parseFiniteBytes(readFirstLine(cgroupV2File("pids.max")));
  snapshot.memory_peak_bytes =
      parseFiniteBytes(readFirstLine(cgroupV2File("memory.peak")));
  snapshot.memory_events_high =
      parseFlatCounter(cgroupV2File("memory.events"), "high");
  snapshot.memory_events_max =
      parseFlatCounter(cgroupV2File("memory.events"), "max");
  snapshot.memory_events_oom =
      parseFlatCounter(cgroupV2File("memory.events"), "oom");
  snapshot.memory_events_oom_kill =
      parseFlatCounter(cgroupV2File("memory.events"), "oom_kill");
  snapshot.memory_events_sock_throttled =
      parseFlatCounter(cgroupV2File("memory.events"), "sock_throttled");
  if (snapshot.pids_current == 0)
    snapshot.pids_current = parseFiniteBytes(
        readFirstLine(cgroupV1File("pids", "pids.current")));
  if (snapshot.pids_max == 0)
    snapshot.pids_max =
        parseFiniteBytes(readFirstLine(cgroupV1File("pids", "pids.max")));
  snapshot.cpu_psi_some_milli_percent = parsePsiAvg10WithFallback(
      cgroupV2File("cpu.pressure"), "/proc/pressure/cpu", "some");
  snapshot.cpu_psi_full_milli_percent = parsePsiAvg10WithFallback(
      cgroupV2File("cpu.pressure"), "/proc/pressure/cpu", "full");
  snapshot.memory_psi_some_milli_percent = parsePsiAvg10WithFallback(
      cgroupV2File("memory.pressure"), "/proc/pressure/memory", "some");
  snapshot.memory_psi_full_milli_percent = parsePsiAvg10WithFallback(
      cgroupV2File("memory.pressure"), "/proc/pressure/memory", "full");
  snapshot.io_psi_some_milli_percent = parsePsiAvg10WithFallback(
      cgroupV2File("io.pressure"), "/proc/pressure/io", "some");
  snapshot.open_fds = countOpenFileDescriptors();
  snapshot.open_fds_available = snapshot.open_fds != 0;
  if (snapshot.memory_high_bytes == 0)
    snapshot.memory_high_bytes = parseFiniteBytes(
        readFirstLine(
            cgroupV1File("memory", "memory.soft_limit_in_bytes")));
  if (snapshot.memory_max_bytes == 0)
    snapshot.memory_max_bytes = parseFiniteBytes(
        readFirstLine(cgroupV1File("memory", "memory.limit_in_bytes")));
#endif
#ifdef __linux__
  struct sysinfo info {};
  if (sysinfo(&info) == 0)
    snapshot.host_total_memory_bytes =
        static_cast<uint64_t>(info.totalram) * info.mem_unit;
  snapshot.host_available_memory_bytes = linuxAvailableMemoryBytes();
  if (snapshot.host_available_memory_bytes == 0 && info.freeram != 0)
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
      effective, mode == ResourceControlMode::Compat
                     ? static_cast<uint32_t>(
                           std::max(1, settings.maxConcurThreads))
                     : 0);
  snapshot.suggested_cpu_permits = budget.cpu_permits;
  snapshot.max_cpu_permits = budget.cpu_permits;
  snapshot.configured_cpu_cap =
      static_cast<uint64_t>(std::max(1, settings.maxConcurThreads));
  snapshot.configured_pending_connections =
      static_cast<uint64_t>(std::max(1, settings.maxPendingConns));
  snapshot.configured_server_threads =
      static_cast<uint64_t>(std::max(1, settings.maxServerThreads));
  snapshot.configured_deadline_ms =
      static_cast<uint64_t>(std::max(1, settings.requestDeadlineMs));
  snapshot.hardware_pin = settings.forceMaxCurveFingerprint;
  snapshot.suggested_active_flows = budget.active_flows;
  snapshot.suggested_outbound_connections = budget.outbound_connections;
  if (snapshot.nofile_soft != 0)
    snapshot.suggested_outbound_connections = std::min<uint64_t>(
        snapshot.suggested_outbound_connections,
        std::max<uint64_t>(1, snapshot.nofile_soft / 4));
  snapshot.hardware_detected = snapshot.cgroup_scope_known && affinity > 0.0 &&
                               (snapshot.memory_max_bytes > 0 ||
                                snapshot.host_total_memory_bytes > 0);
  snapshot.hardware_complete = snapshot.hardware_detected;
  snapshot.hardware_fingerprint = fingerprint(snapshot);
  snapshot.hardware_pin_matched =
      hardwarePinMatches(snapshot, settings.forceMaxCurveFingerprint);
  snapshot.controller_state = mode == ResourceControlMode::Compat
                                  ? "compat"
                                  : mode == ResourceControlMode::Adaptive
                                        ? "observe_only"
                                        : snapshot.hardware_detected &&
                                                  snapshot.hardware_pin_matched
                                              ? "max_ready_static"
                                              : "safe_fallback";
  snapshot.controller_reason = mode == ResourceControlMode::Compat
                                   ? "compat"
                                   : !snapshot.hardware_detected
                                         ? "telemetry_incomplete"
                                         : !snapshot.hardware_pin_matched
                                               ? "hardware_pin_mismatch"
                                               : mode ==
                                                         ResourceControlMode::Adaptive
                                                     ? "shadow_controller"
                                                     : "hardware_limits";
  snapshot.effective_mode =
      mode == ResourceControlMode::ForceMax &&
              (!snapshot.hardware_detected || !snapshot.hardware_pin_matched)
          ? "compat"
          : snapshot.mode;
  // Retained as a compatibility diagnostic field. The new controller does not
  // learn or load a persisted capacity curve.
  snapshot.curve_valid = false;
  return snapshot;
}

struct MemoryPressureSample {
  bool valid = false;
  bool events_valid = false;
  bool pressure = false;
};

#ifdef __linux__
bool sampleMemoryEvents(ResourceControlSnapshot &snapshot) noexcept {
  try {
    std::ifstream file(cgroupV2File("memory.events"));
    if (!file)
      return false;
    std::string name;
    uint64_t value = 0;
    bool found = false;
    while (file >> name >> value) {
      if (name == "high")
        snapshot.memory_events_high = value;
      else if (name == "max")
        snapshot.memory_events_max = value;
      else if (name == "oom")
        snapshot.memory_events_oom = value;
      else if (name == "oom_kill")
        snapshot.memory_events_oom_kill = value;
      else if (name == "sock_throttled")
        snapshot.memory_events_sock_throttled = value;
      else
        continue;
      found = true;
    }
    return found;
  } catch (...) {
    return false;
  }
}
#endif

MemoryPressureSample memoryPressure(
    ResourceControlSnapshot &snapshot) noexcept {
  MemoryPressureSample sample;
#ifdef __linux__
  std::string memory_current =
      readFirstLine(cgroupV2File("memory.current"));
  if (memory_current.empty())
    memory_current =
        readFirstLine(cgroupV1File("memory", "memory.usage_in_bytes"));
  if (!memory_current.empty()) {
    snapshot.memory_current_bytes = parseFiniteBytes(memory_current);
    sample.valid = true;
  } else {
    struct sysinfo info {};
    if (sysinfo(&info) == 0) {
      snapshot.host_total_memory_bytes =
          static_cast<uint64_t>(info.totalram) * info.mem_unit;
      snapshot.host_available_memory_bytes = linuxAvailableMemoryBytes();
      if (snapshot.host_available_memory_bytes == 0)
        snapshot.host_available_memory_bytes =
            static_cast<uint64_t>(info.freeram) * info.mem_unit;
      if (snapshot.host_total_memory_bytes != 0 &&
          snapshot.host_available_memory_bytes <=
              snapshot.host_total_memory_bytes) {
        snapshot.memory_current_bytes =
            snapshot.host_total_memory_bytes -
            snapshot.host_available_memory_bytes;
        sample.valid = true;
      }
    }
  }
  snapshot.swap_current_bytes =
      parseFiniteBytes(readFirstLine(cgroupV2File("memory.swap.current")));
  if (snapshot.swap_current_bytes == 0) {
    const uint64_t memory_and_swap = parseFiniteBytes(
        readFirstLine(
            cgroupV1File("memory", "memory.memsw.usage_in_bytes")));
    if (memory_and_swap > snapshot.memory_current_bytes)
      snapshot.swap_current_bytes =
          memory_and_swap - snapshot.memory_current_bytes;
  }
  snapshot.memory_peak_bytes =
      parseFiniteBytes(readFirstLine(cgroupV2File("memory.peak")));
  sample.events_valid = sampleMemoryEvents(snapshot);
  snapshot.memory_events_sample_valid = sample.events_valid;
  snapshot.cpu_psi_some_milli_percent = parsePsiAvg10WithFallback(
      cgroupV2File("cpu.pressure"), "/proc/pressure/cpu", "some");
  snapshot.cpu_psi_full_milli_percent = parsePsiAvg10WithFallback(
      cgroupV2File("cpu.pressure"), "/proc/pressure/cpu", "full");
  snapshot.memory_psi_some_milli_percent = parsePsiAvg10WithFallback(
      cgroupV2File("memory.pressure"), "/proc/pressure/memory", "some");
  snapshot.memory_psi_full_milli_percent = parsePsiAvg10WithFallback(
      cgroupV2File("memory.pressure"), "/proc/pressure/memory", "full");
  snapshot.io_psi_some_milli_percent = parsePsiAvg10WithFallback(
      cgroupV2File("io.pressure"), "/proc/pressure/io", "some");
  snapshot.open_fds = countOpenFileDescriptors();
  snapshot.open_fds_available = snapshot.open_fds != 0;
#elif defined(_WIN32)
  sample.valid = sampleWindowsMemory(snapshot);
#endif
  uint64_t boundary = snapshot.memory_max_bytes;
  if (snapshot.memory_high_bytes != 0)
    boundary = boundary == 0 ? snapshot.memory_high_bytes
                             : std::min(boundary,
                                        snapshot.memory_high_bytes);
  if (boundary == 0)
    boundary = snapshot.host_total_memory_bytes;
  const bool near_boundary =
      sample.valid && boundary != 0 && snapshot.memory_current_bytes != 0 &&
      snapshot.memory_current_bytes >= boundary - boundary / 10;
  sample.pressure = near_boundary;
  return sample;
}

void controllerLoop() noexcept {
  std::unique_lock<std::mutex> lock(runtime.mutex);
  uint64_t previous_accepted = requestAdmissionSnapshot().accepted;
  uint64_t previous_successful =
      requestLifecycleMetricsSnapshot().successful_owners;
  uint64_t previous_memory_high = runtime.snapshot.memory_events_high;
  uint64_t previous_memory_max = runtime.snapshot.memory_events_max;
  uint64_t previous_oom = runtime.snapshot.memory_events_oom;
  uint64_t previous_oom_kill = runtime.snapshot.memory_events_oom_kill;
  ResourceGovernorState governor{
      std::max<uint64_t>(1, runtime.snapshot.suggested_cpu_permits), 0, 0};
  while (!runtime.stopping) {
    if (runtime.condition.wait_for(lock, std::chrono::seconds(1),
                                   [] { return runtime.stopping; }))
      break;
    ResourceControlSnapshot next = runtime.snapshot;
    const ResourcePermitBudget baseline = computeConservativeResourceBudget(
        static_cast<double>(next.effective_cpu_millis) / 1000.0,
        0);
    next.max_cpu_permits = baseline.cpu_permits;
    next.suggested_active_flows = baseline.active_flows;
    next.suggested_outbound_connections = baseline.outbound_connections;
    if (next.nofile_soft != 0)
      next.suggested_outbound_connections = std::min<uint64_t>(
          next.suggested_outbound_connections,
          std::max<uint64_t>(1, next.nofile_soft / 4));
    lock.unlock();
    try {
      const RequestAdmissionSnapshot admission = requestAdmissionSnapshot();
      const WorkloadSchedulerSnapshot scheduler = legacyRequestFlowSnapshot();
      const RequestLifecycleMetricsSnapshot lifecycle =
          requestLifecycleMetricsSnapshot();
      const uint64_t arrivals = admission.accepted - previous_accepted;
      previous_accepted = admission.accepted;
      const uint64_t successful =
          lifecycle.successful_owners - previous_successful;
      previous_successful = lifecycle.successful_owners;
      const MemoryPressureSample memory = memoryPressure(next);
      const bool memory_event = memory.events_valid &&
          (next.memory_events_high > previous_memory_high ||
           next.memory_events_max > previous_memory_max ||
           next.memory_events_oom > previous_oom ||
           next.memory_events_oom_kill > previous_oom_kill);
      if (memory.events_valid) {
        previous_memory_high = next.memory_events_high;
        previous_memory_max = next.memory_events_max;
        previous_oom = next.memory_events_oom;
        previous_oom_kill = next.memory_events_oom_kill;
      }
      const bool pressure = memory.pressure || memory_event;
      const bool active = arrivals != 0 || successful != 0 ||
                          scheduler.active != 0 ||
                          scheduler.queued_entries != 0;
      const bool force_max = next.effective_mode == "force_max";
      const bool telemetry_valid = memory.valid &&
          (!next.memory_events_supported || memory.events_valid);
      const ResourceGovernorDecision decision = governorStep(
          governor,
          {next.max_cpu_permits, force_max, telemetry_valid,
           pressure && !memory_event, memory_event, active});
      next.suggested_cpu_permits = decision.permits;
      next.controller_state = decision.state;
      next.controller_reason = decision.reason;
      next.pressure_fallback = decision.pressure_fallback;
      setConversionCpuPermitLimit(decision.permits);
      ++next.sample_count;
    } catch (...) {
      const ResourceGovernorDecision decision = governorStep(
          governor, {next.max_cpu_permits,
                     next.effective_mode == "force_max", false, false,
                     false, false});
      next.suggested_cpu_permits = decision.permits;
      next.controller_state = decision.state;
      next.controller_reason = "telemetry_error";
      next.pressure_fallback = true;
      setConversionCpuPermitLimit(decision.permits);
    }
    lock.lock();
    runtime.snapshot = std::move(next);
    runtime.sampled_at = Clock::now();
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
    if (runtime.configuration_frozen &&
        (runtime.snapshot.mode != snapshot.mode ||
         runtime.snapshot.hardware_pin != snapshot.hardware_pin ||
         runtime.snapshot.configured_cpu_cap != snapshot.configured_cpu_cap ||
         runtime.snapshot.configured_pending_connections !=
             snapshot.configured_pending_connections ||
         runtime.snapshot.configured_server_threads !=
             snapshot.configured_server_threads ||
         runtime.snapshot.configured_deadline_ms !=
             snapshot.configured_deadline_ms ||
         runtime.snapshot.hardware_fingerprint !=
             snapshot.hardware_fingerprint))
      throw std::invalid_argument(
          "advanced resource-capacity changes require a process restart");
  }
  const bool apply_force_max =
      *parsed == ResourceControlMode::ForceMax && snapshot.hardware_detected &&
      snapshot.hardware_pin_matched;
  uint64_t memory_boundary =
      snapshot.memory_max_bytes != 0 ? snapshot.memory_max_bytes
                                     : snapshot.host_total_memory_bytes;
  if (snapshot.memory_high_bytes != 0 &&
      (memory_boundary == 0 || snapshot.memory_high_bytes < memory_boundary))
    memory_boundary = snapshot.memory_high_bytes;
  uint64_t admission_entries = UINT64_C(2048);
  uint64_t admission_bytes = UINT64_C(64) * 1024 * 1024;
  uint64_t retained_bytes = 0;
  if (apply_force_max) {
    settings.maxConcurThreads = static_cast<int>(
        std::min<uint64_t>(snapshot.suggested_cpu_permits, INT_MAX));
    settings.maxServerThreads =
        std::max(settings.maxServerThreads, settings.maxConcurThreads);
    admission_entries = computeForceMaxAdmissionEntries(
        memory_boundary, snapshot.nofile_soft,
        snapshot.suggested_outbound_connections);
    admission_bytes = computeForceMaxRequestByteLimit(memory_boundary);
    retained_bytes = computeForceMaxRetainedByteLimit(memory_boundary);
    settings.maxPendingConns = static_cast<int>(
        std::min<uint64_t>(admission_entries, INT_MAX));
    snapshot.startup_budget_applied = true;
    snapshot.permits_applied = true;
    snapshot.effective_mode = "force_max";
    snapshot.controller_state = "max_ready_static";
    snapshot.controller_reason = "hardware_limits";
  } else if (*parsed == ResourceControlMode::Adaptive) {
    admission_entries =
        static_cast<uint64_t>(std::clamp(settings.maxPendingConns, 1, 2048));
    retained_bytes = UINT64_C(64) * 1024 * 1024;
    snapshot.suggested_cpu_permits =
        std::max<uint64_t>(1, snapshot.max_cpu_permits / 2);
  }
  configureRequestAdmissionLimits(admission_entries, admission_bytes);
  configureRetainedResponseByteLimit(retained_bytes);
  settings.resourceControlEffective = snapshot.effective_mode;
  {
    std::lock_guard<std::mutex> lock(runtime.mutex);
    runtime.snapshot = snapshot;
    runtime.sampled_at = Clock::now();
  }
  if (!settings.forceMaxCurveFingerprint.empty())
    writeLog(LOG_LEVEL_WARNING,
             "force_max_curve_fingerprint 现仅作为可选硬件 pin；不代表已验证容量曲线。");
  writeLog(LOG_LEVEL_INFO,
           "RESOURCE_CONTROL_EFFECTIVE mode=" + snapshot.mode +
               " effective_mode=" + snapshot.effective_mode +
               " source=" + snapshot.source + " state=" +
               snapshot.controller_state + " reason=" +
               snapshot.controller_reason + " cpu_millis=" +
               std::to_string(snapshot.effective_cpu_millis) +
               " affinity=" + std::to_string(snapshot.affinity_cpus) +
               " cpuset=" + std::to_string(snapshot.cpuset_cpus) +
               " quota_millis=" +
               std::to_string(snapshot.cpu_quota_millis) +
               " memory_max=" +
               std::to_string(snapshot.memory_max_bytes) +
               " cpu_permits=" +
               std::to_string(snapshot.suggested_cpu_permits) +
               " hardware_detected=" +
               (snapshot.hardware_detected ? "true" : "false") +
               " hardware_pin_matched=" +
               (snapshot.hardware_pin_matched ? "true" : "false") +
               " startup_budget_applied=" +
               (snapshot.startup_budget_applied ? "true" : "false") +
               " hardware=" + snapshot.hardware_fingerprint +
               " admission_entries=" + std::to_string(admission_entries) +
               " admission_bytes=" + std::to_string(admission_bytes) +
               " retained_bytes=" + std::to_string(retained_bytes) +
               " deadline_ms=" + std::to_string(settings.requestDeadlineMs));
}

ResourceControlSnapshot resourceControlSnapshot() {
  std::lock_guard<std::mutex> lock(runtime.mutex);
  ResourceControlSnapshot snapshot = runtime.snapshot;
  snapshot.sample_age_ms = static_cast<uint64_t>(
      std::max<int64_t>(0, std::chrono::duration_cast<std::chrono::milliseconds>(
                               Clock::now() - runtime.sampled_at)
                               .count()));
  return snapshot;
}

void startResourceControlRuntime() {
  std::lock_guard<std::mutex> lock(runtime.mutex);
  if (runtime.configuration_frozen)
    return;
  runtime.configuration_frozen = true;
  if (runtime.snapshot.effective_mode != "adaptive" &&
      runtime.snapshot.effective_mode != "force_max")
    return;
  setConversionCpuPermitLimit(runtime.snapshot.suggested_cpu_permits);
  runtime.snapshot.controller_state = "starting";
  runtime.snapshot.controller_reason = "controller_start";
  runtime.stopping = false;
  runtime.thread = std::thread(controllerLoop);
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
