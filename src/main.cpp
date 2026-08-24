#include <cerrno>
#include <csignal>
#include <cstdio>
#include <fcntl.h>
#include <iostream>
#include <rapidjson/stringbuffer.h>
#include <string>
#include <unistd.h>

#include <dirent.h>
#include <sys/types.h>

#include "config/preference_file.h"
#include "config/ruleset.h"
#include "handler/curl_handle_pool.h"
#include "handler/dashboard_auth.h"
#include "handler/conversion_service.h"
#include "handler/dashboard_page.h"
#include "handler/inspect_page.h"
#include "handler/interfaces.h"
#include "handler/multithread.h"
#include "handler/settings.h"
#include "handler/settings_view.h"
#include "handler/statistics.h"
#include "handler/version_page.h"
#include "script/cron.h"
#include "server/socket.h"
#include "server/webserver.h"
#include "utils/defer.h"
#include "utils/file.h"
#include "utils/logger.h"
#include "utils/rapidjson_extra.h"
#include "utils/resource_control.h"
#include "utils/system.h"
#include "version.h"

// #include "vfs.h"

WebServer webServer;
static volatile std::sig_atomic_t pendingShutdownSignal = 0;

#ifndef _WIN32
void SetConsoleTitle(const std::string &title) {
  if (!isatty(STDOUT_FILENO))
    return;
  std::cout << "\033]0;" << title << '\007' << std::flush;
}
#endif // _WIN32

void setcd(std::string &file) {
  char szTemp[4096] = {}, filename[256] = {};
  std::string path;
#ifdef _WIN32
  char *pname = NULL;
  DWORD retVal = GetFullPathName(file.data(), 1023, szTemp, &pname);
  if (!retVal)
    return;
  strcpy(filename, pname);
  strrchr(szTemp, '\\')[1] = '\0';
#else
  char *ret = realpath(file.data(), szTemp);
  if (ret == nullptr)
    return;
  ret = strcpy(filename, strrchr(szTemp, '/') + 1);
  if (ret == nullptr)
    return;
  strrchr(szTemp, '/')[1] = '\0';
#endif // _WIN32
  file.assign(filename);
  path.assign(szTemp);
  chdir(path.data());
}

struct LogRedirectResult {
  bool success = false;
  const char *stage = "open";
  int error_number = 0;
};

LogRedirectResult redirectStderrToAppendFile(const char *path) {
  std::fflush(stderr);
  int flags = O_WRONLY | O_CREAT | O_APPEND;
#ifdef _WIN32
  // Preserve the text-mode line endings of the previous freopen("a") path.
  flags |= O_TEXT;
#endif
  const int file_descriptor = open(path, flags, 0644);
  if (file_descriptor < 0)
    return {false, "open", errno};
  if (file_descriptor != STDERR_FILENO &&
      dup2(file_descriptor, STDERR_FILENO) < 0) {
    const int error_number = errno;
    close(file_descriptor);
    return {false, "dup2", error_number};
  }
  if (file_descriptor != STDERR_FILENO)
    close(file_descriptor);
  clearerr(stderr);
  std::cerr.clear();
  return {true, "none", 0};
}

void chkArg(int argc, char *argv[]) {
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-cfw") == 0) {
      global.CFWChildProcess = true;
      global.updateRulesetOnRequest = true;
    } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--file") == 0) {
      if (i < argc - 1)
        global.prefPath.assign(argv[++i]);
    } else if (strcmp(argv[i], "-g") == 0 || strcmp(argv[i], "--gen") == 0) {
      global.generatorMode = true;
    } else if (strcmp(argv[i], "--artifact") == 0) {
      if (i < argc - 1)
        global.generateProfiles.assign(argv[++i]);
    } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--log") == 0) {
      if (i < argc - 1) {
        const char *log_path = argv[++i];
        // --log is an explicit local-operator destination, not a path derived
        // from an HTTP request. Arbitrary absolute paths are part of the CLI
        // contract and are opened without invoking a shell.
        // codeql[cpp/path-injection]
        const LogRedirectResult result = redirectStderrToAppendFile(log_path);
        if (result.success) {
          writeLog(LOG_LEVEL_INFO,
                   "LOG_REDIRECT_ACTIVE mode=append rotation=external");
        } else {
          writeLog(LOG_LEVEL_ERROR,
                   "LOG_REDIRECT_FAILED stage=" + std::string(result.stage) +
                       " errno=" + std::to_string(result.error_number) +
                       " action=continue-with-stderr");
        }
      } else {
        writeLog(LOG_LEVEL_ERROR,
                 "LOG_REDIRECT_FAILED reason=missing-path "
                 "action=continue-with-stderr");
      }
    }
  }
}

const char *shutdownSignalName(std::sig_atomic_t signal) {
  switch (signal) {
#ifndef _WIN32
  case SIGHUP:
    return "SIGHUP";
  case SIGQUIT:
    return "SIGQUIT";
#endif
  case SIGTERM:
    return "SIGTERM";
  case SIGINT:
    return "SIGINT";
  default:
    return "UNKNOWN";
  }
}

void signal_handler(int sig) {
  switch (sig) {
#ifndef _WIN32
  case SIGHUP:
  case SIGQUIT:
#endif // _WIN32
  case SIGTERM:
  case SIGINT:
    pendingShutdownSignal = sig;
    break;
  }
}

void cron_tick_caller() {
  const std::sig_atomic_t signal = pendingShutdownSignal;
  if (signal != 0) {
    pendingShutdownSignal = 0;
    writeLog(LOG_LEVEL_INFO,
             "SHUTDOWN_REQUESTED signal=" +
                 std::string(shutdownSignalName(signal)) +
                 " signal_code=" + std::to_string(signal) +
                 " action=graceful-stop");
    webServer.stop_web_server();
    return;
  }
  if (global.enableCron)
    cron_tick();
  if (global.statisticsEnabled)
    statistics::tick();
}

void shutdown_runtime() {
  shutdownResourceControlRuntime();
  shutdownConversionScheduler();
  shutdownRulesetExecutor();
  statistics::shutdown();
  shutdownGlobalCurlHandlePool();
}

void begin_runtime_shutdown() {
  cancelAllActiveRequests(RequestCancellationReason::Shutdown);
  shutdownResourceControlRuntime();
  requestConversionSchedulerShutdown();
  requestRulesetExecutorShutdown();
}

void drain_runtime_shutdown() {
  shutdownRulesetExecutor();
  shutdownConversionScheduler();
}

std::string publishRuntimeState() {
  const std::string path = getEnv("SUBCONVERTER_RUNTIME_STATE_FILE");
  if (path.empty())
    return "";

  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  writer.StartObject();
  writer.Key("schema");
  writer.Int(1);
  writer.Key("pid");
  writer.Int64(static_cast<int64_t>(getpid()));
  writer.Key("listen_address");
  writer.String(global.listenAddress.c_str());
  writer.Key("listen_port");
  writer.Int(global.listenPort);
  writer.Key("version");
  writer.String(VERSION);
  writer.Key("build_id");
  writer.String(BUILD_ID);
  writer.EndObject();

  const int result = fileWrite(path, buffer.GetString(), true);
  if (fileCommitFailed(result)) {
    writeLog(LOG_LEVEL_WARNING,
             "RUNTIME_STATE_WRITE_FAILED action=continue-without-state");
    return "";
  }
  return path;
}

int main(int argc, char *argv[]) {
#ifdef _WIN32
  const UINT original_console_output_code_page = GetConsoleOutputCP();
  const bool console_output_code_page_changed =
      original_console_output_code_page != 0 &&
      original_console_output_code_page != CP_UTF8 &&
      SetConsoleOutputCP(CP_UTF8) != 0;
  defer(if (console_output_code_page_changed)
            SetConsoleOutputCP(original_console_output_code_page);)
#endif
#ifndef _DEBUG
  std::string prgpath = argv[0];
  setcd(prgpath); // first switch to program directory
#endif            // _DEBUG
  const PreferenceFileSelection default_preference =
      prepareDefaultPreferenceFile();
  global.prefPath = default_preference.path;
  chkArg(argc, argv);
  if (default_preference.status ==
      PreferenceFileStatus::CopyCommittedUnsynced) {
    writeLog(LOG_LEVEL_WARNING,
             "DEFAULT_PREFERENCE_COPY_VISIBLE source=" +
                 default_preference.source +
                 " destination=" + default_preference.path +
                 " new_file_visible=true durability=unconfirmed "
                 "action=continue");
  }
  if (defaultPreferenceRequiresExit(default_preference, global.prefPath)) {
    const bool temporary_remaining =
        default_preference.status ==
        PreferenceFileStatus::CopyFailedTemporaryRemaining;
    writeLog(LOG_LEVEL_FATAL,
             std::string("DEFAULT_PREFERENCE_COPY_FAILED") +
                 " source=" + default_preference.source +
                 " destination=" + default_preference.path +
                 " new_file_visible=false" +
                 (temporary_remaining
                      ? " temporary_file_remaining=true"
                      : " temporary_file_remaining=false") +
                 " action=exit");
    return 1;
  }
  setcd(global.prefPath); // then switch to pref directory
  writeLog(LOG_LEVEL_INFO, "SubConverter-Extended " VERSION " 正在启动...");
#ifdef _WIN32
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0) {
    // std::cerr<<"WSAStartup failed.\n";
    writeLog(LOG_LEVEL_FATAL, "WSAStartup 初始化失败。");
    return 1;
  }
  defer(WSACleanup();)
#else
  signal(SIGPIPE, SIG_IGN);
  signal(SIGABRT, SIG_IGN);
  signal(SIGHUP, signal_handler);
  signal(SIGQUIT, signal_handler);
#endif // _WIN32
  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);

  SetConsoleTitle("SubConverter-Extended " VERSION);
  if (!readConf())
    return 1;
  writeLog(LOG_LEVEL_INFO,
      "并发运行参数：HTTP base/max threads=" +
          std::to_string(global.maxConcurThreads) + "/" +
          std::to_string(global.maxServerThreads) +
          ", ruleset executor workers/queue=" +
          std::to_string(rulesetExecutorWorkerCount()) + "/" +
          std::to_string(rulesetExecutorQueueCapacity()) +
          ", curl pool cap=" +
          std::to_string(curlHandlePoolCapacity(
              static_cast<size_t>(global.maxConcurThreads))) +
          ", ExternalConfig cache=" +
          std::to_string(externalConfigCacheMaxEntries()) + " entries/" +
          std::to_string(externalConfigCacheMaxBytes()) + " bytes" +
          ", ruleset conversion cache=" +
          std::to_string(rulesetConversionCacheMaxEntries()) + " entries/" +
          std::to_string(rulesetConversionCacheMaxBytes()) + " bytes。");
  // Register cleanup before any background refresh starts. The HTTP backend
  // drains accepted requests before returning, so only then may the executor
  // cancel unobserved work and release its curl leases before the pool stops.
  defer(shutdown_runtime();)
  startResourceControlRuntime();
  statistics::initialize();
  // vfs::vfs_read("vfs.ini");
  if (!global.updateRulesetOnRequest)
    refreshRulesets(global.customRulesets, global.rulesetsContent);

  auto normalize_managed_prefix = [](const std::string &raw_value) {
    std::string value = trimWhitespace(raw_value, true, true);
    while (value.size() > 1 && value.back() == '/' && !endsWith(value, "://"))
      value.pop_back();
    return value;
  };
  global.managedConfigPrefix = normalize_managed_prefix(global.managedConfigPrefix);
  std::string env_managed_config_prefix =
      normalize_managed_prefix(getEnv("MANAGED_CONFIG_PREFIX"));
  std::string env_managed_prefix =
      normalize_managed_prefix(getEnv("MANAGED_PREFIX"));
  if (!env_managed_config_prefix.empty() && !env_managed_prefix.empty() &&
      env_managed_config_prefix != env_managed_prefix) {
    writeLog(LOG_LEVEL_WARNING,
             "同时设置了 MANAGED_CONFIG_PREFIX 和 MANAGED_PREFIX，使用 "
             "MANAGED_CONFIG_PREFIX。");
  }
  if (!env_managed_config_prefix.empty())
    global.managedConfigPrefix = env_managed_config_prefix;
  else if (!env_managed_prefix.empty())
    global.managedConfigPrefix = env_managed_prefix;
  global.templateVars["managed_config_prefix"] = global.managedConfigPrefix;
  publishSettingsSnapshot(global);

  if (global.generatorMode)
    return simpleGenerator();

  webServer.append_response("GET", "/version/favicon-dark.svg",
                            "image/svg+xml; charset=utf-8",
                            version_page::faviconDark);
  webServer.append_response("GET", "/version/favicon-light.svg",
                            "image/svg+xml; charset=utf-8",
                            version_page::faviconLight);

  webServer.append_response("GET", "/version", "text/html; charset=utf-8",
                            version_page::page);
  webServer.append_response("GET", "/inspect", "text/html; charset=utf-8",
                            inspect_page::page);
  if (global.statisticsEnabled) {
    webServer.append_response(
        "GET", "/dashboard", "text/html; charset=utf-8",
        global.dashboardAuthEnabled ? dashboard_auth::page
                                    : dashboard_page::page);
    webServer.append_response(
        "GET", "/dashboard/data", "application/json; charset=utf-8",
        global.dashboardAuthEnabled ? dashboard_auth::data
                                    : statistics::dashboardData);
  }

  webServer.append_response(
      "GET", "/robots.txt", "text/plain; charset=utf-8",
      [](RESPONSE_CALLBACK_ARGS) -> std::string {
        return "User-agent: *\n"
               "Disallow: /version\n"
               "Disallow: /inspect\n"
               "Disallow: /dashboard\n"
               "Disallow: /v\n";
      });

  webServer.append_response("GET", "/healthz", "text/plain; charset=utf-8",
                            [](RESPONSE_CALLBACK_ARGS) -> std::string {
                              return "ok\n";
                            });

  if (global.resourceControlEffective == "compat") {
    webServer.append_response(
        "GET", "/sub", "text/plain;charset=utf-8",
        global.statisticsEnabled ? subconverterTracked : subconverter);
    webServer.append_response(
        "HEAD", "/sub", "text/plain",
        global.statisticsEnabled ? subconverterTracked : subconverter);
  } else {
    webServer.append_async_response(
        "GET", "/sub", "text/plain;charset=utf-8",
        global.statisticsEnabled ? subconverterTracked : subconverter,
        global.statisticsEnabled ? subconverterTrackedAsync
                                 : subconverterAsync);
    webServer.append_async_response(
        "HEAD", "/sub", "text/plain",
        global.statisticsEnabled ? subconverterTracked : subconverter,
        global.statisticsEnabled ? subconverterTrackedAsync
                                 : subconverterAsync);
  }

  webServer.append_response("GET", "/getruleset", "text/plain;charset=utf-8",
                            getRuleset);

  std::string env_port = getEnv("PORT");
  if (getEnv("SUBCONVERTER_LISTEN_PORT").empty() && !env_port.empty())
    global.listenPort = to_int(env_port, global.listenPort);
  publishSettingsSnapshot(global);
  const std::string runtime_state_path = publishRuntimeState();
  defer(if (!runtime_state_path.empty())
            std::remove(runtime_state_path.c_str());)
  if (global.securityProfile == "lan" &&
      (global.listenAddress == "0.0.0.0" || global.listenAddress == "::")) {
    writeLog(LOG_LEVEL_WARNING,
             "当前安全档位为 lan，但正在监听所有网络接口。面向公网部署请使用 "
             "security.profile=public。");
  }
  logSecurityPosture();
  listener_args args = {global.listenAddress,   global.listenPort,
                        global.maxPendingConns, global.maxConcurThreads,
                        cron_tick_caller,       200,
                        static_cast<uint32_t>(global.requestDeadlineMs),
                        begin_runtime_shutdown, drain_runtime_shutdown};
  // std::cout<<"Serving HTTP @
  // http://"<<listen_address<<":"<<listen_port<<std::endl;
  writeLog(LOG_LEVEL_INFO,
           "正在启动 HTTP 服务：http://" + global.listenAddress + ":" +
               std::to_string(global.listenPort));
  int ret = webServer.start_web_server_multi(&args);
  return ret;
}
