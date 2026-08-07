#include <csignal>
#include <iostream>
#include <string>
#include <unistd.h>

#include <dirent.h>
#include <sys/types.h>

#include "config/preference_file.h"
#include "config/ruleset.h"
#include "handler/curl_handle_pool.h"
#include "handler/dashboard_auth.h"
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
#include "utils/logger.h"
#include "utils/rapidjson_extra.h"
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
      if (i < argc - 1)
        if (freopen(argv[++i], "a", stderr) == nullptr)
          std::cerr << "无法将输出重定向到日志文件。\n";
    }
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
    writeLog(0,
             "收到中断信号 " + std::to_string(signal) + "，正在退出...",
             LOG_LEVEL_FATAL);
    webServer.stop_web_server();
    return;
  }
  if (global.enableCron)
    cron_tick();
  if (global.statisticsEnabled)
    statistics::tick();
}

int main(int argc, char *argv[]) {
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
    writeLog(0,
             "DEFAULT_PREFERENCE_COPY_VISIBLE source=" +
                 default_preference.source +
                 " destination=" + default_preference.path +
                 " new_file_visible=true durability=unconfirmed "
                 "action=continue",
             LOG_LEVEL_WARNING);
  }
  if (defaultPreferenceRequiresExit(default_preference, global.prefPath)) {
    const bool temporary_remaining =
        default_preference.status ==
        PreferenceFileStatus::CopyFailedTemporaryRemaining;
    writeLog(0,
             std::string("DEFAULT_PREFERENCE_COPY_FAILED") +
                 " source=" + default_preference.source +
                 " destination=" + default_preference.path +
                 " new_file_visible=false" +
                 (temporary_remaining
                      ? " temporary_file_remaining=true"
                      : " temporary_file_remaining=false") +
                 " action=exit",
             LOG_LEVEL_FATAL);
    return 1;
  }
  setcd(global.prefPath); // then switch to pref directory
  writeLog(0, "SubConverter-Extended " VERSION " 正在启动...", LOG_LEVEL_INFO);
#ifdef _WIN32
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0) {
    // std::cerr<<"WSAStartup failed.\n";
    writeLog(0, "WSAStartup 初始化失败。", LOG_LEVEL_FATAL);
    return 1;
  }
  UINT origcp = GetConsoleOutputCP();
  defer(SetConsoleOutputCP(origcp);) SetConsoleOutputCP(65001);
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
  writeLog(
      0,
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
          std::to_string(rulesetConversionCacheMaxBytes()) + " bytes。",
      LOG_LEVEL_INFO);
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
    writeLog(0,
             "同时设置了 MANAGED_CONFIG_PREFIX 和 MANAGED_PREFIX，使用 "
             "MANAGED_CONFIG_PREFIX。",
             LOG_LEVEL_WARNING);
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

  webServer.append_response("GET", "/sub", "text/plain;charset=utf-8",
                            global.statisticsEnabled ? subconverterTracked
                                                     : subconverter);

  webServer.append_response("HEAD", "/sub", "text/plain",
                            global.statisticsEnabled ? subconverterTracked
                                                     : subconverter);

  webServer.append_response("GET", "/getruleset", "text/plain;charset=utf-8",
                            getRuleset);

  std::string env_port = getEnv("PORT");
  if (!env_port.empty())
    global.listenPort = to_int(env_port, global.listenPort);
  publishSettingsSnapshot(global);
  if (global.securityProfile == "lan" &&
      (global.listenAddress == "0.0.0.0" || global.listenAddress == "::")) {
    writeLog(0,
             "当前安全档位为 lan，但正在监听所有网络接口。面向公网部署请使用 "
             "security.profile=public。",
             LOG_LEVEL_WARNING);
  }
  logSecurityPosture();
  listener_args args = {global.listenAddress,   global.listenPort,
                        global.maxPendingConns, global.maxConcurThreads,
                        cron_tick_caller,       200};
  // std::cout<<"Serving HTTP @
  // http://"<<listen_address<<":"<<listen_port<<std::endl;
  writeLog(0,
           "正在启动 HTTP 服务：http://" + global.listenAddress + ":" +
               std::to_string(global.listenPort),
           LOG_LEVEL_INFO);
  int ret = webServer.start_web_server_multi(&args);
  statistics::shutdown();

#ifdef _WIN32
  WSACleanup();
#endif // _WIN32
  return ret;
}
