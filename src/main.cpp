#include <csignal>
#include <iostream>
#include <string>
#include <unistd.h>

#include <dirent.h>
#include <sys/types.h>

#include "config/ruleset.h"
#include "handler/interfaces.h"
#include "handler/settings.h"
#include "handler/version_page.h"
#include "handler/webget.h"
#include "script/cron.h"
#include "server/socket.h"
#include "server/webserver.h"
#include "utils/defer.h"
#include "utils/file_extra.h"
#include "utils/logger.h"
#include "utils/network.h"
#include "utils/rapidjson_extra.h"
#include "utils/system.h"
#include "utils/urlencode.h"
#include "version.h"

// #include "vfs.h"

WebServer webServer;

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
  // std::cerr<<"Interrupt signal "<<sig<<" received. Exiting gracefully...\n";
  writeLog(0,
           "收到中断信号 " + std::to_string(sig) + "，正在退出...",
           LOG_LEVEL_FATAL);
  switch (sig) {
#ifndef _WIN32
  case SIGHUP:
  case SIGQUIT:
#endif // _WIN32
  case SIGTERM:
  case SIGINT:
    webServer.stop_web_server();
    break;
  }
}

void cron_tick_caller() {
  if (global.enableCron)
    cron_tick();
}

int main(int argc, char *argv[]) {
#ifndef _DEBUG
  std::string prgpath = argv[0];
  setcd(prgpath); // first switch to program directory
#endif            // _DEBUG
  if (fileExist("pref.toml"))
    global.prefPath = "pref.toml";
  else if (fileExist("pref.yml"))
    global.prefPath = "pref.yml";
  else if (!fileExist("pref.ini")) {
    if (fileExist("pref.example.toml")) {
      fileCopy("pref.example.toml", "pref.toml");
      global.prefPath = "pref.toml";
    } else if (fileExist("pref.example.yml")) {
      fileCopy("pref.example.yml", "pref.yml");
      global.prefPath = "pref.yml";
    } else if (fileExist("pref.example.ini"))
      fileCopy("pref.example.ini", "pref.ini");
  }
  chkArg(argc, argv);
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
  readConf();
  // vfs::vfs_read("vfs.ini");
  if (!global.updateRulesetOnRequest)
    refreshRulesets(global.customRulesets, global.rulesetsContent);

  // API_MODE and API_TOKEN environment variables removed
  // APIMode is hardcoded to true for security
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

  if (global.generatorMode)
    return simpleGenerator();

  /*
  webServer.append_response("GET", "/", "text/plain", [](RESPONSE_CALLBACK_ARGS)
  -> std::string
  {
      return "SubConverter-Extended " VERSION " backend\n";
  });
  */

  webServer.append_response("GET", "/version/favicon-dark.svg",
                            "image/svg+xml; charset=utf-8",
                            version_page::faviconDark);
  webServer.append_response("GET", "/version/favicon-light.svg",
                            "image/svg+xml; charset=utf-8",
                            version_page::faviconLight);

  webServer.append_response("GET", "/version", "text/html; charset=utf-8",
                            version_page::page);

  webServer.append_response(
      "GET", "/robots.txt", "text/plain; charset=utf-8",
      [](RESPONSE_CALLBACK_ARGS) -> std::string {
        return "User-agent: *\n"
               "Disallow: /version\n"
               "Disallow: /v\n";
      });

  /*
  webServer.append_response("GET", "/refreshrules", "text/plain",
                            [](RESPONSE_CALLBACK_ARGS) -> std::string {
                              // Token authentication disabled - no
                              // authorization required
                              refreshRulesets(global.customRulesets,
                                              global.rulesetsContent);
                              return "done\n";
                            });
  */

  /*
  webServer.append_response("GET", "/readconf", "text/plain",
                            [](RESPONSE_CALLBACK_ARGS) -> std::string {
                              // Token authentication disabled - no
                              // authorization required
                              readConf();
                              if (!global.updateRulesetOnRequest)
                                refreshRulesets(global.customRulesets,
                                                global.rulesetsContent);
                              return "done\n";
                            });
  */

  /*
  webServer.append_response(
      "POST", "/updateconf", "text/plain",
      [](RESPONSE_CALLBACK_ARGS) -> std::string {
        // Token authentication disabled - no authorization required
        std::string type = getUrlArg(request.argument, "type");
        if (type == "form" || type == "direct") {
          fileWrite(global.prefPath, request.postdata, true);
        } else {
          response.status_code = 501;
          return "Not Implemented\n";
        }

        readConf();
        if (!global.updateRulesetOnRequest)
          refreshRulesets(global.customRulesets, global.rulesetsContent);
        return "done\n";
      });
  */

  /*
  webServer.append_response("GET", "/flushcache", "text/plain",
                            [](RESPONSE_CALLBACK_ARGS) -> std::string {
                              // Token authentication disabled - no
                              // authorization required
                              flushCache();
                              return "done";
                            });
  */

  webServer.append_response("GET", "/sub", "text/plain;charset=utf-8",
                            subconverter);

  webServer.append_response("HEAD", "/sub", "text/plain", subconverter);

  /*
  webServer.append_response("GET", "/sub2clashr", "text/plain;charset=utf-8",
                            simpleToClashR);

  webServer.append_response("GET", "/surge2clash", "text/plain;charset=utf-8",
                            surgeConfToClash);
  */

  webServer.append_response("GET", "/getruleset", "text/plain;charset=utf-8",
                            getRuleset);

  /*
  webServer.append_response("GET", "/getprofile", "text/plain;charset=utf-8",
                            getProfile);

  webServer.append_response("GET", "/render", "text/plain;charset=utf-8",
                            renderTemplate);
  */

  if (!global.APIMode) {
    webServer.append_response("GET", "/get", "text/plain;charset=utf-8",
                              [](RESPONSE_CALLBACK_ARGS) -> std::string {
                                std::string url = urlDecode(
                                    getUrlArg(request.argument, "url"));
                                return webGet(url, "");
                              });

    webServer.append_response(
        "GET", "/getlocal", "text/plain;charset=utf-8",
        [](RESPONSE_CALLBACK_ARGS) -> std::string {
          return fileGet(urlDecode(getUrlArg(request.argument, "path")));
        });
  }

  // webServer.append_response("POST", "/create-profile",
  // "text/plain;charset=utf-8", createProfile);

  // webServer.append_response("GET", "/list-profiles",
  // "text/plain;charset=utf-8", listProfiles);

  std::string env_port = getEnv("PORT");
  if (!env_port.empty())
    global.listenPort = to_int(env_port, global.listenPort);
  if (global.securityProfile == "lan" &&
      (global.listenAddress == "0.0.0.0" || global.listenAddress == "::")) {
    writeLog(0,
             "当前安全档位为 lan，但正在监听所有网络接口。面向公网部署请使用 "
             "security.profile=public。",
             LOG_LEVEL_WARNING);
  }
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

#ifdef _WIN32
  WSACleanup();
#endif // _WIN32
  return ret;
}
