#include <csignal>
#include <iostream>
#include <string>
#include <unistd.h>

#include <dirent.h>
#include <sys/types.h>

#include "config/ruleset.h"
#include "handler/interfaces.h"
#include "handler/settings.h"
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
  system(std::string("echo \"\\033]0;" + title + R"(\007\c")").data());
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
          std::cerr << "Error redirecting output to file.\n";
    }
  }
}

void signal_handler(int sig) {
  // std::cerr<<"Interrupt signal "<<sig<<" received. Exiting gracefully...\n";
  writeLog(0,
           "Interrupt signal " + std::to_string(sig) +
               " received. Exiting gracefully...",
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
  writeLog(0, "SubConverter " VERSION " starting up..", LOG_LEVEL_INFO);
#ifdef _WIN32
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0) {
    // std::cerr<<"WSAStartup failed.\n";
    writeLog(0, "WSAStartup failed.", LOG_LEVEL_FATAL);
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

  SetConsoleTitle("SubConverter " VERSION);
  readConf();
  // vfs::vfs_read("vfs.ini");
  if (!global.updateRulesetOnRequest)
    refreshRulesets(global.customRulesets, global.rulesetsContent);

  // API_MODE and API_TOKEN environment variables removed
  // APIMode is hardcoded to true for security
  std::string env_managed_prefix = getEnv("MANAGED_PREFIX");
  if (!env_managed_prefix.empty())
    global.managedConfigPrefix = env_managed_prefix;

  if (global.generatorMode)
    return simpleGenerator();

  /*
  webServer.append_response("GET", "/", "text/plain", [](RESPONSE_CALLBACK_ARGS)
  -> std::string
  {
      return "subconverter " VERSION " backend\n";
  });
  */

  webServer.append_response(
      "GET", "/version", "text/html; charset=utf-8",
      [](RESPONSE_CALLBACK_ARGS) -> std::string {
        std::string build_id = BUILD_ID;
        std::string commit_link =
            build_id.empty()
                ? ""
                : "<a "
                  "href=\"https://github.com/Aethersailor/"
                  "SubConverter-Extended/commit/" +
                      build_id + "\" target=\"_blank\">" + build_id + "</a>";

        return R"(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="color-scheme" content="light dark">
    <title>SubConverter-Extended</title>
    <style>
        :root {
            /* Light Theme (Default) */
            --bg-gradient: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            --container-bg: rgba(255, 255, 255, 0.7);
            --container-border: rgba(255, 255, 255, 0.4);
            --shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.1);
            --text-primary: #2d3748;
            --text-secondary: #4a5568;
            --divider-bg: linear-gradient(90deg, transparent, rgba(0,0,0,0.1), transparent);
            --info-block-bg: rgba(0, 0, 0, 0.03);
            --info-block-border: rgba(0,0,0,0.05);
            --link-color: #667eea;
            --link-hover: #764ba2;
            --text-shadow: none;
        }

        @media (prefers-color-scheme: dark) {
            :root {
                /* Dark Theme */
                --bg-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                --container-bg: rgba(255, 255, 255, 0.1);
                --container-border: rgba(255, 255, 255, 0.18);
                --shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
                --text-primary: #ffffff;
                --text-secondary: rgba(255, 255, 255, 0.95);
                --divider-bg: linear-gradient(90deg, transparent, rgba(255,255,255,0.5), transparent);
                --info-block-bg: rgba(255, 255, 255, 0.08);
                --info-block-border: rgba(255,255,255,0.6);
                --link-color: #ffd700;
                --link-hover: #ffed4e;
                --text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
            }
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: var(--bg-gradient);
            padding: 20px;
            color: var(--text-primary);
            transition: background 0.3s ease, color 0.3s ease;
        }
        
        .container {
            background: var(--container-bg);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            max-width: 900px;
            width: 100%;
            box-shadow: var(--shadow);
            border: 1px solid var(--container-border);
            animation: fadeIn 0.6s ease-out;
            transition: background 0.3s ease, border-color 0.3s ease, box-shadow 0.3s ease;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        h1 {
            color: var(--text-primary);
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 700;
            text-shadow: var(--text-shadow);
        }
        
        .subtitle {
            color: var(--text-secondary);
            font-size: 1.2em;
            margin-bottom: 20px;
            font-weight: 400;
            font-style: italic;
            opacity: 0.9;
        }
        
        .divider {
            height: 1px;
            background: var(--divider-bg);
            margin: 25px 0;
        }
        
        .description {
            color: var(--text-secondary);
            font-size: 1.05em;
            line-height: 1.8;
            margin-bottom: 15px;
        }
        
        .info-block {
            background: var(--info-block-bg);
            border-radius: 12px;
            padding: 20px;
            margin: 25px 0;
            border-left: 4px solid var(--info-block-border);
        }
        
        .info-row {
            color: var(--text-secondary);
            font-size: 1.1em;
            margin: 10px 0;
            display: flex;
            align-items: center;
        }
        
        .info-label {
            font-weight: 600;
            min-width: 90px;
            color: var(--text-primary);
        }
        
        a {
            color: var(--link-color);
            text-decoration: none;
            position: relative;
            transition: all 0.3s ease;
            font-weight: 500;
        }
        
        a::after {
            content: '';
            position: absolute;
            bottom: -2px;
            left: 0;
            width: 0;
            height: 2px;
            background: var(--link-color);
            transition: width 0.3s ease;
        }
        
        a:hover::after {
            width: 100%;
        }
        
        a:hover {
            color: var(--link-hover);
            text-shadow: 0 0 8px rgba(var(--link-hover), 0.4);
        }
        
        .footer {
            margin-top: 25px;
            padding-top: 20px;
            text-align: center;
            color: var(--text-secondary);
            opacity: 0.8;
            font-size: 0.9em;
        }
        
        @media (max-width: 600px) {
            .container { padding: 30px 20px; }
            h1 { font-size: 2em; }
            .info-row { flex-direction: column; align-items: flex-start; }
            .info-label { margin-bottom: 5px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>SubConverter-Extended</h1>
        <p class="subtitle">A Modern Evolution of subconverter</p>
        <div class="divider"></div>
        
        <p class="description">
            An enhanced implementation of subconverter, aligned with the 
            <a href="https://github.com/MetaCubeX/mihomo/tree/Meta" target="_blank">Mihomo</a> 
            <a href="https://wiki.metacubex.one/config/" target="_blank">configuration</a>
        </p>
        
        <p class="description">
            Primarily intended for use alongside <a href="https://github.com/vernesong/OpenClash" target="_blank">OpenClash</a>, also compatible with other Clash clients
        </p>
        
        <p class="description">
            Derived as a companion backend for the 
            <a href="https://github.com/Aethersailor/Custom_OpenClash_Rules" target="_blank">Custom_OpenClash_Rules</a> project
        </p>
        
        <div class="info-block">
            <div class="info-row">
                <span class="info-label">Version:</span>
                <span>)" VERSION R"(</span>
            </div>
            <div class="info-row">
                <span class="info-label">Build:</span>
                <span>)" +
               commit_link + R"(</span>
            </div>
        </div>
        
        <div class="divider"></div>
        
        <p class="description">
            Originated and enhanced from: 
            <a href="https://github.com/asdlokj1qpi233/subconverter" target="_blank">subconverter v0.9.9</a>
        </p>
        
        <p class="description">
            Modified and evolved by: 
            <a href="https://github.com/Aethersailor" target="_blank">Aethersailor</a>
        </p>
        
        <div class="footer">
            Source Code: <a href="https://github.com/Aethersailor/SubConverter-Extended" target="_blank">GitHub</a> • License: <a href="https://www.gnu.org/licenses/gpl-3.0.html" target="_blank">GPL-3.0</a>
        </div>
    </div>
</body>
</html>)";
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
  listener_args args = {global.listenAddress,   global.listenPort,
                        global.maxPendingConns, global.maxConcurThreads,
                        cron_tick_caller,       200};
  // std::cout<<"Serving HTTP @
  // http://"<<listen_address<<":"<<listen_port<<std::endl;
  writeLog(0,
           "Startup completed. Serving HTTP @ http://" + global.listenAddress +
               ":" + std::to_string(global.listenPort),
           LOG_LEVEL_INFO);
  webServer.start_web_server_multi(&args);

#ifdef _WIN32
  WSACleanup();
#endif // _WIN32
  return 0;
}
