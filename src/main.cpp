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
        std::string build_date = BUILD_DATE;
        auto format_build_date = [](const std::string &value) -> std::string {
          if (value.empty())
            return "unknown";
          size_t split_pos = value.find('T');
          if (split_pos == std::string::npos)
            split_pos = value.find(' ');
          std::string candidate = split_pos == std::string::npos
                                      ? value
                                      : value.substr(0, split_pos);
          if (candidate.size() >= 10 && candidate[4] == '-' &&
              candidate[7] == '-' && candidate[0] >= '0' &&
              candidate[0] <= '9' && candidate[1] >= '0' &&
              candidate[1] <= '9' && candidate[2] >= '0' &&
              candidate[2] <= '9' && candidate[3] >= '0' &&
              candidate[3] <= '9' && candidate[5] >= '0' &&
              candidate[5] <= '9' && candidate[6] >= '0' &&
              candidate[6] <= '9' && candidate[8] >= '0' &&
              candidate[8] <= '9' && candidate[9] >= '0' &&
              candidate[9] <= '9') {
            return candidate.substr(0, 10);
          }
          return candidate;
        };
        std::string build_date_display = format_build_date(build_date);
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
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            /* Light Theme - 精准调优 */
            --bg-gradient: linear-gradient(135deg, #f5f7fa 0%, #e4e7eb 100%);
            --container-bg: rgba(255, 255, 255, 0.85);
            --container-border: rgba(255, 255, 255, 0.4);
            --shadow: 0 12px 40px rgba(31, 38, 135, 0.08);
            --text-primary: #1a202c;
            --text-secondary: #4a5568;
            --divider-bg: linear-gradient(90deg, transparent, rgba(0,0,0,0.08), transparent);
            --info-block-bg: rgba(0, 0, 0, 0.02);
            --info-block-border: rgba(0,0,0,0.04);
            --link-color: #3182ce;
            --link-hover: #2b6cb0;
            --header-gradient: linear-gradient(135deg, #1a202c 0%, #4a5568 100%);
        }

        @media (prefers-color-scheme: dark) {
            :root {
                /* Dark Theme - 极黑质感 */
                --bg-gradient: radial-gradient(circle at 50% 50%, #1a1b1e 0%, #000000 100%);
                --container-bg: rgba(28, 28, 30, 0.7);
                --container-border: rgba(255, 255, 255, 0.1);
                --shadow: 0 20px 50px rgba(0, 0, 0, 0.6);
                --text-primary: #f8f9fa;
                --text-secondary: #a0aec0;
                --divider-bg: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
                --info-block-bg: rgba(255, 255, 255, 0.04);
                --info-block-border: rgba(255,255,255,0.06);
                --link-color: #63b3ed;
                --link-hover: #90cdf4;
                --header-gradient: linear-gradient(135deg, #ffffff 0%, #90cdf4 100%);
            }
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Outfit', system-ui, -apple-system, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: var(--bg-gradient);
            background-attachment: fixed;
            padding: 24px;
            color: var(--text-primary);
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }
        
        .container {
            background: var(--container-bg);
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
            border-radius: 32px;
            padding: 40px 50px;
            max-width: 800px;
            width: 100%;
            box-shadow: var(--shadow);
            border: 1px solid var(--container-border);
            position: relative;
            animation: fadeIn 1s cubic-bezier(0.16, 1, 0.3, 1);
        }

        .container::after {
            content: "";
            position: absolute;
            inset: 0;
            border-radius: 32px;
            padding: 1px;
            background: linear-gradient(135deg, rgba(255,255,255,0.2), transparent, rgba(255,255,255,0.05));
            -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
            mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
            -webkit-mask-composite: xor;
            mask-composite: exclude;
            pointer-events: none;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        header {
            text-align: center;
            margin-bottom: 32px;
        }

        h1 {
            background: var(--header-gradient);
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
            font-size: 3em;
            margin-bottom: 8px;
            font-weight: 700;
            letter-spacing: -0.04em;
            line-height: 1.05;
        }
        
        .subtitle {
            color: var(--text-secondary);
            font-size: 1.05em;
            font-weight: 500;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            opacity: 0.6;
        }
        
        .section {
            margin: 20px 0;
            padding: 20px 25px;
            background: var(--info-block-bg);
            border-radius: 20px;
            border: 1px solid var(--info-block-border);
        }

        .section-title {
            font-size: 0.9em;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 8px;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            opacity: 0.8;
        }

        .description {
            color: var(--text-secondary);
            font-size: 1em;
            line-height: 1.8;
            margin-bottom: 12px;
            padding-left: 1.5em;
            position: relative;
        }

        .description::before {
            content: "•";
            position: absolute;
            left: 0.2em;
            color: var(--link-color);
            font-weight: bold;
        }

        .info-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin: 20px 0;
        }
        
        .info-card {
            background: var(--info-block-bg);
            border: 1px solid var(--info-block-border);
            border-radius: 16px;
            padding: 20px;
            text-align: center;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .info-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.05);
        }

        .info-card .info-label {
            display: block;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.1em;
            color: var(--text-secondary);
            margin-bottom: 8px;
            font-weight: 600;
        }
        
        .info-card .info-value {
            font-size: 1.1rem;
            font-weight: 700;
            color: var(--text-primary);
            word-break: break-all;
        }
        
        .info-card .info-value a {
            font-family: 'Outfit', monospace;
            font-weight: 600;
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
        }
        
        .footer {
            margin-top: 30px;
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.85em;
            opacity: 0.6;
        }
        
        .footer a {
            font-weight: 400;
        }
        
        @media (max-width: 600px) {
            .container { padding: 30px 20px; }
            h1 { font-size: 2.2em; }
            .info-grid { grid-template-columns: 1fr; gap: 12px; }
            .section { padding: 15px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>SubConverter-Extended</h1>
            <p class="subtitle">A Modern Evolution of Subconverter</p>
        </header>

        <div class="info-grid">
            <div class="info-card">
                <span class="info-label">Version</span>
                <div class="info-value">)" VERSION R"(</div>
            </div>
            <div class="info-card">
                <span class="info-label">Build</span>
                <div class="info-value">)" +
               commit_link + R"(</div>
            </div>
            <div class="info-card">
                <span class="info-label">Build Date</span>
                <div class="info-value">)" +
               build_date_display + R"(</div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">✨ Overview</div>
            <p class="description">An enhanced implementation of subconverter, aligned with the <a href="https://github.com/MetaCubeX/mihomo/tree/Meta" target="_blank">Mihomo</a> <a href="https://wiki.metacubex.one/config/" target="_blank">configuration</a>.</p>
            <p class="description">Primarily for <a href="https://github.com/vernesong/OpenClash" target="_blank">OpenClash</a>, while compatible with other Clash clients.</p>
            <p class="description">Dedicated companion backend for the <a href="https://github.com/Aethersailor/Custom_OpenClash_Rules" target="_blank">Custom_OpenClash_Rules</a> project.</p>
        </div>

        <div class="section">
            <div class="section-title">🚀 Lineage</div>
            <p class="description">Originated and enhanced from: <a href="https://github.com/asdlokj1qpi233/subconverter" target="_blank">subconverter</a></p>
            <p class="description">Modified and evolved by: <a href="https://github.com/Aethersailor" target="_blank">Aethersailor</a></p>
        </div>

        <div class="footer">
            Source Code: <a href="https://github.com/Aethersailor/SubConverter-Extended" target="_blank">GitHub</a> • 
            License: <a href="https://www.gnu.org/licenses/gpl-3.0.html" target="_blank">GPL-3.0</a>
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
