#include <algorithm>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "handler/settings.h"
#include "handler/settings_view.h"
#include "handler/webget.h"
#include "nodemanip.h"
#include "parser/config/proxy.h"
#include "parser/infoparser.h"
#include "parser/mihomo_bridge.h"
#include "parser/mihomo_scheme_utils.h"
#include "parser/subparser.h"
#include "script/script_quickjs.h"
#include "subexport.h"
#include "utils/file_extra.h"
#include "utils/logger.h"
#include "utils/map_extra.h"
#include "utils/network.h"
#include "parser/config/proxy_utils.h"
#include "utils/regexp.h"
#include "utils/redact.h"
#include "utils/string.h"
#include "utils/urlencode.h"

extern Settings global;

bool applyMatcher(const std::string &rule, std::string &real_rule,
                  const Proxy &node);

int explodeConf(const std::string &filepath, std::vector<Proxy> &nodes) {
  return explodeConfContent(fileGet(filepath), nodes);
}

void copyNodes(std::vector<Proxy> &source, std::vector<Proxy> &dest) {
  std::move(source.begin(), source.end(), std::back_inserter(dest));
}

static void appendMihomoNodes(std::vector<mihomo::ProxyNode> &source,
                              std::vector<Proxy> &nodes) {
  nodes.reserve(nodes.size() + source.size());
  for (auto &mnode : source) {
    Proxy node;
    node.Remark = std::move(mnode.name);
    node.Type = getProxyTypeFromString(mnode.type);
    node.Hostname = std::move(mnode.server);
    node.Port = mnode.port;
    node.CanonicalProxyJson = std::move(mnode.canonical_json);

    nlohmann::json canonical;
    try {
      canonical = nlohmann::json::parse(node.CanonicalProxyJson);
    } catch (const nlohmann::json::exception &) {
      continue;
    }

    const bool is_vless = node.Type == ProxyType::VLESS;
    const bool is_hysteria2 = node.Type == ProxyType::Hysteria2;

    for (auto it = canonical.begin(); it != canonical.end(); ++it) {
      const std::string &key = it.key();
      if (!it->is_string() && !it->is_boolean() && !it->is_number())
        continue;

      std::string value;
      if (it->is_string())
        value = it->get<std::string>();
      else if (it->is_boolean())
        value = it->get<bool>() ? "true" : "false";
      else
        value = it->dump();

      if (key == "password")
        node.Password = value;
      else if (key == "cipher" || key == "method")
        node.EncryptMethod = value;
      else if (key == "uuid")
        node.UserId = value;
      else if (key == "alterId")
        node.AlterId = std::stoi(value);
      else if (key == "udp")
        node.UDP = (value == "true");
      else if (is_hysteria2 && key == "skip-cert-verify")
        node.AllowInsecure = (value == "true");
      else if (key == "tls")
        node.TLSStr = is_vless && value == "true" ? "tls" : value;
      else if (key == "sni" || key == "servername")
        node.ServerName = value;
      else if (key == "network")
        node.TransferProtocol = value;
      else if (is_vless && key == "flow")
        node.Flow = value;
      else if (is_vless &&
               (key == "client-fingerprint" || key == "fingerprint"))
        node.Fingerprint = value;
      else if (is_vless && key == "packet-encoding")
        node.PacketEncoding = value;
      else if (is_hysteria2 && key == "obfs")
        node.OBFSParam = value;
      else if (is_hysteria2 && key == "obfs-password")
        node.OBFSPassword = value;
      else if (is_hysteria2 && key == "ports")
        node.Ports = value;
    }

    auto parse_object = [&](const std::string &key) {
      auto value = canonical.find(key);
      if (value == canonical.end() || !value->is_object())
        return nlohmann::json();
      return *value;
    };

    nlohmann::json ws_options = parse_object("ws-opts");
    if (is_vless && !ws_options.empty()) {
      node.Path = ws_options.value("path", std::string());
      const nlohmann::json headers = ws_options.value(
          "headers", nlohmann::json::object());
      if (headers.is_object()) {
        node.Host = headers.value(
            "Host", headers.value("host", std::string()));
        node.Edge = headers.value(
            "Edge", headers.value("edge", std::string()));
      }
    }

    nlohmann::json grpc_options = parse_object("grpc-opts");
    if (is_vless && !grpc_options.empty()) {
      node.GRPCServiceName =
          grpc_options.value("grpc-service-name", std::string());
      node.Path = node.GRPCServiceName;
      node.GRPCMode = grpc_options.value("grpc-mode", std::string());
    }

    nlohmann::json reality_options = parse_object("reality-opts");
    if (is_vless && !reality_options.empty()) {
      node.PublicKey = reality_options.value("public-key", std::string());
      node.ShortId = reality_options.value("short-id", std::string());
    }

    auto alpn = canonical.find("alpn");
    if (is_vless && alpn != canonical.end()) {
      if (alpn->is_array()) {
        for (const auto &value : *alpn) {
          if (value.is_string())
            node.AlpnList.emplace_back(value.get<std::string>());
        }
      } else if (alpn->is_string()) {
        node.AlpnList.emplace_back(alpn->get<std::string>());
      }
    }

    nodes.emplace_back(std::move(node));
  }
}

static bool isBrowserUA(const std::string &ua) {
  static const std::vector<std::string> browser_keywords = {
      "Mozilla/",        "AppleWebKit/", "Chrome/",
      "Safari/",         "Firefox/",     "Edg/",
      "Edge/",           "OPR/",         "Opera/",
      "Brave/",          "Vivaldi/",     "YaBrowser/",
      "SamsungBrowser/", "UCBrowser/",   "Maxthon/",
      "QQBrowser/",      "Sogou/",       "360SE",
      "360EE",           "Whale/",       "MSIE "};

  for (const auto &keyword : browser_keywords) {
    if (ua.find(keyword) != std::string::npos)
      return true;
  }
  return false;
}

int addNodes(std::string link, std::vector<Proxy> &allNodes, int groupID,
             parse_settings &parse_set) {
  ProxyPolicy &proxy = *parse_set.proxy;
  std::string &subInfo = *parse_set.sub_info;
  string_array &exclude_remarks = *parse_set.exclude_remarks;
  string_array &include_remarks = *parse_set.include_remarks;
  RegexMatchConfigs &stream_rules = *parse_set.stream_rules;
  RegexMatchConfigs &time_rules = *parse_set.time_rules;
  string_icase_map *request_headers = parse_set.request_header;
  bool &authorized = parse_set.authorized;

  ConfType linkType = ConfType::Unknow;
  std::vector<Proxy> nodes;
  Proxy node;
  std::string strSub, extra_headers, custom_group;

  // TODO: replace with startsWith if appropriate
  link = replaceAllDistinct(link, "\"", "");

  /// script:filepath,arg1,arg2,...
  if (authorized)
    script_safe_runner(
        parse_set.js_runtime, parse_set.js_context,
        [&](qjs::Context &ctx) {
          if (startsWith(link, "script:")) /// process subscription with script
          {
            writeLog(LOG_LEVEL_INFO, "发现脚本链接，开始执行...");
            string_array args = split(link.substr(7), ",");
            if (args.size() >= 1) {
              std::string script = fileGet(args[0], false);
              try {
                ctx.eval(script);
                args.erase(args.begin()); /// remove script path
                auto parse = (std::function<std::string(const std::string &,
                                                        const string_array &)>)
                                 ctx.eval("parse");
                switch (args.size()) {
                case 0:
                  link = parse("", string_array());
                  break;
                case 1:
                  link = parse(args[0], string_array());
                  break;
                default: {
                  std::string first = args[0];
                  args.erase(args.begin());
                  link = parse(first, args);
                  break;
                }
                }
              } catch (qjs::exception) {
                script_print_stack(ctx);
              }
            }
          }
        },
        effectiveSettings().scriptCleanContext);
  /*
  duk_context *ctx = duktape_init();
  defer(duk_destroy_heap(ctx);)
  duktape_peval(ctx, script);
  duk_get_global_string(ctx, "parse");
  for(size_t i = 1; i < args.size(); i++)
      duk_push_string(ctx, trim(args[i]).c_str());
  if(duk_pcall(ctx, args.size() - 1) == 0)
      link = duktape_get_res_str(ctx);
  else
  {
      writeLog(LOG_LEVEL_ERROR, "执行脚本时发生错误：\n" +
  duktape_get_err_stack(ctx)); duk_pop(ctx); /// pop err
  }
  */

  /// tag:group_name,link
  if (startsWith(link, "tag:")) {
    string_size pos = link.find(",");
    if (pos != link.npos) {
      custom_group = link.substr(4, pos - 4);
      link.erase(0, pos + 1);
    }
  }

  if (link == "nullnode") {
    node.GroupId = 0;
    writeLog(LOG_LEVEL_VERBOSE, "正在添加节点占位符...");
    allNodes.emplace_back(std::move(node));
    return 0;
  }

  const bool use_mihomo_parser =
      parse_set.parser_mode == NodeParserMode::MihomoOnly;
  auto recordParserInvocation = [&]() {
    if (parse_set.parser_stats)
      parse_set.parser_stats->invocations++;
  };
  auto recordParserFailure = [&]() {
    if (parse_set.parser_stats)
      parse_set.parser_stats->failures++;
  };
  const bool isMihomoScheme =
      use_mihomo_parser && mihomo::isSupportedSchemeLink(link);

  // Handle pipe separated links recursively
  if (link.find('|') != std::string::npos && (isLink(link) || isMihomoScheme)) {
    std::vector<std::string> links = split(link, "|");
    for (const auto &l : links) {
      if (l.empty())
        continue;
      addNodes(l, allNodes, groupID, parse_set);
    }
    return 0;
  }

  writeLog(LOG_LEVEL_VERBOSE, "已收到链接。");
  if (parse_set.force_direct_link)
    linkType = ConfType::HTTP;
  else if (!use_mihomo_parser && isLegacyHttpProxyUri(link))
    linkType = ConfType::HTTP;
  else if (startsWith(link, "https://t.me/socks") || startsWith(link, "tg://socks"))
    linkType = ConfType::SOCKS;
  else if (startsWith(link, "https://t.me/http") ||
           startsWith(link, "tg://http"))
    linkType = ConfType::HTTP;
  else if (isLink(link) || startsWith(link, "surge:///install-config") ||
           isMihomoScheme) // Mihomo 节点链接走 SUB case，由新分流逻辑区分
    linkType = ConfType::SUB;
  else if (startsWith(link, "Netch://"))
    linkType = ConfType::Netch;
  else if (fileExist(link))
    linkType = ConfType::Local;

  switch (linkType) {
  case ConfType::SUB: {
    // Check for multiple links separated by pipe '|'
    if (link.find('|') != std::string::npos) {
      std::vector<std::string> links = split(link, "|");
      for (const auto &l : links) {
        if (l.empty())
          continue;
        // Recursive call or simplified processing for each link
        // Since we are already inside addNodes, and we know these are likely
        // links it's safest to treat them as individual subscriptions/nodes
        addNodes(l, allNodes, groupID, parse_set);
      }
      return 0; // Handled
    }

    // ========== 智能订阅/节点链接分流逻辑 ==========
    // 目标：准确区分订阅链接和节点链接，支持多种格式

    bool isSubscription = false; // 订阅链接标志
    bool isNodeLink = false;     // 节点链接标志

    // Surge install-config links wrap a remote subscription URL.
    if (startsWith(link, "surge:///install-config")) {
      isSubscription = true;
    }
    // 规则 1: HTTP(S) 开头的链接
    else if (mihomo::isHttpSchemeLink(link)) {
      size_t protocolEnd = link.find("://") + 3;
      size_t pathStart = link.find("/", protocolEnd);
      size_t queryStart = link.find("?", protocolEnd);

      // 有查询参数 = 订阅（非常明确）
      // 例如: https://api.com/sub?token=xxx
      if (queryStart != link.npos) {
        isSubscription = true;
      }
      // 有实际路径（不只是单个 /）= 订阅
      // 例如: https://api.com/api/v1/sub
      else if (pathStart != link.npos) {
        std::string path = link.substr(pathStart);
        if (path.length() > 1) { // 路径长度 > 1（不只是尾部 /）
          isSubscription = true;
        } else {
          // 只有单个 "/" = 可能是 HTTP 代理节点
          // 例如: http://proxy.com:8080/
          isNodeLink = true;
        }
      }
      // 无路径无参数 = HTTP 代理节点
      // 例如: http://proxy.com:8080
      else {
        isNodeLink = true;
      }
    }
    // 规则 2: 无协议头（无 ://）= 订阅
    // 用户可能省略 http:// 或 https://
    // 例如: api.com/sub, example.com/clash?token=xxx, sub.domain.com
    else if (link.find("://") == link.npos) {
      isSubscription = true;
      writeLog(LOG_LEVEL_VERBOSE,
               "检测到无协议头链接，按订阅处理：" +
                   summarizeUrlForLog(link));
    }
    // 规则 3: 在 SUPPORTED_SCHEMES 中 = 节点链接
    // 例如: trojan://..., vmess://..., hysteria2://...
    else {
      isNodeLink = mihomo::isSupportedSchemeLink(link);
      // 规则 4: 其他未知协议 = 节点链接（交给当前目标的解析器尝试）
      // 例如: newproto://..., unknown://...
      // 解析器会拒绝自己不支持的协议。
      if (!isNodeLink) {
        isNodeLink = true;
        writeLog(LOG_LEVEL_VERBOSE,
                 "检测到未知协议，交给当前目标的节点解析器处理：" +
                     summarizeUrlForLog(link));
      }
    }

    // Clash proxy-provider sources are intercepted by the caller. Any
    // subscription URL that reaches addNodes must be expanded into nodes.
    if (isSubscription) {
      writeLog(LOG_LEVEL_VERBOSE, "正在下载订阅数据...");
      if (startsWith(link, "surge:///install-config"))
        link = urlDecode(getUrlArg(link, "url"));

      // Replace browser UA with clash.meta to avoid subscription-side blocks.
      if (request_headers) {
        auto ua_it = request_headers->find("User-Agent");
        if (ua_it != request_headers->end() && isBrowserUA(ua_it->second)) {
          writeLog(LOG_LEVEL_VERBOSE,
                   "检测到浏览器 UA，已替换为 clash.meta UA 以避免被拦截");
          ua_it->second = "clash.meta";
        }
      }

      strSub = webGet(link, proxy, effectiveSettings().cacheSubscription,
                      &extra_headers, request_headers, parse_set.fetch_context);
    } else if (isNodeLink) {
      // 节点链接不需要下载，直接交给当前目标的解析器。
      writeLog(LOG_LEVEL_VERBOSE, "检测到节点链接，正在直接解析...");
      strSub = link; // 直接使用链接本身作为解析内容
    } else {
      // 其他情况（surge config link 等）：保持原有逻辑
      writeLog(LOG_LEVEL_VERBOSE, "正在下载订阅数据...");
      if (startsWith(link, "surge:///install-config")) // surge config link
        link = urlDecode(getUrlArg(link, "url"));

      // Replace browser UA with clash.meta
      if (request_headers) {
        auto ua_it = request_headers->find("User-Agent");
        if (ua_it != request_headers->end() && isBrowserUA(ua_it->second)) {
          writeLog(LOG_LEVEL_VERBOSE,
                   "检测到浏览器 UA，已替换为 clash.meta UA 以避免被拦截");
          ua_it->second = "clash.meta";
        }
      }

      strSub = webGet(link, proxy, effectiveSettings().cacheSubscription,
                      &extra_headers, request_headers, parse_set.fetch_context);
    }
    /*
    if(strSub.size() == 0)
    {
        //try to get it again with system proxy
        writeLog(LOG_LEVEL_WARNING, "无法直接下载订阅，正在使用
    system proxy."); strProxy = getSystemProxy(); if(strProxy != "")
        {
            strSub = webGet(link, strProxy);
        }
        else
            writeLog(LOG_LEVEL_WARNING, "未设置系统代理，跳过。");
    }
    */
    if (!strSub.empty()) {
      if (use_mihomo_parser) {
        recordParserInvocation();
        writeLog(LOG_LEVEL_VERBOSE,
                 "NODE_PARSER_INVOKE parser=mihomo branch=sub");
#ifdef USE_MIHOMO_PARSER
        try {
          auto mihomo_nodes = mihomo::parseSubscription(strSub);
          appendMihomoNodes(mihomo_nodes, nodes);
        } catch (const std::exception &e) {
          recordParserFailure();
          writeLog(LOG_LEVEL_ERROR,
                   "NODE_PARSER_FAILED parser=mihomo branch=sub detail=" +
                       summarizeSensitiveTextForLog(e.what()));
          return -1;
        }
        if (nodes.empty()) {
          recordParserFailure();
          writeLog(LOG_LEVEL_ERROR,
                   "NODE_PARSER_FAILED parser=mihomo branch=sub reason=no_nodes");
          return -1;
        }
        writeLog(LOG_LEVEL_VERBOSE,
                 "Mihomo 解析器成功解析 " + std::to_string(nodes.size()) +
                     " 个节点。");
#else
        recordParserFailure();
        writeLog(LOG_LEVEL_ERROR,
                 "NODE_PARSER_FAILED parser=mihomo branch=sub reason=unavailable");
        return -1;
#endif
      } else {
        recordParserInvocation();
        writeLog(LOG_LEVEL_VERBOSE,
                 "NODE_PARSER_INVOKE parser=legacy branch=sub");
        if (explodeConfContent(strSub, nodes) == 0) {
          recordParserFailure();
          writeLog(LOG_LEVEL_ERROR,
                   "NODE_PARSER_FAILED parser=legacy branch=sub reason=no_nodes");
          return -1;
        }
      }

      if (startsWith(strSub, "ssd://")) {
        getSubInfoFromSSD(strSub, subInfo);
      } else {
        if (!getSubInfoFromHeader(extra_headers, subInfo))
          getSubInfoFromNodes(nodes, stream_rules, time_rules, subInfo);
      }
      writeLog(LOG_LEVEL_VERBOSE,
               "过滤前节点数：" + std::to_string(nodes.size()));
      filterNodes(nodes, exclude_remarks, include_remarks, groupID);
      writeLog(LOG_LEVEL_VERBOSE,
               "过滤后节点数：" + std::to_string(nodes.size()));
      for (Proxy &x : nodes) {
        x.GroupId = groupID;
        if (custom_group.size())
          x.Group = custom_group;
      }
      writeLog(LOG_LEVEL_VERBOSE,
               "正在复制 " + std::to_string(nodes.size()) +
                   " 个节点到总节点列表");
      copyNodes(nodes, allNodes);
      writeLog(LOG_LEVEL_VERBOSE,
               "总节点列表当前共有 " + std::to_string(allNodes.size()) +
                   " 个节点");
    } else {
      writeLog(LOG_LEVEL_ERROR,
               "NODE_SOURCE_FAILED branch=sub reason=fetch_empty");
      return -1;
    }
    break;
  }
  case ConfType::Local:
    if (!authorized)
      return -1;
    recordParserInvocation();
    writeLog(LOG_LEVEL_VERBOSE,
             "NODE_PARSER_INVOKE parser=legacy branch=local");
    writeLog(LOG_LEVEL_VERBOSE, "正在解析配置文件数据...");
    if (explodeConf(link, nodes) == 0) {
      recordParserFailure();
      writeLog(LOG_LEVEL_ERROR,
               "NODE_PARSER_FAILED parser=legacy branch=local reason=no_nodes");
      return -1;
    }
    if (startsWith(strSub, "ssd://")) {
      getSubInfoFromSSD(strSub, subInfo);
    } else {
      getSubInfoFromNodes(nodes, stream_rules, time_rules, subInfo);
    }
    filterNodes(nodes, exclude_remarks, include_remarks, groupID);
    for (Proxy &x : nodes) {
      x.GroupId = groupID;
      if (!custom_group.empty())
        x.Group = custom_group;
    }
    copyNodes(nodes, allNodes);
    break;
  default:
    if (use_mihomo_parser) {
      recordParserInvocation();
      writeLog(LOG_LEVEL_VERBOSE,
               "NODE_PARSER_INVOKE parser=mihomo branch=direct");
      strSub = link;
#ifdef USE_MIHOMO_PARSER
      try {
        auto mihomo_nodes = mihomo::parseSubscription(strSub);
        std::vector<Proxy> parsed_nodes;
        appendMihomoNodes(mihomo_nodes, parsed_nodes);
        if (parsed_nodes.empty()) {
          recordParserFailure();
          writeLog(LOG_LEVEL_ERROR,
                   "NODE_PARSER_FAILED parser=mihomo branch=direct reason=no_nodes");
          return -1;
        }
        for (auto &node : parsed_nodes) {
          node.GroupId = groupID;
          if (!custom_group.empty())
            node.Group = custom_group;
          allNodes.emplace_back(std::move(node));
        }
      } catch (const std::exception &e) {
        recordParserFailure();
        writeLog(LOG_LEVEL_ERROR,
                 "NODE_PARSER_FAILED parser=mihomo branch=direct detail=" +
                     summarizeSensitiveTextForLog(e.what()));
        return -1;
      }
#else
      recordParserFailure();
      writeLog(LOG_LEVEL_ERROR,
               "NODE_PARSER_FAILED parser=mihomo branch=direct reason=unavailable");
      return -1;
#endif
    } else {
      recordParserInvocation();
      writeLog(LOG_LEVEL_VERBOSE,
               "NODE_PARSER_INVOKE parser=legacy branch=direct");
      if (startsWith(link, "mierus://")) {
        std::vector<Proxy> parsed_nodes;
        explodeMierusNodes(link, parsed_nodes);
        if (parsed_nodes.empty()) {
          recordParserFailure();
          writeLog(LOG_LEVEL_ERROR,
                   "NODE_PARSER_FAILED parser=legacy branch=direct reason=no_nodes");
          return -1;
        }
        for (auto &parsed_node : parsed_nodes) {
          parsed_node.GroupId = groupID;
          if (!custom_group.empty())
            parsed_node.Group = custom_group;
          allNodes.emplace_back(std::move(parsed_node));
        }
        return 0;
      }
      explode(link, node);
      if (node.Type == ProxyType::Unknown) {
        recordParserFailure();
        writeLog(LOG_LEVEL_ERROR,
                 "NODE_PARSER_FAILED parser=legacy branch=direct reason=no_nodes");
        return -1;
      }
      node.GroupId = groupID;
      if (!custom_group.empty())
        node.Group = custom_group;
      allNodes.emplace_back(std::move(node));
    }
  }
  return 0;
}

bool chkIgnore(const Proxy &node, string_array &exclude_remarks,
               string_array &include_remarks) {
  bool excluded = false, included = false;
  // std::string remarks = UTF8ToACP(node.remarks);
  // std::string remarks = node.remarks;
  // writeLog(LOG_LEVEL_VERBOSE, "正在匹配排除规则...");
  excluded = std::any_of(exclude_remarks.cbegin(), exclude_remarks.cend(),
                         [&node](const auto &x) {
                           std::string real_rule;
                           if (applyMatcher(x, real_rule, node)) {
                             if (real_rule.empty())
                               return true;
                             return regFind(node.Remark, real_rule);
                           } else
                             return false;
                         });
  if (include_remarks.size() != 0) {
    // writeLog(LOG_LEVEL_VERBOSE, "正在匹配包含规则...");
    included = std::any_of(include_remarks.cbegin(), include_remarks.cend(),
                           [&node](const auto &x) {
                             std::string real_rule;
                             if (applyMatcher(x, real_rule, node)) {
                               if (real_rule.empty())
                                 return true;
                               return regFind(node.Remark, real_rule);
                             } else
                               return false;
                           });
  } else {
    included = true;
  }

  return excluded || !included;
}

void filterNodes(std::vector<Proxy> &nodes, string_array &exclude_remarks,
                 string_array &include_remarks, int groupID) {
  const size_t input_count = nodes.size();
  size_t ignored_count = 0;
  int node_index = 0;
  auto write_iter = nodes.begin();
  for (auto iter = nodes.begin(); iter != nodes.end(); ++iter) {
    if (chkIgnore(*iter, exclude_remarks, include_remarks)) {
      ignored_count++;
      continue;
    }

    iter->Id = node_index;
    iter->GroupId = groupID;
    ++node_index;
    if (write_iter != iter)
      *write_iter = std::move(*iter);
    ++write_iter;
  }
  nodes.erase(write_iter, nodes.end());
  writeLog(LOG_LEVEL_VERBOSE,
           "NODE_FILTER_RESULT input_count=" + std::to_string(input_count) +
               " kept_count=" + std::to_string(nodes.size()) +
               " ignored_count=" + std::to_string(ignored_count));
  /*
  std::vector<std::unique_ptr<pcre2_code, decltype(&pcre2_code_free)>>
  exclude_patterns, include_patterns;
  std::vector<std::unique_ptr<pcre2_match_data,
  decltype(&pcre2_match_data_free)>> exclude_match_data, include_match_data;
  unsigned int i = 0;
  PCRE2_SIZE erroroffset;
  int errornumber, rc;

  for(i = 0; i < exclude_remarks.size(); i++)
  {
      std::unique_ptr<pcre2_code, decltype(&pcre2_code_free)>
  pattern(pcre2_compile(reinterpret_cast<const unsigned
  char*>(exclude_remarks[i].c_str()), exclude_remarks[i].size(), PCRE2_UTF |
  PCRE2_MULTILINE | PCRE2_ALT_BSUX, &errornumber, &erroroffset, NULL),
  &pcre2_code_free); if(!pattern) return;
      exclude_patterns.emplace_back(std::move(pattern));
      pcre2_jit_compile(exclude_patterns[i].get(), 0);
      std::unique_ptr<pcre2_match_data, decltype(&pcre2_match_data_free)>
  match_data(pcre2_match_data_create_from_pattern(exclude_patterns[i].get(),
  NULL), &pcre2_match_data_free);
      exclude_match_data.emplace_back(std::move(match_data));
  }
  for(i = 0; i < include_remarks.size(); i++)
  {
      std::unique_ptr<pcre2_code, decltype(&pcre2_code_free)>
  pattern(pcre2_compile(reinterpret_cast<const unsigned
  char*>(include_remarks[i].c_str()), include_remarks[i].size(), PCRE2_UTF |
  PCRE2_MULTILINE | PCRE2_ALT_BSUX, &errornumber, &erroroffset, NULL),
  &pcre2_code_free); if(!pattern) return;
      include_patterns.emplace_back(std::move(pattern));
      pcre2_jit_compile(include_patterns[i].get(), 0);
      std::unique_ptr<pcre2_match_data, decltype(&pcre2_match_data_free)>
  match_data(pcre2_match_data_create_from_pattern(include_patterns[i].get(),
  NULL), &pcre2_match_data_free);
      include_match_data.emplace_back(std::move(match_data));
  }
  writeLog(LOG_LEVEL_VERBOSE, "过滤开始。");
  while(iter != nodes.end())
  {
      bool excluded = false, included = false;
      for(i = 0; i < exclude_patterns.size(); i++)
      {
          rc = pcre2_match(exclude_patterns[i].get(), reinterpret_cast<const
  unsigned char*>(iter->remarks.c_str()), iter->remarks.size(), 0, 0,
  exclude_match_data[i].get(), NULL); if (rc < 0)
          {
              switch(rc)
              {
              case PCRE2_ERROR_NOMATCH:
                  break;
              default:
                  return;
              }
          }
          else
              excluded = true;
      }
      if(include_patterns.size() > 0)
          for(i = 0; i < include_patterns.size(); i++)
          {
              rc = pcre2_match(include_patterns[i].get(),
  reinterpret_cast<const unsigned char*>(iter->remarks.c_str()),
  iter->remarks.size(), 0, 0, include_match_data[i].get(), NULL); if (rc < 0)
              {
                  switch(rc)
                  {
                  case PCRE2_ERROR_NOMATCH:
                      break;
                  default:
                      return;
                  }
              }
              else
                  included = true;
          }
      else
          included = true;
      if(excluded || !included)
      {
          writeLog(LOG_LEVEL_VERBOSE, "节点 " + iter->group + " - " +
  iter->remarks
  + " 已被忽略，不会添加。"); nodes.erase(iter);
      }
      else
      {
          writeLog(LOG_LEVEL_VERBOSE, "节点 " + iter->group + " - " +
  iter->remarks
  + " 已添加。"); iter->id = node_index; iter->groupID = groupID;
          ++node_index;
          ++iter;
      }
  }
  */
  writeLog(LOG_LEVEL_VERBOSE, "过滤完成。");
}

void nodeRename(Proxy &node, const RegexMatchConfigs &rename_array,
                extra_settings &ext) {
  std::string &remark = node.Remark, original_remark = node.Remark,
              returned_remark, real_rule;

  for (const RegexMatchConfig &x : rename_array) {
    if (!x.Script.empty() && ext.authorized) {
      script_safe_runner(
          ext.js_runtime, ext.js_context,
          [&](qjs::Context &ctx) {
            std::string script = x.Script;
            if (startsWith(script, "path:"))
              script = fileGet(script.substr(5), true);
            try {
              ctx.eval(script);
              auto rename =
                  (std::function<std::string(const Proxy &)>)ctx.eval("rename");
              returned_remark = rename(node);
              if (!returned_remark.empty())
                remark = returned_remark;
            } catch (qjs::exception) {
              script_print_stack(ctx);
            }
          },
          effectiveSettings().scriptCleanContext);
      continue;
    }
    if (applyMatcher(x.Match, real_rule, node) && real_rule.size())
      remark = regReplace(remark, real_rule, x.Replace);
  }
  if (remark.empty())
    remark = original_remark;
  return;
}

std::string removeEmoji(const std::string &orig_remark) {
  char emoji_id[2] = {(char)-16, (char)-97};
  std::string remark = orig_remark;
  while (true) {
    if (remark[0] == emoji_id[0] && remark[1] == emoji_id[1])
      remark.erase(0, 4);
    else
      break;
  }
  if (remark.empty())
    return orig_remark;
  return remark;
}

std::string addEmoji(const Proxy &node, const RegexMatchConfigs &emoji_array,
                     extra_settings &ext) {
  std::string real_rule, ret;

  for (const RegexMatchConfig &x : emoji_array) {
    if (!x.Script.empty() && ext.authorized) {
      std::string result;
      script_safe_runner(
          ext.js_runtime, ext.js_context,
          [&](qjs::Context &ctx) {
            std::string script = x.Script;
            if (startsWith(script, "path:"))
              script = fileGet(script.substr(5), true);
            try {
              ctx.eval(script);
              auto getEmoji =
                  (std::function<std::string(const Proxy &)>)ctx.eval(
                      "getEmoji");
              ret = getEmoji(node);
              if (!ret.empty())
                result = ret + " " + node.Remark;
            } catch (qjs::exception) {
              script_print_stack(ctx);
            }
          },
          effectiveSettings().scriptCleanContext);
      if (!result.empty())
        return result;
      continue;
    }
    if (x.Replace.empty())
      continue;
    if (applyMatcher(x.Match, real_rule, node) && real_rule.size() &&
        regFind(node.Remark, real_rule))
      return x.Replace + " " + node.Remark;
  }
  return node.Remark;
}

void preprocessNodes(std::vector<Proxy> &nodes, extra_settings &ext) {
  std::for_each(nodes.begin(), nodes.end(), [&ext](Proxy &x) {
    if (ext.remove_emoji)
      x.Remark = trim(removeEmoji(x.Remark));

    nodeRename(x, ext.rename_array, ext);

    if (ext.add_emoji)
      x.Remark = addEmoji(x, ext.emoji_array, ext);
  });

  if (ext.sort_flag) {
    bool failed = true;
    if (ext.sort_script.size() && ext.authorized) {
      std::string script = ext.sort_script;
      if (startsWith(script, "path:"))
        script = fileGet(script.substr(5), false);
      script_safe_runner(
          ext.js_runtime, ext.js_context,
          [&](qjs::Context &ctx) {
            try {
              ctx.eval(script);
              auto compare =
                  (std::function<int(const Proxy &, const Proxy &)>)ctx.eval(
                      "compare");
              auto comparer = [&](const Proxy &a, const Proxy &b) {
                if (a.Type == ProxyType::Unknown)
                  return 1;
                if (b.Type == ProxyType::Unknown)
                  return 0;
                return compare(a, b);
              };
              std::stable_sort(nodes.begin(), nodes.end(), comparer);
              failed = false;
            } catch (qjs::exception) {
              script_print_stack(ctx);
            }
          },
          effectiveSettings().scriptCleanContext);
    }
    if (failed)
      std::stable_sort(
          nodes.begin(), nodes.end(),
          [](const Proxy &a, const Proxy &b) { return a.Remark < b.Remark; });
  }
}
