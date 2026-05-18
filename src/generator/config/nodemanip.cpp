#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#include "handler/settings.h"
#include "handler/webget.h"
#include "nodemanip.h"
#include "parser/config/proxy.h"
#include "parser/infoparser.h"
#include "parser/mihomo_bridge.h"
#include "parser/subparser.h"
#include "script/script_quickjs.h"
#include "subexport.h"
#include "utils/file_extra.h"
#include "utils/logger.h"
#include "utils/map_extra.h"
#include "utils/network.h"
#ifdef USE_MIHOMO_PARSER
#include "parser/mihomo_schemes.h"
#endif
#include "parser/config/proxy_utils.h"
#include "utils/regexp.h"
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
  std::string &proxy = *parse_set.proxy, &subInfo = *parse_set.sub_info;
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
            writeLog(0, "发现脚本链接，开始执行...", LOG_LEVEL_INFO);
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
        global.scriptCleanContext);
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
      writeLog(0, "执行脚本时发生错误：\n" +
  duktape_get_err_stack(ctx), LOG_LEVEL_ERROR); duk_pop(ctx); /// pop err
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
    writeLog(0, "正在添加节点占位符...");
    allNodes.emplace_back(std::move(node));
    return 0;
  }

  bool isMihomoScheme = false;
#ifdef USE_MIHOMO_PARSER
  for (const auto &scheme : mihomo::SUPPORTED_SCHEMES) {
    if (startsWith(link, scheme + "://")) {
      isMihomoScheme = true;
      break;
    }
  }
#endif

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

  writeLog(LOG_TYPE_INFO, "已收到链接。");
  if (startsWith(link, "https://t.me/socks") || startsWith(link, "tg://socks"))
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

    // 规则 1: HTTP(S) 开头的链接
    if (startsWith(link, "http://") || startsWith(link, "https://")) {
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
      writeLog(LOG_TYPE_INFO,
               "检测到无协议头链接，按订阅处理：" +
                   link);
    }
    // 规则 3: 在 SUPPORTED_SCHEMES 中 = 节点链接
    // 例如: trojan://..., vmess://..., hysteria2://...
    else {
#ifdef USE_MIHOMO_PARSER
      for (const auto &scheme : mihomo::SUPPORTED_SCHEMES) {
        if (startsWith(link, scheme + "://")) {
          isNodeLink = true;
          break;
        }
      }
#endif
      // 规则 4: 其他未知协议 = 节点链接（喂给 Mihomo 尝试）
      // 例如: newproto://..., unknown://...
      // 让 Mihomo 的静默失败机制过滤无效链接
      if (!isNodeLink) {
        isNodeLink = true;
        writeLog(LOG_TYPE_INFO,
                 "检测到未知协议，交给 Mihomo 解析器处理：" +
                     link);
      }
    }

    // 处理订阅链接：跳过下载，交给 proxy-provider
    if (isSubscription) {
      writeLog(LOG_TYPE_INFO, "检测到订阅 URL，跳过下载（将作为 "
                              "proxy-provider 使用）：" +
                                  link);
      return 0; // 返回成功，让后续逻辑将其写入 proxy-provider
    }

    // 节点链接：直接用 mihomo 解析（不需要 webGet）
    if (isNodeLink) {
      writeLog(LOG_TYPE_INFO, "检测到节点链接，正在使用 Mihomo 解析...");
      strSub = link; // 直接使用链接本身作为解析内容
    } else {
      // 其他情况（surge config link 等）：保持原有逻辑
      writeLog(LOG_TYPE_INFO, "正在下载订阅数据...");
      if (startsWith(link, "surge:///install-config")) // surge config link
        link = urlDecode(getUrlArg(link, "url"));

      // Replace browser UA with clash.meta
      if (request_headers) {
        auto ua_it = request_headers->find("User-Agent");
        if (ua_it != request_headers->end() && isBrowserUA(ua_it->second)) {
          writeLog(LOG_TYPE_INFO, "检测到浏览器 UA，已替换为 clash.meta UA "
                                  "以避免被拦截");
          ua_it->second = "clash.meta";
        }
      }

      strSub = webGet(link, proxy, global.cacheSubscription, &extra_headers,
                      request_headers, parse_set.fetch_context);
    }
    /*
    if(strSub.size() == 0)
    {
        //try to get it again with system proxy
        writeLog(LOG_TYPE_WARN, "无法直接下载订阅，正在使用
    system proxy."); strProxy = getSystemProxy(); if(strProxy != "")
        {
            strSub = webGet(link, strProxy);
        }
        else
            writeLog(LOG_TYPE_WARN, "未设置系统代理，跳过。");
    }
    */
    if (!strSub.empty()) {
      writeLog(LOG_TYPE_INFO,
               "正在使用 Mihomo 解析器解析订阅数据...");

#ifdef USE_MIHOMO_PARSER
      // Use mihomo parser (100% compatible with mihomo)
      try {
        auto mihomo_nodes = mihomo::parseSubscription(strSub);

        // Convert mihomo::ProxyNode to SubConverter-Extended's Proxy structure
        for (const auto &mnode : mihomo_nodes) {
          Proxy node;
          node.Remark = mnode.name;
          node.Type = ProxyType::Unknown; // Will be set based on type string

          // Map mihomo proxy type to SubConverter-Extended ProxyType
          node.Type = getProxyTypeFromString(mnode.type);

          // Copy all raw params for generic pass-through
          for (const auto &[key, value] : mnode.params) {
            node.RawParams[key] = value;
          }

          // CRITICAL: Preserve original type string from mihomo
          // This ensures unknown protocols (e.g., linksb) output correctly as
          // "type: linksb" instead of "type: Unknown" which would break Clash
          node.RawParams["type"] = mnode.type;

          // Add more types as needed

          node.Hostname = mnode.server;
          node.Port = mnode.port;

          // Store all additional params for later serialization
          // (mihomo guarantees these are correct for the protocol)
          for (const auto &[key, value] : mnode.params) {
            // These will be used when generating the final config
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
            else if (key == "tls")
              node.TLSStr = value;
            else if (key == "sni" || key == "servername")
              node.ServerName = value;
            else if (key == "network")
              node.TransferProtocol = value;
            // Store everything else in a raw format for mihomo-compatible
            // output
          }

          nodes.push_back(node);
        }

        if (nodes.empty()) {
          writeLog(LOG_TYPE_ERROR,
                   "Mihomo 解析器未从链接中解析到有效节点：'" + link +
                       "'！");
          return -1;
        }

        writeLog(LOG_TYPE_INFO, "Mihomo 解析器成功解析 " +
                                    std::to_string(nodes.size()) + " 个节点。");
        // Debug: Log first node name if available
        if (!nodes.empty()) {
          writeLog(LOG_TYPE_INFO, "第一个节点：" + nodes[0].Remark);
        }
      } catch (const std::exception &e) {
        writeLog(LOG_TYPE_ERROR,
                 "Mihomo 解析器错误：" + std::string(e.what()) +
                     "，回退到旧解析器。");
        // Fallback to legacy parser
        if (explodeConfContent(strSub, nodes) == 0) {
          writeLog(LOG_TYPE_ERROR, "无效订阅：'" + link + "'！");
          return -1;
        }
      }
#else
      // Fallback when mihomo parser is not available
      if (explodeConfContent(strSub, nodes) == 0) {
        writeLog(LOG_TYPE_ERROR, "无效订阅：'" + link + "'！");
        return -1;
      }
#endif

      if (startsWith(strSub, "ssd://")) {
        getSubInfoFromSSD(strSub, subInfo);
      } else {
        if (!getSubInfoFromHeader(extra_headers, subInfo))
          getSubInfoFromNodes(nodes, stream_rules, time_rules, subInfo);
      }
      writeLog(LOG_TYPE_INFO,
               "过滤前节点数：" + std::to_string(nodes.size()));
      filterNodes(nodes, exclude_remarks, include_remarks, groupID);
      writeLog(LOG_TYPE_INFO,
               "过滤后节点数：" + std::to_string(nodes.size()));
      for (Proxy &x : nodes) {
        x.GroupId = groupID;
        if (custom_group.size())
          x.Group = custom_group;
      }
      writeLog(LOG_TYPE_INFO, "正在复制 " + std::to_string(nodes.size()) +
                                  " 个节点到总节点列表");
      copyNodes(nodes, allNodes);
      writeLog(LOG_TYPE_INFO, "总节点列表当前共有 " +
                                  std::to_string(allNodes.size()) +
                                  " 个节点");
    } else {
      writeLog(LOG_TYPE_ERROR, "无法下载订阅数据。");
      return -1;
    }
    break;
  }
  case ConfType::Local:
    if (!authorized)
      return -1;
    writeLog(LOG_TYPE_INFO, "正在解析配置文件数据...");
    if (explodeConf(link, nodes) == 0) {
      writeLog(LOG_TYPE_ERROR, "无效配置文件！");
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
    // 理论上不应该走到这里，因为：
    // 1. 所有 Mihomo 协议都走 SUB case（由新分流逻辑处理）
    // 2. HTTP(S)/SOCKS/Netch/Local 都有专门的 case
    // 如果走到这里，说明有未处理的边缘情况
    writeLog(LOG_TYPE_WARN,
             "遇到非预期链接类型，理论上不应发生：" + link);
    writeLog(LOG_TYPE_INFO, "正在尝试使用 Mihomo 作为回退解析器...");

    // 作为最后的 fallback，尝试喂给 Mihomo
    strSub = link;
    if (!strSub.empty()) {
      writeLog(LOG_TYPE_INFO, "正在使用 Mihomo 解析器处理回退解析...");
#ifdef USE_MIHOMO_PARSER
      try {
        auto mihomo_nodes = mihomo::parseSubscription(strSub);
        for (const auto &mnode : mihomo_nodes) {
          Proxy node;
          node.Remark = mnode.name;
          node.Type = getProxyTypeFromString(mnode.type);
          for (const auto &[key, value] : mnode.params) {
            node.RawParams[key] = value;
          }
          node.RawParams["_mihomo_type"] = mnode.type;
          node.GroupId = groupID;
          if (!custom_group.empty())
            node.Group = custom_group;
          allNodes.emplace_back(std::move(node));
        }
      } catch (const std::exception &e) {
        writeLog(LOG_TYPE_ERROR,
                 "Mihomo 回退解析失败：" + std::string(e.what()));
        return -1;
      }
#else
      writeLog(LOG_TYPE_ERROR,
               "Mihomo 解析器不可用，且没有匹配到其他处理器。");
      return -1;
#endif
    } else {
      writeLog(LOG_TYPE_ERROR, "默认分支未找到有效链接。");
      return -1;
    }
  }
  return 0;
}

bool chkIgnore(const Proxy &node, string_array &exclude_remarks,
               string_array &include_remarks) {
  bool excluded = false, included = false;
  // std::string remarks = UTF8ToACP(node.remarks);
  // std::string remarks = node.remarks;
  // writeLog(LOG_TYPE_INFO, "正在匹配排除规则...");
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
    // writeLog(LOG_TYPE_INFO, "正在匹配包含规则...");
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
  int node_index = 0;
  auto write_iter = nodes.begin();
  for (auto iter = nodes.begin(); iter != nodes.end(); ++iter) {
    if (chkIgnore(*iter, exclude_remarks, include_remarks)) {
      writeLog(LOG_TYPE_INFO, "节点 " + iter->Group + " - " + iter->Remark +
                                  " 已被忽略，不会添加。");
      continue;
    }

    writeLog(LOG_TYPE_INFO, "节点 " + iter->Group + " - " + iter->Remark +
                                " 已添加。");
    iter->Id = node_index;
    iter->GroupId = groupID;
    ++node_index;
    if (write_iter != iter)
      *write_iter = std::move(*iter);
    ++write_iter;
  }
  nodes.erase(write_iter, nodes.end());
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
  writeLog(LOG_TYPE_INFO, "过滤开始。");
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
          writeLog(LOG_TYPE_INFO, "节点 " + iter->group + " - " +
  iter->remarks
  + " 已被忽略，不会添加。"); nodes.erase(iter);
      }
      else
      {
          writeLog(LOG_TYPE_INFO, "节点 " + iter->group + " - " +
  iter->remarks
  + " 已添加。"); iter->id = node_index; iter->groupID = groupID;
          ++node_index;
          ++iter;
      }
  }
  */
  writeLog(LOG_TYPE_INFO, "过滤完成。");
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
          global.scriptCleanContext);
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
          global.scriptCleanContext);
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
          global.scriptCleanContext);
    }
    if (failed)
      std::stable_sort(
          nodes.begin(), nodes.end(),
          [](const Proxy &a, const Proxy &b) { return a.Remark < b.Remark; });
  }
}
