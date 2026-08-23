<div align="center">

<p>
  <img src="design/favicon-light-proposal.svg#gh-light-mode-only" alt="SubConverter-Extended icon" width="96" height="96">
  <img src="design/favicon-dark-proposal.svg#gh-dark-mode-only" alt="SubConverter-Extended icon" width="96" height="96">
</p>

# SubConverter-Extended

**面向多种代理客户端的订阅转换后端增强版**

[![GitHub Tag](https://img.shields.io/github/v/tag/Aethersailor/SubConverter-Extended?style=flat&logo=github&label=version&color=blue)](https://github.com/Aethersailor/SubConverter-Extended/releases/latest)
[![Release](https://img.shields.io/github/actions/workflow/status/Aethersailor/SubConverter-Extended/release.yml?style=flat&label=release&logo=githubactions)](https://github.com/Aethersailor/SubConverter-Extended/actions/workflows/release.yml)
[![Docker Pulls](https://img.shields.io/docker/pulls/aethersailor/subconverter-extended?style=flat&logo=docker)](https://hub.docker.com/r/aethersailor/subconverter-extended)
[![License](https://img.shields.io/badge/license-GPL--3.0-orange?style=flat)](LICENSE)
[![Wiki](https://img.shields.io/badge/Wiki-完整用户手册-2f81f7?style=flat&logo=github)](https://github.com/Aethersailor/SubConverter-Extended/wiki)

[🧭 按任务开始](#按任务开始) · [🔗 相关项目](#与相关项目的关系) · [💡 立项原因](#立项原因) · [🚀 快速开始](#快速开始) · [📚 完整 Wiki](https://github.com/Aethersailor/SubConverter-Extended/wiki)

</div>

---

<a id="项目介绍"></a>

## 📖 项目介绍

SubConverter-Extended 基于 [asdlokj1qpi233/subconverter](https://github.com/asdlokj1qpi233/subconverter) 深度演进，是一个面向多种代理客户端和订阅格式的转换后端。

项目为 Mihomo 提供专用解析桥和 Proxy Provider，并可为 Surge、Quantumult X、Loon、Surfboard 和 Stash 生成客户端原生远程资源；Sing-box、Quantumult 及多种传统订阅格式则由后端完成转换。不同目标使用与其配置能力相匹配的处理方式。

> [!IMPORTANT]
> **维护重点**：Mihomo 相关需求是项目的首要优化方向。`clash`、`clashr` 的解析、Provider 和协议参数支持会优先完善；对其他客户端的支持也会持续优化，并在各自格式能力范围内尽量提供完整、可靠的转换结果。

<a id="按任务开始"></a>

### 🧭 按任务开始

| 想完成的任务 | 入口 |
| :--- | :--- |
| 使用公共实例生成第一份配置 | [快速开始](https://github.com/Aethersailor/SubConverter-Extended/wiki/Getting-Started) |
| 确认客户端应使用哪个 `target` | [客户端与目标格式](https://github.com/Aethersailor/SubConverter-Extended/wiki/Compatibility) |
| 自行部署服务 | [Docker 部署](https://github.com/Aethersailor/SubConverter-Extended/wiki/Docker-Deployment) · [原生部署](https://github.com/Aethersailor/SubConverter-Extended/wiki/Native-Deployment) |
| 使用 OpenClash 模板和规则 | [Custom_OpenClash_Rules](https://github.com/Aethersailor/Custom_OpenClash_Rules) |
| 排查失败或提交脱敏反馈 | [故障排查](https://github.com/Aethersailor/SubConverter-Extended/wiki/Troubleshooting) · [Bug 反馈](https://github.com/Aethersailor/SubConverter-Extended/issues/new?template=bug_report.yml) |

<a id="与相关项目的关系"></a>

### 🔗 与相关项目的关系

| 项目 | 用户可见职责 | 与 SubConverter-Extended 的关系 |
| :--- | :--- | :--- |
| [Custom_OpenClash_Rules](https://github.com/Aethersailor/Custom_OpenClash_Rules) | 提供 OpenClash 模板、规则和使用教程 | 可作为转换模板和规则来源；也可直接供 OpenClash 使用。 |
| **SubConverter-Extended** | 转换订阅、模板和规则，生成目标客户端配置 | 不负责收集 Mihomo `MATCH` 域名，也不供应订阅或节点。 |
| [Rule-Bot Client](https://github.com/Aethersailor/Rule-Bot-Client) | 从 Mihomo `MATCH` 连接中收集域名，默认保存在本地，可选发送 | 可用于发现需要补充的规则；不是订阅转换的必需组件。 |
| [Rule-Bot](https://github.com/Aethersailor/Rule-Bot) | 检查域名并按策略提交到目标规则仓库 | 项目公共实例的目标是 Custom_OpenClash_Rules；自建服务可维护其他仓库。 |

常见使用方式是「Custom_OpenClash_Rules 模板 → 可选的 SubConverter-Extended 转换 → Mihomo/OpenClash」。规则反馈是独立流程：「Mihomo `MATCH` → 可选的 Rule-Bot Client 发送 → Rule-Bot → 目标规则仓库」。两条流程相互独立，无需成套部署。

### 🎯 长期愿景

SubConverter-Extended 的长期目标，是把不同客户端的配置转换简化为一套统一流程：用户只需维护自己的订阅转换模板，或直接选用公共模板，再附加自己的代理信息（订阅链接或节点链接），即可生成适用于不同客户端的配置文件。

> [!NOTE]
> 这一目标尚未完全实现。当前不同客户端在配置结构、远程资源表达、协议字段和模板能力方面仍有差异，部分场景仍需按客户端分别配置与处理。当前可用能力以最新正式 Release 和 Wiki 的兼容性说明为准。

> [!TIP]
> 第一次使用时，先阅读 Wiki 的[快速开始](https://github.com/Aethersailor/SubConverter-Extended/wiki/Getting-Started)和[客户端与目标格式](https://github.com/Aethersailor/SubConverter-Extended/wiki/Compatibility)。准备自行部署时，再选择 [Docker](https://github.com/Aethersailor/SubConverter-Extended/wiki/Docker-Deployment) 或[原生部署](https://github.com/Aethersailor/SubConverter-Extended/wiki/Native-Deployment)。

### 🔀 两类远程订阅处理方式

<p align="center">
  <img src="docs/images/readme-flow-overview.svg" alt="SubConverter-Extended 远程订阅与节点链接处理方式" width="1100">
</p>

远程订阅是否由客户端更新，取决于目标格式、请求参数和输入类型。完整行为见 Wiki 的[远程订阅与客户端拉取](https://github.com/Aethersailor/SubConverter-Extended/wiki/Remote-Subscriptions)。

### 🛡️ Mihomo Provider 流程对比

> [!NOTE]
> 下图仅对比 `target=clash`、`target=clashr` 处理远程 HTTP 订阅时的默认流程。`list=true` 和其他客户端目标使用各自的处理流程。

<p align="center">
  <img src="docs/images/readme-flow-legacy.svg" alt="传统 subconverter 远程订阅链接处理流程" width="820">
</p>

<p align="center">
  <img src="docs/images/readme-flow-extended.svg" alt="SubConverter-Extended Mihomo Proxy Provider 处理流程" width="820">
</p>

### 🧩 当前 Release 目标格式

| 工作方式 | 目标 |
| :--- | :--- |
| Mihomo 节点解析与 Proxy Provider | `clash`、`clashr` |
| 客户端原生远程资源 | `surge`、`quanx`、`loon`、`surfboard`、`stash` |
| 完整配置转换 | `quan`、`mellow`、`singbox` |
| 简单订阅或分享链接输出 | `ss`、`ssd`、`ssr`、`sssub`、`v2ray`、`v2rayn`、`v2rayng`、`shadowrocket`、`trojan`、`vless`、`hysteria2`、`mixed` |

> [!NOTE]
> 上表按当前正式 Release 的显式目标整理。不同目标支持的节点类型、传输参数和客户端最低版本各不相同。闭源客户端仍需在实际版本中验证导入和连通性；详细范围见[客户端与目标格式](https://github.com/Aethersailor/SubConverter-Extended/wiki/Compatibility)。

---

<a id="立项原因"></a>

## 💡 立项原因

SubConverter-Extended 源于项目维护者长期使用 subconverter 的实际经历。立项时，主要希望解决以下三个问题。

### 🐢 协议支持滞后

subconverter 的节点解析器需要人工跟进协议、传输方式和参数变化。`hysteria2`、`tuic`、`anytls` 等新协议需要逐项适配；`vless` 等已有协议也会随着传输层参数演进而出现新的兼容需求。维护节奏一旦落后于客户端，转换结果就可能缺少客户端已经支持的字段。

### 🚫 远程订阅服务商的访问限制

传统 subconverter 需要由转换后端连接远程订阅服务器、下载订阅并解析节点。部分远程订阅服务商会限制海外 IP、subconverter 使用的 User-Agent 或非客户端发起的请求。这会造成客户端可以直接更新订阅，而转换后端无法获取相同的订阅内容。

修改 User-Agent 只能处理针对 User-Agent 的限制，无法解决地区或出口 IP 限制，也会增加转换工具与远程服务商之间的适配成本。

### 🤯 新手使用门槛

协议解析、订阅拉取和参数转换出现问题时，使用者往往需要自行修改 YAML 配置或排查转换细节。一些开发者和内容创作者也因此转向推荐手工维护 YAML。对于新手和普通用户，这种方式把配置结构、协议字段和故障排查的负担转移给了使用者。

这也延续了项目维护者在 [Custom_OpenClash_Rules](https://github.com/Aethersailor/Custom_OpenClash_Rules) 中坚持的理念：

> [!IMPORTANT]
> **对于新手和普通用户，最具普适性的操作流程始终是基于 UI 的操作流程。**

理想的使用流程是：提供订阅链接，通过少量可视化操作生成适合自身场景的配置，并由模板和客户端继续更新远程资源，而不必先手工维护完整的 YAML 文件。

### 🛠️ 从改进尝试到独立立项

项目维护者曾尝试向日常使用的 subconverter 分支提交改进，但当时无法在该仓库提交 PR、发起 Issue，也无法为该仓库添加 Star。具体原因无从确认，因此无法通过该仓库提交相关改进。

> **既然无法向原分支贡献，那就自己动手。**

这就是 SubConverter-Extended 诞生的原因。最初的技术思路包括：

- 保留用户熟悉的订阅转换接口和 UI 使用流程；
- 对 Mihomo 远程订阅生成 `proxy-providers`，由客户端直接更新订阅；
- 使用 Mihomo 解析器处理节点链接，减少重复维护协议解析逻辑的成本。

其中，`proxy-providers` 路径用于减少转换后端代取订阅造成的访问问题；Mihomo 解析器用于跟随 Mihomo 的协议和参数支持。随着项目演进，支持范围已从最初的 Mihomo/Clash 使用场景扩展到多种客户端；Mihomo 仍是重点增强方向，其他客户端也会在各自格式能力范围内持续完善。

---

<a id="相比上游的主要改进"></a>

## ✨ 相比上游的主要改进

| 方面 | SubConverter-Extended 当前 Release 的行为 |
| :--- | :--- |
| 多目标远程订阅 | 除 Mihomo Proxy Provider 外，还可为 Surge、Quantumult X、Loon、Surfboard 和 Stash 生成客户端原生远程资源。 |
| Mihomo 节点解析 | `target=clash`、`target=clashr` 的节点链接只进入 Mihomo 解析桥，协议能力来自锁定的 Mihomo 依赖。 |
| 独立目标生成 | 为 Stash、Shadowrocket、v2rayN、v2rayNG 等目标提供独立输出和能力过滤；无法表示的节点会按目标能力过滤或返回明确错误。 |
| 请求诊断 | `explain=true` 返回脱敏 JSON 诊断；`/inspect` 提供可视化诊断台；响应和日志使用服务端生成的 `X-Request-ID` 关联。 |
| 运行统计 | 可选 `/dashboard` 与 `/dashboard/data`，支持持久化、时间窗口统计、地区分布和可选 Basic Auth。 |
| 部署安全 | 提供 `lan`、`public`、`strict` 安全档位，并区分请求方可控抓取、可信本地配置和上传权限。 |
| 出站访问 | `proxy_config`、`proxy_ruleset`、`proxy_subscription` 使用明确的 Direct、System、Explicit、Cors 策略，并支持 `proxy_bypass`。 |
| 规则扩展 | 支持外部 Clash 完整规则的 `ruleprepend` / `ruleappend`，以及 `clash-ipcidr` 的 `no-resolve` 选项。 |
| 交付形式 | 同时提供 Docker Hub、GHCR、多架构 Linux 便携包、Windows 便携包和 OpenWrt APK，并发布校验清单。 |
| 运行可靠性 | 增加请求合并、响应微缓存、有界规则任务、连接复用、优雅停机、敏感日志脱敏和可配置资源限制。 |

完整差异、限制和兼容语义见[上游关系与支持边界](https://github.com/Aethersailor/SubConverter-Extended/wiki/Support-and-License)。

### 🧰 特色参数示例

以下扩展用于解决实际订阅更新和排障问题。这里只展示高频形式，完整优先级、默认值和错误条件见[特色参数与扩展语法](https://github.com/Aethersailor/SubConverter-Extended/wiki/Feature-Parameters)。

```text
# 自定义 Provider 名称和更新间隔
provider:HK,interval:21600,https://example.com/sub

# 让这一条 Mihomo Provider 不写入 proxy: DIRECT
proxy_direct:false,https://example.com/sub

# 对整个请求覆盖 Mihomo Provider 的直连策略
&provider_proxy_direct=false

# 返回脱敏诊断报告，不返回配置文件
&explain=true
```

规则和外部配置还支持：

- `ruleprepend` / `ruleappend`：向 Clash 完整规则的首尾插入远程规则来源；
- `28800|no-resolve`：为 `clash-ipcidr` 规则集引用增加 `no-resolve`；
- `provider_headers`：从当前请求中选择允许的请求头，并写入 Clash 或 Stash Provider；
- `[proxy_provider]`：设置部署级 Provider 更新间隔和 `proxy: DIRECT` 默认行为。

---

<a id="快速开始"></a>

## 🚀 快速开始

可直接使用公共实例，也可自行部署。公共实例无需自行维护服务；自行部署可独立控制安全策略、出站访问和数据边界。

### 🌍 直接使用公共实例

公共实例地址：

```text
https://api.asailor.org
```

先访问 [`/version`](https://api.asailor.org/version) 查看当前 Release 身份，再按照[快速开始](https://github.com/Aethersailor/SubConverter-Extended/wiki/Getting-Started)生成第一个请求。

> [!WARNING]
> 公共实例不会替使用者保管订阅秘密。即使 Provider 模式下后端不下载订阅内容，转换请求仍可能携带订阅 URL；浏览器、网络入口、CDN 或反向代理也可能接触请求信息。敏感订阅建议自行部署，并阅读[安全与隐私](https://github.com/Aethersailor/SubConverter-Extended/wiki/Security-and-Privacy)。

> [!IMPORTANT]
> 除 Stash 独立模板外，默认输出通常是最简配置，不包含完整 DNS 设置。客户端需要启用 DNS 覆写，或使用包含 DNS 的自定义基础模板。否则节点域名可能无法解析。

### 🐳 使用 Docker 自行部署

```bash
docker run -d \
  --name SubConverter-Extended \
  -p 25500:25500 \
  --restart unless-stopped \
  aethersailor/subconverter-extended:latest
```

检查服务：

```text
http://localhost:25500/version
http://localhost:25500/healthz
```

> [!NOTE]
> 上述命令是最小启动示例，不会持久化自定义配置和统计数据。`-p 25500:25500` 还会把端口发布到宿主机全部接口。需要保留配置或统计数据时，请按照 Wiki 的 [Docker 部署](https://github.com/Aethersailor/SubConverter-Extended/wiki/Docker-Deployment)配置持久化目录，并根据实际网络范围选择安全档位。

### 📦 可用交付形式

| 交付形式 | 当前 Release 支持 |
| :--- | :--- |
| Docker | Docker Hub 与 GHCR；`linux/amd64`、`linux/arm64`、`linux/arm/v7` |
| Linux 便携包 | `amd64`、`arm64`、`armv7` |
| Windows 便携包 | `windows-amd64.zip` |
| OpenWrt APK | OpenWrt 25.12+ 的多种 `apk` 架构；包未签名 |
| 完整性校验 | `SHA256SUMS` 与 `RELEASE-MANIFEST.json` |

下载入口：[最新 Release](https://github.com/Aethersailor/SubConverter-Extended/releases/latest)

---

## 🧭 文档导航

| 想完成的任务 | 文档 |
| :--- | :--- |
| 判断项目是否适合当前客户端 | [客户端与目标格式](https://github.com/Aethersailor/SubConverter-Extended/wiki/Compatibility) |
| 直接使用公共实例 | [快速开始](https://github.com/Aethersailor/SubConverter-Extended/wiki/Getting-Started) |
| 使用 Docker 自行部署 | [Docker 部署](https://github.com/Aethersailor/SubConverter-Extended/wiki/Docker-Deployment) |
| 部署到 Linux、Windows 或 OpenWrt | [原生部署](https://github.com/Aethersailor/SubConverter-Extended/wiki/Native-Deployment) |
| 理解 `/sub` 和常用参数 | [基本转换](https://github.com/Aethersailor/SubConverter-Extended/wiki/Basic-Conversion) |
| 使用特色参数 | [特色参数与扩展语法](https://github.com/Aethersailor/SubConverter-Extended/wiki/Feature-Parameters) |
| 配置模板和规则 | [外部配置与模板](https://github.com/Aethersailor/SubConverter-Extended/wiki/External-Configuration) · [规则与规则集](https://github.com/Aethersailor/SubConverter-Extended/wiki/Rules-and-Rulesets) |
| 配置公网安全和出站代理 | [安全与隐私](https://github.com/Aethersailor/SubConverter-Extended/wiki/Security-and-Privacy) · [出站代理](https://github.com/Aethersailor/SubConverter-Extended/wiki/Outbound-Proxy) |
| 使用诊断台和 Dashboard | [诊断](https://github.com/Aethersailor/SubConverter-Extended/wiki/Diagnostics) · [Dashboard 与统计](https://github.com/Aethersailor/SubConverter-Extended/wiki/Dashboard-and-Statistics) |
| 处理转换或部署故障 | [故障排查](https://github.com/Aethersailor/SubConverter-Extended/wiki/Troubleshooting) |
| 查找所有 API 参数 | [API 参考](https://github.com/Aethersailor/SubConverter-Extended/wiki/API-Reference) |

完整目录：[SubConverter-Extended Wiki](https://github.com/Aethersailor/SubConverter-Extended/wiki)

---

## 🔐 安全、合规与使用边界

- 项目不提供订阅服务或代理节点；规则转换功能也不会授予第三方内容的再分发权利。
- 项目不保证任意订阅都能被任意目标客户端完整表示。
- 自行部署者需要自行管理 TLS、访问控制、防火墙、日志、备份和更新。
- `lan` 是兼容旧部署的默认安全档位，不代表服务可以安全地直接暴露到公网。
- 项目日志会对已知敏感字段进行脱敏，但这不是通用数据防泄漏系统。
- 未修复的安全漏洞请按 [安全策略](SECURITY.md) 私密报告，不要在公开 Issue 中披露利用细节。

> [!WARNING]
> 本项目保持中立，不提供规避监管制度的功能。项目仅用于计算机技术学习和合法场景中的配置转换。使用者需要遵守所在地法律法规及远程服务提供者的使用条款。

---

## 📦 获取正式版本

正式 Release 是面向用户的发布版本。Docker `latest` 在正式 Release 完成验证后更新，并指向该 Release 的版本镜像。

| 交付形式 | 获取方式 | 用途 |
| :--- | :--- | :--- |
| Docker `latest` | Docker Hub 或 GHCR | 默认安装和更新 |
| Docker 版本标签 | 与正式 Release 相同的 `vX.Y.Z` | 固定版本和回滚 |
| 便携包与 OpenWrt APK | [最新 Release](https://github.com/Aethersailor/SubConverter-Extended/releases/latest) | 原生部署与完整性校验 |

功能说明以当前正式 Release 为准。报告问题时，请提供 `/version` 显示的版本和源代码修订。

---

## 🤝 致谢与许可证

本项目使用或引用以下开源项目：

- [asdlokj1qpi233/subconverter](https://github.com/asdlokj1qpi233/subconverter)：本项目的上游基础；
- [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo)：提供 Mihomo 节点解析能力；
- [Aethersailor/Custom_OpenClash_Rules](https://github.com/Aethersailor/Custom_OpenClash_Rules)：提供 OpenClash 模板、规则和用户教程。

SubConverter-Extended 按 [GPL-3.0](LICENSE) 发布。Mihomo 解析桥使用的 Mihomo 依赖同样遵循 GPL-3.0；具体依赖版本以 `bridge/go.mod` 为准。

---

## ⭐ Star 历史

<div align="center">
  <a href="https://www.star-history.com/?type=date&repos=Aethersailor%2FSubConverter-Extended">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=Aethersailor/SubConverter-Extended&type=date&theme=dark&legend=top-left&sealed_token=NKvX6WwN3no1B0JCAxO5Tkk4nqJLR5HppGP59Pp9IDkrygstiLYT8T8_MsYyG-hqMAuML_mTOU2N1PX79o9ZgwfXacAhIBKClQskYzigRVD1FQyH66FGwA">
      <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=Aethersailor/SubConverter-Extended&type=date&legend=top-left&sealed_token=NKvX6WwN3no1B0JCAxO5Tkk4nqJLR5HppGP59Pp9IDkrygstiLYT8T8_MsYyG-hqMAuML_mTOU2N1PX79o9ZgwfXacAhIBKClQskYzigRVD1FQyH66FGwA">
      <img alt="SubConverter-Extended Star 历史" src="https://api.star-history.com/chart?repos=Aethersailor/SubConverter-Extended&type=date&legend=top-left&sealed_token=NKvX6WwN3no1B0JCAxO5Tkk4nqJLR5HppGP59Pp9IDkrygstiLYT8T8_MsYyG-hqMAuML_mTOU2N1PX79o9ZgwfXacAhIBKClQskYzigRVD1FQyH66FGwA">
    </picture>
  </a>
</div>

## 📊 仓库活跃度

<p align="center">
  <img src="https://repobeats.axiom.co/api/embed/c249ae5c34b99a067c78e9216600c1a5eac16c65.svg" alt="SubConverter-Extended 仓库活跃度统计">
</p>

---

<div align="center">

如果项目对使用有所帮助，欢迎通过 ⭐ Star 支持持续维护。

Made with ❤️ by [Aethersailor](https://github.com/Aethersailor)

</div>
