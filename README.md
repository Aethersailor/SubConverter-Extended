<div align="center">

<p>
  <img src="design/favicon-light-proposal.svg#gh-light-mode-only" alt="SubConverter-Extended icon" width="96" height="96">
  <img src="design/favicon-dark-proposal.svg#gh-dark-mode-only" alt="SubConverter-Extended icon" width="96" height="96">
</p>

# SubConverter-Extended

**面向多种代理客户端的订阅转换后端增强版**

[![GitHub Tag](https://img.shields.io/github/v/tag/Aethersailor/SubConverter-Extended?style=flat&logo=github&label=version&color=blue)](https://github.com/Aethersailor/SubConverter-Extended/releases/latest)
[![Build](https://img.shields.io/github/actions/workflow/status/Aethersailor/SubConverter-Extended/build-dockerhub.yml?branch=master&style=flat&label=build&logo=githubactions)](https://github.com/Aethersailor/SubConverter-Extended/actions/workflows/build-dockerhub.yml)
[![Docker Pulls](https://img.shields.io/docker/pulls/aethersailor/subconverter-extended?style=flat&logo=docker)](https://hub.docker.com/r/aethersailor/subconverter-extended)
[![License](https://img.shields.io/badge/license-GPL--3.0-orange?style=flat)](LICENSE)
[![Wiki](https://img.shields.io/badge/Wiki-完整用户手册-2f81f7?style=flat&logo=github)](https://github.com/Aethersailor/SubConverter-Extended/wiki)

[📖 项目介绍](#项目介绍) · [💡 立项原因](#立项原因) · [✨ 相比上游](#相比上游的主要改进) · [🚀 快速开始](#快速开始) · [📚 完整 Wiki](https://github.com/Aethersailor/SubConverter-Extended/wiki)

</div>

---

<a id="项目介绍"></a>

## 📖 项目介绍

SubConverter-Extended 基于 [asdlokj1qpi233/subconverter](https://github.com/asdlokj1qpi233/subconverter) 深度演进，是一个面向多种代理客户端和订阅格式的转换后端。

项目为 Mihomo 提供专用解析桥和 Proxy Provider，并可为 Surge、Quantumult X、Loon、Surfboard 和 Stash 生成客户端原生远程资源；Sing-box、Quantumult 及多种传统订阅格式则由后端完成转换。不同目标使用与其配置能力相匹配的处理方式。

> [!IMPORTANT]
> **维护重点**：Mihomo 相关需求是项目的首要优化方向。`clash`、`clashr` 的解析、Provider 和协议参数支持会优先完善；对其他客户端的支持也会持续优化，并在各自格式能力范围内尽量提供完整、可靠的转换结果。

### 🎯 长期愿景

SubConverter-Extended 的长期目标，是把不同客户端的配置转换简化为一套统一流程：用户只需维护自己的订阅转换模板，或直接选用公共模板，再附加自己的代理信息（订阅链接或节点链接），即可生成适用于不同客户端的配置文件。

> [!NOTE]
> 这一目标尚未完全实现。当前不同客户端在配置结构、远程资源表达、协议字段和模板能力方面仍有差异，部分场景仍需按客户端分别配置与处理。现阶段的实际支持范围以稳定版文档为准。

> [!TIP]
> 第一次使用时，先阅读 Wiki 的[快速开始](https://github.com/Aethersailor/SubConverter-Extended/wiki/Getting-Started)和[客户端与目标格式](https://github.com/Aethersailor/SubConverter-Extended/wiki/Compatibility)。准备自行部署时，再选择 [Docker](https://github.com/Aethersailor/SubConverter-Extended/wiki/Docker-Deployment) 或[原生部署](https://github.com/Aethersailor/SubConverter-Extended/wiki/Native-Deployment)。

### 🔀 两类远程订阅处理方式

<p align="center">
  <img src="docs/images/readme-flow-overview.svg" alt="SubConverter-Extended 远程订阅与节点链接处理方式" width="1100">
</p>

远程订阅是否由客户端更新，取决于目标格式、请求参数和输入类型。完整行为见 Wiki 的[远程订阅与客户端拉取](https://github.com/Aethersailor/SubConverter-Extended/wiki/Remote-Subscriptions)。

### 🛡️ Mihomo Provider 流程对比

> [!NOTE]
> 下图对比的是 `target=clash`、`target=clashr` 处理远程 HTTP 订阅时的默认流程。`list=true` 和其他客户端目标可能仍由后端下载并解析订阅，不能把这组图理解为所有目标的统一行为。

<p align="center">
  <img src="docs/images/readme-flow-legacy.svg" alt="传统 subconverter 远程订阅链接处理流程" width="820">
</p>

<p align="center">
  <img src="docs/images/readme-flow-extended.svg" alt="SubConverter-Extended Mihomo Proxy Provider 处理流程" width="820">
</p>

### 🧩 稳定版目标格式

| 工作方式 | 目标 |
| :--- | :--- |
| Mihomo 节点解析与 Proxy Provider | `clash`、`clashr` |
| 客户端原生远程资源 | `surge`、`quanx`、`loon`、`surfboard`、`stash` |
| 完整配置转换 | `quan`、`mellow`、`singbox` |
| 简单订阅或分享链接输出 | `ss`、`ssd`、`ssr`、`sssub`、`v2ray`、`v2rayn`、`v2rayng`、`shadowrocket`、`trojan`、`vless`、`hysteria2`、`mixed` |

> [!NOTE]
> 上表按当前稳定版 `master` 的显式目标整理。不同目标的节点类型、传输参数和客户端最低版本并不相同。“能够生成”也不等于已经在对应闭源客户端上完成真机连通测试。使用前请查看[客户端与目标格式](https://github.com/Aethersailor/SubConverter-Extended/wiki/Compatibility)。

---

<a id="立项原因"></a>

## 💡 立项原因

### 🔄 协议和参数持续演进

原版 subconverter 的节点解析器主要依赖人工维护。新协议、新传输方式和既有协议参数持续变化时，解析器需要不断补充代码、样例和兼容逻辑；维护节奏一旦跟不上，转换结果就可能遗漏客户端已经支持的字段。

对于 Mihomo 路径，本项目直接集成 Mihomo 的 Go 解析模块，并在构建阶段从锁定的 Mihomo 依赖生成协议和参数能力数据。这样可以减少重复维护 Mihomo 节点解析规则的成本，同时保持明确的依赖版本和构建边界。

### 🌐 服务端代取订阅存在访问差异

传统转换流程通常由后端先访问远程订阅，再解析和回写节点。后端所在地区、出口 IP、User-Agent、代理设置和远程服务商访问策略都可能与用户设备不同，从而出现“客户端可以更新，转换后端却无法访问”的情况。

如果目标客户端具有原生远程资源能力，本项目优先生成客户端可直接使用的远程资源配置，让客户端自行更新订阅。Mihomo 使用 `proxy-providers`，Surge、Quantumult X、Loon、Surfboard 和 Stash 使用各自能够表示的远程资源形式。

### 🧑‍💻 普通用户需要可执行的使用流程

手工维护完整 YAML、INI 或 JSON 配置并不适合所有用户。很多使用者更需要清晰的目标格式选择、可复制的调用方式、部署后的成功检查，以及在失败时能够判断问题位于订阅、后端还是客户端。

SubConverter-Extended 保留常见 subconverter 调用方式，并增加请求诊断台、运行仪表盘、安全档位和完整用户手册，让直接使用公共实例和自行部署都具备可检查、可排障的路径。

> [!IMPORTANT]
> 最适合普通用户的流程应当从实际使用入口开始：选择客户端和目标格式，生成配置，检查客户端是否成功更新，再在需要时进入参数和排障页面，而不是先学习项目内部实现。

---

<a id="相比上游的主要改进"></a>

## ✨ 相比上游的主要改进

| 方面 | SubConverter-Extended 的稳定版行为 |
| :--- | :--- |
| 多目标远程订阅 | 除 Mihomo Proxy Provider 外，还可为 Surge、Quantumult X、Loon、Surfboard 和 Stash 生成客户端原生远程资源。 |
| Mihomo 节点解析 | `target=clash`、`target=clashr` 的节点链接只进入 Mihomo 解析桥，协议能力来自锁定的 Mihomo 依赖。 |
| 独立目标生成 | 为 Stash、Shadowrocket、v2rayN、v2rayNG 等目标提供独立输出和能力过滤，不能表示的节点不会伪装成成功结果。 |
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

### 🌍 直接使用公共实例

公共实例地址：

```text
https://api.asailor.org
```

先访问 [`/version`](https://api.asailor.org/version) 查看稳定版身份，再按照[快速开始](https://github.com/Aethersailor/SubConverter-Extended/wiki/Getting-Started)生成第一个请求。

> [!WARNING]
> 公共实例不会替使用者保管订阅秘密。即使 Provider 模式下后端不下载订阅内容，转换请求仍可能携带订阅 URL；浏览器、网络入口、CDN 或反向代理也可能接触请求信息。敏感订阅建议自行部署，并阅读[安全与隐私](https://github.com/Aethersailor/SubConverter-Extended/wiki/Security-and-Privacy)。

> [!IMPORTANT]
> 除 Stash 独立模板外，默认输出通常是最简配置，不包含完整 DNS 设置。客户端需要启用 DNS 覆写，或使用包含 DNS 的自定义基础模板。否则节点域名可能无法解析。

### 🐳 使用 Docker 体验

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
> 上述命令适合体验，不会持久化自定义配置和统计数据。`-p 25500:25500` 还会把端口发布到宿主机全部接口。长期运行请使用 Wiki 的 [Docker 部署](https://github.com/Aethersailor/SubConverter-Extended/wiki/Docker-Deployment)，并根据实际网络范围选择安全档位。

### 📦 可用交付形式

| 交付形式 | 稳定版支持 |
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
| 使用 Docker 长期部署 | [Docker 部署](https://github.com/Aethersailor/SubConverter-Extended/wiki/Docker-Deployment) |
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

> [!WARNING]
> 本项目保持中立，不提供规避监管制度的功能。项目仅用于计算机技术学习和合法场景中的配置转换。使用者需要遵守所在地法律法规及远程服务提供者的使用条款。

---

## 📦 发布通道

| 通道 | 来源 | 用途 |
| :--- | :--- | :--- |
| `latest` | `master` / 正式 Release | 稳定部署 |
| 版本标签 | 正式 Release | 固定版本和回滚 |
| `dev` | `dev` 分支 | 开发验证，不建议作为稳定生产版本 |

`master` 用于正式发布和稳定版 README；日常开发主要在 `dev` 进行。Wiki 默认描述当前稳定版，尚未发布的 dev-only 能力不会写成稳定功能。

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
