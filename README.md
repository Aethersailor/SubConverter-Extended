<div align="center">

<p>
  <img src="design/favicon-light-proposal.svg#gh-light-mode-only" alt="SubConverter-Extended icon" width="96" height="96">
  <img src="design/favicon-dark-proposal.svg#gh-dark-mode-only" alt="SubConverter-Extended icon" width="96" height="96">
</p>

# SubConverter-Extended

**A Modern Evolution of subconverter**

![GitHub Tag](https://img.shields.io/github/v/tag/Aethersailor/SubConverter-Extended?style=flat&logo=github&label=version&color=blue)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/Aethersailor/SubConverter-Extended/build-dockerhub.yml?branch=master&style=flat&label=docker%20build&logo=GitHub%20Actions)
[![Docker Pulls](https://img.shields.io/docker/pulls/aethersailor/subconverter-extended?style=flat&logo=docker)](https://hub.docker.com/r/aethersailor/subconverter-extended)
[![License](https://img.shields.io/badge/license-GPL--3.0-orange?style=flat)](LICENSE)

<h3>⚡ 现代化的订阅转换后端 | 深度适配 Mihomo 内核 ⚡</h3>

<p align="center">
  <a href="#-项目简介">项目简介</a> •
  <a href="#-立项原因">立项原因</a> •
  <a href="#-核心特性">核心特性</a> •
  <a href="#-快速开始">快速开始</a> •
  <a href="#-使用说明">使用说明</a> •
  <a href="#-配置说明">配置说明</a>
</p>

</div>

---

## 📖 项目简介

> [!NOTE]
> **SubConverter-Extended** 是基于 [asdlokj1qpi233/subconverter](https://github.com/asdlokj1qpi233/subconverter) 深度二次开发的订阅转换后端增强版本，重点解决传统 subconverter 易被远程订阅服务商屏蔽、节点参数解析不完善、维护滞后等问题。

它围绕 [Mihomo](https://github.com/MetaCubeX/mihomo) 内核的实际使用场景进行优化，提供更现代、更稳定的订阅转换能力。

**核心定位**：SubConverter-Extended 不再充当客户端与远程订阅服务商之间的“中转站”，而是作为独立的 **配置融合器** 运行。它只与客户端通信，不再主动连接远程订阅服务器；同时在编译阶段自动跟进 Mihomo 的协议支持。

**远程订阅链接处理流程对比：**

<p align="center">
  <img src="docs/images/readme-flow-legacy.svg" alt="传统 subconverter 远程订阅链接处理流程" width="820">
</p>

<p align="center">
  <img src="docs/images/readme-flow-extended.svg" alt="SubConverter-Extended 远程订阅链接处理流程" width="820">
</p>

**关键差异**：SubConverter-Extended 仅负责生成配置，不再直接连接远程订阅服务器。

> [!WARNING]
> 1. 本项目保持中立，不提供任何规避监管制度的功能。
> 2. 本项目仅用于计算机编程技术学习与研究，使用时请严格遵守当地法律法规，请勿用于任何非法用途。
> 3. 建议始终使用合法合规的第三方服务商。

---

## 💡 立项原因

### 遇到的问题

在长期使用 subconverter 的过程中，主要会遇到以下几个痛点：

#### 1. 协议支持滞后 🐢

原版 subconverter 对节点参数的支持高度依赖人工维护，其解析器的更新速度通常取决于开发者的时间与精力。

许多新兴协议（如 `hysteria2`、`tuic`、`anytls` 等）往往无法在第一时间获得完善支持；一些老协议（如 `vless`）也会因为传输层参数持续演进，而长期存在转换不完整的问题。

这一现象并非个别案例。在 subconverter 及其多个流行分支的仓库中，都能看到大量与协议支持相关的 issue。

问题的根源并不在于开发者是否足够积极，而在于这类人工维护模式本身就需要持续投入大量测试和适配成本，长期来看很难稳定覆盖所有协议与参数变化。

#### 2. 远程订阅服务商屏蔽问题 🚫

原版 subconverter 需要主动连接远程订阅服务商的订阅服务器拉取节点，而部分远程订阅服务商出于安全策略，会采取如下限制：

* 屏蔽海外 IP 访问
* 屏蔽 subconverter 的 User-Agent
* 限制非客户端发起的订阅请求

这会直接导致许多用户无法正常使用订阅转换服务。

对于按地区限制订阅访问的场景，原版 subconverter 无法从架构层面规避；对于 User-Agent 限制，虽然可以通过修改或删除特定 UA 进行绕过，但这本质上是在工具和服务商之间制造额外对抗，并不是稳妥的长期方案。

#### 3. 新手友好度不足 🤯

由于上述问题，subconverter 逐渐被一些开发者和内容创作者视为“过时方案”，转而推崇手动维护 YAML 配置。

但对大量普通用户而言，他们并不希望研究 YAML 细节，更需要的是一套基于 UI、可直接使用、问题边界清晰的操作流程。

现实情况是，在 subconverter 与远程订阅服务商限制叠加的情况下，用户经常会遇到无法解析节点、无法拉取节点、节点参数失效等问题；而新手用户通常也缺乏足够的排障能力。

正因如此，正如 [Custom_OpenClash_Rules](https://github.com/Aethersailor/Custom_OpenClash_Rules) 项目一直坚持的理念：

> [!IMPORTANT]
> **最适合新手和普通用户、且最具普适性的操作流程，始终是基于 UI 的操作流程。**

理想状态应当是：用户拿到订阅链接后，只需进行少量可视化操作，就能按自身场景生成合适配置，并自动获得后续规则更新。

### 🎯 解决方案

如果目标客户端本身基于 Mihomo 内核，那么订阅转换后端完全可以直接在配置文件中生成符合内核要求的 `proxy-provider` 字段，以取代过去“读取订阅内容 -> 解析节点 -> 回写节点参数”的旧流程。

这样一来，工具自身无需再承担远程订阅抓取与节点参数适配的职责，从架构上同时规避了协议支持滞后和服务商访问限制这两类问题。

对于本地节点链接解析，则可以直接引入 Mihomo 内核的解析器模块，替代原先需要人工维护的解析器逻辑，使订阅转换后端与 Mihomo 内核的解析能力保持一致。

基于这一思路，本项目只需跟随 Mihomo 内核更新，即可在绝大多数场景下自动获得同步的协议与参数支持，而无需重复投入额外的人工适配成本。

SubConverter-Extended 因此诞生。它是一款更贴合 Mihomo 使用场景的订阅转换工具，**服务于所有保留“订阅转换”接口且使用 Mihomo 内核的 Clash 客户端**。  

---

## ✨ 核心特性

### 🚀 相对原版的重大改进

| 功能 | 原版 Subconverter | SubConverter-Extended |
| :--- | :--- | :--- |
| **节点链接解析** | 🛠️ 人工维护解析器，支持有限 | 🤖 **集成 Mihomo 内核解析模块，自动对齐协议支持** |
| **订阅链接处理** | 📥 拉取并解析订阅，容易被屏蔽 | 🔗 **Mihomo 使用 `proxy-provider`；兼容的其他客户端使用各自的远程资源机制** |
| **协议维护方式** | ⏳ 依赖人工新增和维护 | 🔄 **编译时自动扫描 Mihomo 源码，跟进新协议支持** |
| **全局参数维护** | 📝 人工维护节点参数列表 | 🔍 **编译时自动识别硬编码参数和可覆写参数** |  

> [!WARNING]
> 1. 本项目优先保证 Mihomo 路径。`target=clash`、`target=clashr` 及 `target=auto` 识别为二者时，远程订阅只生成 `proxy-provider`，节点链接只调用 Mihomo 解析模块。
> 2. Quantumult X、Surge、Surfboard 和 Loon 的完整配置可以使用客户端原生远程资源；其节点链接仍调用继承自上游项目的 Legacy 解析器。
> 3. 其他非 Mihomo 目标仍使用 Legacy 解析器。协议和参数支持范围以对应生成器能够表示的内容为准。

Legacy 解析器对经典格式的兼容范围包括：Shadowsocks SIP002（含 AEAD-2022、插件和 IPv6）、SIP008/旧版 JSON 输入、历史 SSR 链接、v2rayN `socks://` 新旧格式、Naive HTTPS/QUIC 分享链接、Telegram 和 Base64 authority 形式的 HTTP(S) 代理链接，以及 Surge、Loon、Mihomo 和 sing-box 新旧结构中的 WireGuard 节点。它也会校准 Hysteria v1 的官方 URI、Mihomo YAML 与 sing-box JSON 字段、当前 Netch `Netch://` 分享链接和 `settings.json` 中的 SS/SSR/SOCKS/VMess/VLESS/Trojan/WireGuard 节点，以及 Surge Snell v1-v6 的 `version`、`reuse`、HTTP/TLS obfs、`udp-port`、v6 `mode` 和 Shadow TLS 字段；历史 Netch 的 `Socks5`、`TLSSecure` 和 Snell 字段仍保持兼容。输出时仍会按目标客户端的稳定能力过滤不可表示的组合。Netch 的 SSH 节点没有可共用的内部代理模型，会明确跳过；`packet` 模式可由 VLESS 单链接保留，但不会输出给不支持该模式的 sing-box。普通 HTTP(S) URL 仍按订阅处理；`socks5://` 仍属于 Mihomo 路径，不会借此改动进入 Legacy 解析器。解析成功不代表每个目标客户端都能表示对应协议，最终仍由目标生成器筛选。Netch 字段依据见其[当前服务模型与分享链接实现](https://github.com/netchx/netch/tree/main/Netch/Servers)。

V2Ray/V2Fly 是代理平台与内核，不定义可由本项目直接生成的客户端订阅容器；其[官方文档](https://www.v2fly.org/)与 [VMess 协议说明](https://www.v2fly.org/en_US/developer/protocols/vmess.html)不应和 v2rayN、v2rayNG 的订阅格式混为一谈。为保持既有部署平滑升级，历史 `target=v2ray` 继续只生成原有 VMess 订阅，不改变字节级输出契约。现代客户端使用以下独立目标：

| 目标 | 与当前客户端源码对齐的节点类型 | 输出格式 |
| --- | --- | --- |
| `v2rayn` | VMess、Shadowsocks、SOCKS5、VLESS、Trojan、Hysteria2（含 Realm/Gecko）、TUIC、WireGuard、HTTP、AnyTLS、Naive | 官方 `v2rayn://<type>/<base64url ProfileItem JSON>` 内部订阅格式 |
| `v2rayng` | VMess、Shadowsocks、SOCKS5、VLESS、Trojan、Hysteria2、WireGuard、HTTP | v2rayNG 同样直接解析的 `v2rayn://` 内部订阅格式 |

该格式由 [v2rayN 订阅说明](https://github.com/2dust/v2rayN/wiki/Description-of-subscription)正式定义；本轮协议编号和能力固定对照 v2rayN 提交 `e01717d` 的 [`EConfigType`](https://github.com/2dust/v2rayN/blob/e01717d8326a4f5060b335523590c5fda943fe03/v2rayN/ServiceLib/Enums/EConfigType.cs) 与[全局协议表](https://github.com/2dust/v2rayN/blob/e01717d8326a4f5060b335523590c5fda943fe03/v2rayN/ServiceLib/Global.cs)。v2rayNG 提交 `e8a82d9` 也注册了[对应内部格式解析器](https://github.com/2dust/v2rayNG/blob/e8a82d9810ca1cf97a3cc8a9b9525a9f21955807/V2rayNG/app/src/main/java/com/v2ray/ang/fmt/V2rayNFmt.kt)，但其[协议枚举](https://github.com/2dust/v2rayNG/blob/e8a82d9810ca1cf97a3cc8a9b9525a9f21955807/V2rayNG/app/src/main/java/com/v2ray/ang/enums/EConfigType.kt)比桌面端更窄。两个目标因此使用独立能力矩阵：例如 Realm/Gecko、TUIC、AnyTLS 和 Naive 只输出给当前确实支持它们的 v2rayN，不会借共用容器塞给 v2rayNG。两个目标仍由本项目下载并用 Legacy 解析器展开远程订阅，不会改动 Clash/Mihomo 路径。标准 URI或内部模型无法无损携带的客户端外字段会按节点明确跳过；若没有任何节点可表示，请求返回 HTTP 400，不会返回空白或不可连接的伪成功订阅。

Mieru 的 Legacy 支持仅覆盖官方可读的 `mierus://` 简化链接。解析器会校验 profile、MTU、复用等级、握手模式和 traffic-pattern 的 Base64/protobuf 外层格式，并按成对出现的 `port` / `protocol` 展开多端口配置。完整客户端配置 `mieru://` 只在 `target=clash`、`target=clashr` 及 `auto` 命中这两类目标时，由 Mihomo 专属 Go 桥使用 `bridge/go.mod` 锁定的官方 Mieru v3 protobuf 定义严格展开，再交回同一 Mihomo 解析器；不可等价表达的配置会失败关闭，且绝不回退 Legacy。其他目标继续只走 Legacy，不会因该格式改变解析路径。

Legacy 生成器会统一统计「已解析但目标格式无法表示」的节点。请求中的本地节点全部无法表示，且没有客户端原生远程资源时，接口返回 HTTP 400，不再以空节点列表伪装成功；混合输入只保留能够精确表示的节点，并在 Explain 与 `TARGET_NODE_GENERATION` 日志中给出协议计数。Quantumult X 当前可精确输出 VMess、VLESS、Trojan 的 TLS、WebSocket、Reality/Vision 组合和 AnyTLS；Loon 当前可精确输出 VMess、VLESS、Trojan 的 TCP、WebSocket、HTTP 组合、VLESS Reality/Vision、AnyTLS，以及带 Salamander 的 Hysteria 2。无法等价表达的传输、TLS 组合或危险配置分隔符会明确跳过，不会静默降级成 TCP。以上判断依据官方配置语法和项目往返测试；由于仓库不包含 Quantumult X 或 Loon 内核，仍需客户端设备验证实际导入与连通性。

### 🔥 独特功能

#### 1. Proxy-Provider 模式 🛡️

**使用 Mihomo 的 Proxy-Provider 机制**

项目不再下载并解析远程订阅内容，而是生成客户端可直接使用的配置，交由用户客户端内置的 Mihomo 内核自行拉取订阅：

```yaml
# SubConverter-Extended 生成示例内容

proxy-providers:
  Provider_A1B2C3:  # provider 名称可通过参数自定义
    type: http
    url: https://your-subscription-url  # 客户端实际拉取订阅的地址
    interval: 3600  # 默认值可由部署配置设置，也可对每条订阅单独覆盖
    proxy: DIRECT  # 默认以直连方式拉取订阅；可按部署配置或单条订阅省略
    path: ./providers/Provider_A1B2C3.yaml
    health-check:
      enable: true
      url: https://cp.cloudflare.com/generate_204
      interval: 300
    override:  # 将请求中附加的覆写参数透传给 provider
      skip-cert-verify: true
      udp: true
```

> [!NOTE]
> * `proxy-provider` 名称默认自动生成，也可通过文档下方的自定义参数指定
> * 使用 `proxy-provider` 后，订阅由客户端内核以**直连**方式自行拉取
> * 订阅是否可访问，**与本后端无关，与规则无关**；效果等同于你手动编写 YAML 并填入订阅链接
> * 如内核使用 `proxy-provider` 拉取订阅失败，通常意味着订阅链接本身无效，或当前网络环境下无法直连访问该订阅地址，请与远程订阅服务商客服对线

> [!TIP]
> **优势：**
>
> * ✅ 不再干预用户节点，交由内核原生处理
> * ✅ 订阅更新由客户端控制，无需重新转换
> * ✅ 避免远程订阅服务商屏蔽转换服务带来的问题

#### 2. Mihomo 内核模块集成 🧩

对于本地节点链接（如 `vless://` 等格式）的处理，项目直接调用 Mihomo 的 Go 解析库，确保：

* ✅ 原生支持 Mihomo 内核可解析的全部节点链接协议（包括但不限于 `hysteria2`、`tuic`、`anytls` 等）
* ✅ 解析能力与 Mihomo 内核自动对齐，无需手动补丁式维护
* ✅ 新协议可随 Mihomo 更新同步获得支持

#### 3. GitHub 原生文件地址回落 🌐

当远程外部配置、规则集或 `!!import` 引用的是 GitHub 原生文件地址时，后端会优先访问原始 GitHub 原始地址；当原始地址因网络问题无法正常获取时，自动改用 `cdn.jsdelivr.net` 加速地址重试。非 GitHub 地址不受影响。  

此项改进旨在优化中国大陆地区的自部署用户使用托管在 GitHub 上的模板和规则时的访问性能。  

支持的 GitHub 文件地址形式包括：

```text
https://raw.githubusercontent.com/<owner>/<repo>/<ref>/<path>
https://github.com/<owner>/<repo>/raw/<ref>/<path>
https://github.com/<owner>/<repo>/blob/<ref>/<path>
```

#### 4. COCR 取源与外部配置失败策略 🔁

本项目不再捆绑、构建、打包或通过自身路由发布 `Custom_OpenClash_Rules` 文件，也不会改写生成配置中的规则集 URL。部署者应在独立站点托管所需文件；原 `/Custom_OpenClash_Rules/main/...` 路由固定不可用。

服务端抓取行为由两个互相独立的开关控制：

| 配置项 | 默认值 | 行为 |
| :--- | :--- | :--- |
| `custom_openclash_rules.fallback_enabled` | `false` | 开启后，仅在服务端发起 GET 请求前，将可明确识别的官方 COCR `main` 分支 GitHub/jsDelivr 地址切换为 `https://git.asailor.org/Custom_OpenClash_Rules/main/...`；不改变输出 URL，也不拒绝其他地址 |
| `common.fallback_to_default_external_config` | `false` | 开启后，用户显式指定的 `config` 加载失败时，允许再尝试一次 `default_external_config`；缺失或关闭时直接返回错误 |

外部配置采用完整加载后再应用的原子语义：显式 `config` 获取、模板渲染、解析、导入或资源限制检查失败时返回 HTTP `400`，不会继续生成语义不同的配置；未显式指定 `config` 时，默认外部配置失败返回 HTTP `500`。这两类错误响应均带有 `Cache-Control: private, no-store`。规则集中单条无效、不支持或无法转换的规则仍按原有行为跳过，不会因此令整份规则集或整次订阅失败。

升级兼容性说明：旧版 INI/YAML/TOML 缺少上述新参数时按 `false` 处理，并支持热重载；旧 `custom_openclash_rules.publish_enabled` 可继续留在配置中但已被忽略。以下变化属于有意不兼容行为：

* COCR 文件不再出现在源码树、便携包、APK 或容器镜像中，旧发布路由返回 `404`，旧 OCI COCR revision 标签被移除。
* `fallback_enabled=true` 不再表示本地文件回落或路由发布，而只表示上述服务端取源地址切换。
* 用户显式选择的外部配置失败时默认不再静默回落；若部署者确实需要旧式默认配置回落，必须显式启用 `fallback_to_default_external_config`。
* 外部配置中的失败导入现在会令该外部配置整体加载失败；已成功加载的配置和正常 ruleset 单条过滤行为不变。

取源切换不会新增 SSRF、协议、私网地址、userinfo、URL 编码或凭据限制；原有抓取安全检查仍先作用于用户提供的原始 URL。

#### 5. 请求诊断台 🔎

内置 `explain=true` 诊断模式和 `/inspect` 网页诊断台，方便在不改变实际转换逻辑的前提下排查请求：

* ✅ 展示请求参数是否被识别、是否生效、是否被项目安全逻辑覆盖
* ✅ 汇总外部配置、规则集、自定义组、Provider、输出大小等关键状态
* ✅ 对订阅来源等敏感信息只展示长度、数量和安全结构摘要，便于排障时降低泄露风险

#### 6. 运行仪表盘 📊

启用统计后，`/dashboard` 可展示服务运行期转换统计，适合公开服务部署者观察后端使用情况：

* ✅ 展示本次启动、历史总计、最近 24 小时和滚动时间窗口统计、访问者地理位置分布
* ✅ 按请求数和规则转换数展示国家 / 地区分布与排行
* ✅ 支持统计数据持久化和可选 Basic Auth 验证，便于公网部署时限制访问

#### 7. 兼容性保证 🤝

* ✅ **无缝切换**：兼容常见传统 subconverter API 接口，客户端侧几乎无需学习成本即可迁移
* ✅ **模板兼容**：继续沿用传统外部模板，由后端内置逻辑确保 `proxy-provider` 模式在分流规则中正确生成
* ✅ **自动跟进**：编译时自动遍历 [Mihomo 内核源码仓库](https://github.com/MetaCubeX/mihomo/meta)，提取最新解析模块、协议格式与可覆写参数

#### 8. 新手友好 👶

* ✅ 使用 **[Custom_OpenClash_Rules](https://github.com/Aethersailor/Custom_OpenClash_Rules)** 远程配置模板，替代默认内置模板与自定义代理组功能
* ✅ 锁定 API 模式，强制关闭相关接口，降低新手误配置带来的安全风险
* ✅ 精简参数设计，聚焦高频核心场景

---

## 🚀 快速开始

### 🌍 使用演示实例（无需部署）

如果你不想自行部署，可以直接使用演示实例：

> [!TIP]
> **地址**：`https://api.asailor.org`
>
> ![Website](https://img.shields.io/website?url=https%3A%2F%2Fapi.asailor.org%2Fversion&up_message=%E5%9C%A8%E7%BA%BF&down_message=%E7%A6%BB%E7%BA%BF&style=for-the-badge&label=%E5%90%8E%E7%AB%AF%E6%9C%8D%E5%8A%A1%E5%BD%93%E5%89%8D%E7%8A%B6%E6%80%81)

OpenClash 已内置该演示实例地址；在其他支持自定义后端的订阅转换网站或客户端中，也可以直接填入该地址进行调用。

> [!IMPORTANT]
> 默认输出为**最简配置**，不包含 DNS 参数，请在 Clash 客户端中启用 DNS 覆写功能。
> 例如：`OpenClash > 覆写设置 > 自定义上游 DNS 服务器`
> 否则将无法解析节点域名，导致全部节点无法连接。

### 🚀 自行部署

推荐优先使用 Docker 部署；如果部署环境不方便运行容器，可以根据 [Release](https://github.com/Aethersailor/SubConverter-Extended/releases/latest) 中的安装包类型选择便携包或 OpenWrt APK。

> [!IMPORTANT]
> 如果服务需要被其他设备访问，请将配置中的 `managed_config_prefix` 改为实际访问地址，例如 `http://192.168.1.10:25500` 或 `https://sub.example.com`。公网部署还建议在配置中启用 `public` 安全档位，详见下方“配置说明”。

#### 安装包类型速查

| 类型 | 文件 / 镜像 | 适用场景 |
| :--- | :--- | :--- |
| Docker 镜像 | `aethersailor/subconverter-extended`、`ghcr.io/aethersailor/subconverter-extended` | 服务器、NAS、软路由容器环境 |
| Linux 便携包 | `SubConverter-Extended-<version>-linux-amd64.tar.gz`、`linux-arm64.tar.gz`、`linux-armv7.tar.gz` | 不使用 Docker 的 Linux 主机 |
| Windows 便携包 | `SubConverter-Extended-<version>-windows-amd64.zip` | Windows x64 主机 |
| OpenWrt APK | `SubConverter-Extended-<version>-openwrt-<arch>.apk` | 使用 `apk` 包管理器的 OpenWrt 25.12+ |
| 校验文件 | `SHA256SUMS` | 校验 Release 下载文件完整性 |

<details>
<summary><strong>Docker 部署（推荐）</strong></summary>

Docker 镜像支持以下平台：

* `linux/amd64`
* `linux/arm64`
* `linux/arm/v7`

#### 一键试运行

```bash
docker run -d \
  --name SubConverter-Extended \
  -p 25500:25500 \
  --restart unless-stopped \
  aethersailor/subconverter-extended:latest
```

访问 `http://localhost:25500/version` 验证服务是否正常启动。

> [!NOTE]
> 上述命令适合快速体验，不会持久化自定义配置和 `/dashboard` 统计数据。删除容器后，这些容器内数据会一并删除；长期运行请使用下方的持久化部署方式。
>
> `-p 25500:25500` 会把端口发布到宿主机全部接口，以便局域网设备访问；这表示服务“可能被外部访问”，但不能单凭该参数认定已经暴露公网。请同时检查宿主防火墙、云安全组、NAT 和反向代理。只需本机访问时可改为 `-p 127.0.0.1:25500:25500`；确认公网可达时应显式选择 `public` 或 `strict`。

#### 持久化配置和统计数据

Docker 部署建议持久化以下内容：

* 宿主机 `/opt/SubConverter-Extended/base/pref.toml` → 容器 `/base/pref.toml`
* 宿主机 `/opt/SubConverter-Extended/stats` → 容器 `/base/stats`

容器内的统计目录是 `/base/stats`，不是 `/stats`。不建议直接将整个宿主机目录挂载到容器 `/base`，否则会遮盖镜像内随版本更新的规则、模板等内置文件。

```bash
# 创建持久化目录；重复执行不会删除已有配置和统计数据
mkdir -p /opt/SubConverter-Extended/base /opt/SubConverter-Extended/stats

cd /opt/SubConverter-Extended

# 仅在配置不存在时下载默认配置，避免覆盖已有设置
if [ ! -f base/pref.toml ]; then
  wget -O base/pref.toml \
    https://gcore.jsdelivr.net/gh/Aethersailor/SubConverter-Extended@master/base/pref.example.toml
fi

# 如需外部访问，请修改 base/pref.toml 中的 managed_config_prefix
# 如需启用运行统计，请将 [statistics] 下的 enabled 改为 true

# 启动容器并挂载配置文件和统计目录
docker run -d \
  --name SubConverter-Extended \
  -p 25500:25500 \
  -v /opt/SubConverter-Extended/base/pref.toml:/base/pref.toml:ro \
  -v /opt/SubConverter-Extended/stats:/base/stats \
  --restart unless-stopped \
  aethersailor/subconverter-extended:latest
```

也可以在上述 `docker run` 命令中按需加入环境变量，覆盖常用配置：

```text
-e MANAGED_CONFIG_PREFIX="http://your-domain-or-ip:25500" \
-e SUBCONVERTER_SECURITY_PROFILE=public \
-e SUBCONVERTER_ALLOW_PUBLIC_UPLOAD=false
```

更新 Docker 镜像时，保留宿主机上的 `base/pref.toml` 和 `stats`，拉取新镜像后重新创建容器即可：

```bash
docker pull aethersailor/subconverter-extended:latest
docker rm -f SubConverter-Extended
# 然后重新执行上面的 docker run 命令
```

#### Docker Compose

```bash
# 创建持久化目录；重复执行不会删除已有配置和统计数据
mkdir -p /opt/SubConverter-Extended/base /opt/SubConverter-Extended/stats

cd /opt/SubConverter-Extended

# 仅在文件不存在时下载 Compose 示例和默认配置，避免覆盖已有设置
if [ ! -f docker-compose.yml ]; then
  wget -O docker-compose.yml \
    https://gcore.jsdelivr.net/gh/Aethersailor/SubConverter-Extended@master/docker-compose.yml
fi

if [ ! -f base/pref.toml ]; then
  wget -O base/pref.toml \
    https://gcore.jsdelivr.net/gh/Aethersailor/SubConverter-Extended@master/base/pref.example.toml
fi

# 如需外部访问，请修改 docker-compose.yml 中的 MANAGED_CONFIG_PREFIX，
# 或修改 base/pref.toml 中的 managed_config_prefix
# 如需启用运行统计，请将 [statistics] 下的 enabled 改为 true

# 启动容器
docker compose up -d
```

仓库提供的 `docker-compose.yml` 已包含以下持久化挂载：

```yaml
volumes:
  - ./base/pref.toml:/base/pref.toml:ro
  - ./stats:/base/stats
```

Compose 示例为了保持既有局域网部署体验，继续使用 `25500:25500`。这不会自动把安全档位切为 `public`，也不等于程序能够判断公网是否可达；只允许宿主机访问时，可将端口映射手动改为 `127.0.0.1:25500:25500`。

更新 Compose 部署：

```bash
cd /opt/SubConverter-Extended
docker compose pull
docker compose up -d
```

只要不删除宿主机上的 `/opt/SubConverter-Extended/base/pref.toml` 和 `/opt/SubConverter-Extended/stats`，更新镜像或重建容器都不会丢失配置和历史统计。

常用维护命令：

```bash
docker logs -f SubConverter-Extended
docker restart SubConverter-Extended
docker rm -f SubConverter-Extended
```

</details>

<details>
<summary><strong>Linux 便携包部署</strong></summary>

Linux 便携包适用于不方便运行 Docker 的 Linux 主机。Release 提供 `amd64`、`arm64`、`armv7` 三类包，包内已包含启动脚本和运行时依赖。

#### 选择架构

```bash
uname -m
```

常见对应关系：

| `uname -m` 输出 | 选择的包 |
| :--- | :--- |
| `x86_64` | `linux-amd64.tar.gz` |
| `aarch64` / `arm64` | `linux-arm64.tar.gz` |
| `armv7l` / `armv7` | `linux-armv7.tar.gz` |

#### 下载并解压

```bash
# 将 VERSION 替换为 Release 页面中的实际版本号，例如 v1.1.13
VERSION=v1.1.13
ARCH=amd64
INSTALL_DIR=/opt/SubConverter-Extended

mkdir -p "$INSTALL_DIR"
cd /tmp

curl -fLO "https://github.com/Aethersailor/SubConverter-Extended/releases/download/${VERSION}/SubConverter-Extended-${VERSION}-linux-${ARCH}.tar.gz"
curl -fLO "https://github.com/Aethersailor/SubConverter-Extended/releases/download/${VERSION}/SHA256SUMS"
sha256sum -c SHA256SUMS --ignore-missing

tar -xzf "SubConverter-Extended-${VERSION}-linux-${ARCH}.tar.gz" \
  -C "$INSTALL_DIR" \
  --strip-components=1
```

#### 启动服务

```bash
cd /opt/SubConverter-Extended
chmod +x start.sh subconverter

# 首次启动会自动从 base/pref.example.toml 创建 base/pref.toml
./start.sh
```

访问 `http://localhost:25500/version` 验证服务是否正常启动。

#### 使用 systemd 常驻运行

```bash
cat >/etc/systemd/system/subconverter-extended.service <<'EOF'
[Unit]
Description=SubConverter-Extended
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/SubConverter-Extended
ExecStart=/opt/SubConverter-Extended/start.sh
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now subconverter-extended
systemctl status subconverter-extended
```

如需把配置文件放在其他位置，可以通过 `PREF_PATH` 指定：

```bash
PREF_PATH=/etc/subconverter/pref.toml /opt/SubConverter-Extended/start.sh
```

</details>

<details>
<summary><strong>Windows 便携包部署</strong></summary>

Windows 便携包适用于 Windows x64 环境，文件名为 `SubConverter-Extended-<version>-windows-amd64.zip`。

#### 部署步骤

1. 从 [Release](https://github.com/Aethersailor/SubConverter-Extended/releases/latest) 下载 `windows-amd64.zip`。
2. 解压到固定目录，例如 `C:\SubConverter-Extended`。
3. 双击运行 `start.bat`，或在 PowerShell 中运行：

```powershell
cd C:\SubConverter-Extended
.\start.ps1
```

如果 PowerShell 执行策略阻止脚本运行，可以改用：

```powershell
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

首次启动时，启动脚本会按顺序查找 `base\pref.toml`、`base\pref.yml`、`base\pref.ini`；如果都不存在，会自动从示例配置创建 `base\pref.toml`。

访问 `http://localhost:25500/version` 验证服务是否正常启动。首次运行时如果 Windows 防火墙弹窗，请按实际访问范围放行。

#### 使用自定义配置路径

PowerShell：

```powershell
$env:PREF_PATH = "D:\subconverter\pref.toml"
& C:\SubConverter-Extended\start.ps1
```

CMD：

```cmd
set PREF_PATH=D:\subconverter\pref.toml
C:\SubConverter-Extended\start.bat
```

</details>

<details>
<summary><strong>OpenWrt APK 部署</strong></summary>

OpenWrt APK 包适用于使用 `apk` 包管理器的 OpenWrt 25.12+。该包未签名，安装时需要使用 `--allow-untrusted`。

#### 选择架构

```sh
apk print-arch
```

下载与输出完全匹配的 APK，例如：

| `apk print-arch` 输出 | 选择的包 |
| :--- | :--- |
| `x86_64` | `openwrt-x86_64.apk` |
| `aarch64_generic` | `openwrt-aarch64_generic.apk` |
| `aarch64_cortex-a53` | `openwrt-aarch64_cortex-a53.apk` |
| `aarch64_cortex-a72` | `openwrt-aarch64_cortex-a72.apk` |
| `arm_cortex-*` | 对应同名 `openwrt-arm_cortex-*.apk` |

#### 下载并安装

```sh
# 将 VERSION 替换为 Release 页面中的实际版本号，例如 v1.1.13
VERSION=v1.1.13
ARCH="$(apk print-arch)"
PKG="/tmp/SubConverter-Extended-${VERSION}-openwrt-${ARCH}.apk"

wget -O "$PKG" \
  "https://github.com/Aethersailor/SubConverter-Extended/releases/download/${VERSION}/SubConverter-Extended-${VERSION}-openwrt-${ARCH}.apk"

apk add --allow-untrusted "$PKG"
```

#### 启动服务

```sh
/etc/init.d/subconverter-extended enable
/etc/init.d/subconverter-extended start
```

访问 `http://路由器IP:25500/version` 验证服务是否正常启动。

OpenWrt APK 的默认用户配置位于 `/etc/subconverter/pref.toml`。首次启动时会自动创建该文件，后续升级不会覆盖已有配置。

常用维护命令：

```sh
/etc/init.d/subconverter-extended restart
/etc/init.d/subconverter-extended stop
logread -e subconverter
```

</details>

---

## 📚 使用说明

整体使用方式与原版 subconverter 基本一致，常见客户端和订阅转换前端通常无需额外适配即可迁移。

下方仅重点说明本项目的高频参数、特有能力，以及与原版 subconverter 行为不同的部分；未列出的兼容参数仍可按原版 subconverter 的使用习惯传入。

> [!IMPORTANT]
> 默认输出为**最简配置**，不包含 DNS 参数，请在各 Clash 客户端中启用 DNS 覆写功能，或在生成的配置文件中自行补全 DNS 配置。

<details open>
<summary><strong>快速调用与常用参数</strong></summary>

### 常用参数一览

| 参数 | 说明 | 示例 |
| :--- | :--- | :--- |
| `target` | 目标格式；完整支持 `clash`, `clashr`, `surge`, `quan`, `quanx`, `loon`, `surfboard`, `mellow`, `singbox`, `ss`, `ssd`, `ssr`, `sssub`, `v2ray`, `v2rayn`, `v2rayng`, `trojan`, `vless`, `hysteria2`, `mixed` | `clash`, `v2rayn`, `v2rayng`, `vless`, `hysteria2` |
| `url` | 订阅链接或节点链接（`\|` 分隔） | `https://sub.com\|vless://...` |
| `config` | 外部配置文件 | `https://config-url` |
| `include` | 包含节点（正则） | `香港\|台湾` |
| `exclude` | 排除节点（正则） | `过期\|剩余` |
| `emoji` | 添加 Emoji | `true` / `false` |
| `explain` | 返回本次转换的 JSON 诊断报告 | `true` |
| `provider_proxy_direct` | 所有未单独覆盖的 proxy-provider 是否生成 `proxy: DIRECT` | `true` / `false` |

### 常见调用示例

```text
https://api.asailor.org/sub?target=clash&url=https%3A%2F%2Fexample.com%2Fsub&config=https%3A%2F%2Fexample.com%2Fconfig.ini
```

```text
https://api.asailor.org/sub?target=clash&url=provider%3AHK%2Chttps%3A%2F%2Fexample.com%2Fsub&include=%E9%A6%99%E6%B8%AF&emoji=true
```

</details>

<details>
<summary><strong>诊断与排障</strong></summary>

### `explain=true` 诊断模式

在 `/sub` 请求中追加 `explain=true` 后，后端会按同一组参数执行转换流程，但返回 JSON 诊断报告，而不是返回 Clash/Surge/QuanX 配置文件。

示例：

```text
https://api.asailor.org/sub?target=clash&url=https%3A%2F%2Fexample.com%2Fsub&explain=true
```

这个模式适合排查“参数是否生效”“是否进入 `proxy-provider` 模式”“外部配置是否加载成功”“规则集和节点数量是否符合预期”等问题。报告会包含目标格式、模式开关、输入数量、外部配置状态、规则集统计、provider 数量和输出大小等信息。

**说明：**

* `explain=true` 只改变响应内容，不改变实际转换逻辑。
* 如果同一请求里包含上传参数，诊断模式会抑制上传，避免排障时产生托管配置写入。
* 诊断报告不会直接回显原始订阅地址；来源摘要只保留协议、安全的 HTTP(S) 主机名和原始长度，不保留查询串、路径、凭据或稳定短哈希。

### `/inspect` 请求诊断台

如果不方便直接阅读 `explain=true` 返回的 JSON，可以访问 `/inspect` 打开网页诊断台：

```text
https://api.asailor.org/inspect
```

自部署环境可访问：

```text
http://localhost:25500/inspect
```

诊断台支持粘贴完整 `/sub?...` 链接、完整 URL，或仅粘贴查询参数。页面会自动补充 `explain=true` 并以只读方式发起诊断请求，然后展示摘要、已识别参数、未识别参数、生效配置、Provider 信息和原始 JSON。

这个页面适合排查以下问题：

* 某个请求参数是否被识别、是否生效、是否被覆盖或抑制
* `list=true` 等参数是否被项目强制改写为 `proxy-provider` 模式
* `include` / `exclude`、`emoji`、`new_name`、`config` 等外部参数最终是否参与转换
* 外部配置、规则集、自定义组、Provider 是否按预期加载或生成

**说明：**

* `/inspect` 只是 `explain=true` 诊断报告的可视化界面，不会改变实际转换逻辑。
* 诊断结果区和原始 JSON 不会回显已识别的敏感值，只展示长度、数量、是否生效及安全结构摘要。输入框和“规范化请求”预览仍会保留你粘贴的原始请求；截图或分享页面前请先清空或遮盖。
* 请求诊断台会保留原始 JSON 区域，方便复制给维护者进一步分析。

</details>

<details>
<summary><strong>/dashboard 运行仪表盘</strong></summary>

### `/dashboard` 使用方法

`/dashboard` 用于查看运行期转换统计。该功能默认关闭；只有在配置文件中启用 `statistics.enabled` 后，服务才会注册 `/dashboard` 和 `/dashboard/data` 路由。

启用后可访问：

```text
http://localhost:25500/dashboard
```

公网或反代部署时，请替换为实际域名：

```text
https://sub.example.com/dashboard
```

`/dashboard/data` 会返回仪表盘使用的 JSON 数据，适合接入外部监控或自行排查：

```text
http://localhost:25500/dashboard/data
```

仪表盘主要展示：

* 服务启动时间、本次运行时长、累计运行时长和启动次数
* 成功 `/sub` 转换请求数与规则转换数
* 最近 24 小时请求 / 规则转换柱状图
* 按 1 小时、1 天、7 天、30 天、半年、1 年和历史总计统计的国家 / 地区分布与排行
* 当可信边缘网关提供地区请求头时，展示中国地区请求 / 规则转换地图和排行

**说明：**

* 统计只在 `statistics.enabled=true` 后开始写入，启用前的历史请求不会回补。
* 统计模块只记录成功的 `GET /sub` 转换请求和规则转换计数，不存储订阅链接、节点内容或访问者 IP。
* 国家 / 地区来源于配置的国家码请求头；中国地区来源于配置的地区请求头；无法识别时会归为未知。
* Docker 部署如需跨重启保留统计数据，请将 `data_dir` 对应目录挂载为卷，例如 `./stats:/base/stats`。

### 启用示例（TOML）

修改 `base/pref.toml` 后重启服务：

```toml
[statistics]
enabled = true
data_dir = "stats"
flush_interval = 5

[statistics.geo]
provider = "header"
country_headers = ["CF-IPCountry", "X-Geo-Country", "X-Vercel-IP-Country", "CloudFront-Viewer-Country"]
china_region_headers = ["CF-Region-Code", "cf-region-code", "X-Geo-Subdivision"]

[statistics.dashboard_auth]
enabled = true
username = "admin"
password = "change-this-password"
max_failures = 5
window_seconds = 300
lock_seconds = 900

# 可选：仅当后端只允许本机 Nginx/Caddy 访问，且代理覆盖 X-Forwarded-For 时启用。
[statistics.dashboard_auth.client_ip]
header = "x-forwarded-for"
trusted_proxy_cidrs = ["127.0.0.1/32", "::1/128"]
```

Dashboard 防爆破默认只使用服务端观察到的 TCP socket peer。`CF-Connecting-IP`、`True-Client-IP`、`X-Real-IP`、`X-Forwarded-For`、`Forwarded` 和 `X-Client-IP` 等客户端自带头不会改变默认分桶，因此直连客户端无法通过轮换这些头绕过失败计数。

只有 `client_ip.header` 与 `trusted_proxy_cidrs` 同时有效时，服务才会解析所选的**一个**头；peer 不在可信 CIDR、头缺失/重复/非法/过长、XFF/Forwarded 链超过 16 跳时都会安全降级到 socket peer。IP 会严格解析并规范化，IPv4-mapped IPv6 与对应 IPv4 共用一个桶；桶数量固定有上限，达到上限后的新来源进入共享溢出桶，不会驱逐已有攻击状态。

代理部署边界：

* 直连、Docker `ports` 直接暴露或 Compose 未设独立入口代理：保持 `header="none"`，不要填写可信网段。
* 单层 Nginx/Caddy：只加入实际连接后端的代理地址/CIDR，并让代理先删除客户端同名头、再写入选定头。不要把整个 Docker 宿主网或可被其他容器加入的宽泛网段视为可信。
* 多层代理/CDN：每一层都必须覆盖或按约定追加所选头；`X-Forwarded-For` 与 `Forwarded` 从右向左跳过可信 hop，取第一个不可信地址。所有 hop 都可信或整条链有任一非法项时回退 peer。
* Cloudflare/CDN：仅当源站防火墙保证只能由该 CDN 官方出口访问，并持续维护对应 CIDR 时，才可选择 `cf-connecting-ip`、`true-client-ip` 等单 IP 头。不要为了省事配置 `0.0.0.0/0` 或 `::/0`；程序会拒绝启动/拒绝热重载该配置。

地理统计使用的国家/地区头仍是独立功能；启用 Dashboard 客户端 IP 策略不会扩大地理头的信任范围，也不会改变 `/sub`、Basic Auth 或统计数据格式。

### 新增配置项说明

| TOML / YAML 配置项 | INI 配置项 | 默认值 | 说明 |
| :--- | :--- | :--- | :--- |
| `statistics.enabled` | `enabled` | `false` | 是否启用运行期统计和 `/dashboard`。关闭时不会注册 `/dashboard` 与 `/dashboard/data`。 |
| `statistics.data_dir` | `data_dir` | `stats` | 统计数据目录，按程序工作目录解析；Docker 中可挂载 `/base/stats` 持久化。 |
| `statistics.flush_interval` | `flush_interval` | `5` | 统计数据最小写盘间隔，单位为秒。 |
| `statistics.geo.provider` | `geo_provider` | `header` | 国家 / 地区识别方式。`header` 表示读取国家码请求头，`none` 表示全部记为未知。 |
| `statistics.geo.country_headers` | `country_headers` | `CF-IPCountry`, `X-Geo-Country`, `X-Vercel-IP-Country`, `CloudFront-Viewer-Country` | `provider=header` 时依次尝试读取的国家码请求头。 |
| `statistics.geo.china_region_headers` | `china_region_headers` | `CF-Region-Code`, `cf-region-code`, `X-Geo-Subdivision` | 可信边缘网关注入中国地区码时依次尝试读取的请求头，用于中国地区地图和排行。 |
| `statistics.dashboard_auth.enabled` | `dashboard_auth_enabled` | `false` | 是否为 `/dashboard` 和 `/dashboard/data` 启用 Basic Auth。 |
| `statistics.dashboard_auth.username` | `dashboard_auth_username` | 空 | Basic Auth 用户名。启用认证后不能为空。 |
| `statistics.dashboard_auth.password` | `dashboard_auth_password` | 空 | Basic Auth 密码。启用认证后不能为空；公网部署建议配合 HTTPS。 |
| `statistics.dashboard_auth.max_failures` | `dashboard_auth_max_failures` | `5` | 在统计窗口内允许的失败登录次数。 |
| `statistics.dashboard_auth.window_seconds` | `dashboard_auth_window_seconds` | `300` | 失败登录统计窗口，单位为秒。 |
| `statistics.dashboard_auth.lock_seconds` | `dashboard_auth_lock_seconds` | `900` | 超过失败次数后的锁定时长，单位为秒。 |
| `statistics.dashboard_auth.client_ip.header` | `dashboard_auth_client_ip_header` | `none` | Dashboard 防爆破使用的单一代理头；支持 `x-forwarded-for`、`forwarded`、`x-real-ip`、`cf-connecting-ip`、`true-client-ip`。不支持 `X-Client-IP`。 |
| `statistics.dashboard_auth.client_ip.trusted_proxy_cidrs` | `dashboard_auth_trusted_proxy_cidrs` | 空 | 允许提供所选客户端 IP 头的 socket peer CIDR；最多 64 项，不允许 `/0`。INI 与环境变量使用逗号分隔。 |

**提示：** `pref.yml` 使用同名嵌套字段；`pref.ini` 的上述 INI 配置项均写在 `[statistics]` 段内。环境变量 `SUBCONVERTER_DASHBOARD_CLIENT_IP_HEADER` 与 `SUBCONVERTER_DASHBOARD_TRUSTED_PROXY_CIDRS` 可覆盖文件配置。升级后默认行为是只按 socket peer 分桶；需要区分代理后的客户端时再显式启用。回滚时先恢复 `header=none`/清空可信 CIDR 并重载或重启，再回退程序版本。

</details>

<details>
<summary><strong>客户端远程订阅资源：Clash Proxy-Provider、Quantumult X server_remote、Surge 与 Surfboard policy-path</strong></summary>

### `provider` 前缀

`provider` 不是独立参数，而是写在 `url=` 列表中、放在订阅链接前，并以逗号分隔。Clash/ClashR 使用它自定义 `proxy-providers` 名称；Quantumult X 使用它自定义 `[server_remote]` 资源标签；Surge 和 Surfboard 使用它匹配自定义策略组中的 `!!PROVIDER` 选择器。该前缀对节点链接不生效。

示例：

```text
url=provider:HK,https://example.com/sub
url=provider:HK,https://a|provider:HK,https://b
url=provider%3AHK%2Chttps%3A%2F%2Fexample.com%2Fsub
```

**说明：** 在 OpenClash 这类预置“订阅地址”输入框的软件中，无需填写开头的 `url=`，直接填入等号后的内容即可。

补充说明：

* 支持中文名称；非法字符或空值会回退为默认 `Provider_<MD5>`
* 重名时会自动追加 `_1`、`_2` 等后缀

### `interval` 前缀

部署者可以在主配置文件中设置所有新生成 `proxy-provider` 的默认订阅更新间隔，单位为秒。该配置节完全可选；现有配置文件缺少它时仍可正常启动，并继续使用 `3600`：

```toml
[proxy_provider]
interval = 3600
proxy_direct = true
```

```yaml
proxy_provider:
  interval: 3600
  proxy_direct: true
```

```ini
[proxy_provider]
interval=3600
proxy_direct=true
```

用户需要为某一条订阅单独设置间隔时，在该订阅前添加 `interval:<秒数>,`。它与 `provider:`、`tag:` 前缀可以任意排序：

```text
url=provider:A,interval:0,https://a.example/sub|provider:B,interval:21600,https://b.example/sub|provider:C,https://c.example/sub
```

对于 Clash/ClashR，以上示例中的 A 明确生成 `interval: 0`，B 生成 `interval: 21600`，C 使用主配置文件中的默认值。未配置主配置节时，C 使用 `3600`。

`interval:0` 不会省略 YAML 字段，而是明确生成：

```yaml
interval: 0
```

在 Mihomo 中，这表示关闭该 provider 的周期订阅更新：没有有效缓存时仍会在初始化时拉取一次；已有有效缓存时直接使用缓存；通过控制器或客户端界面发起的手动刷新仍然有效。`health-check.interval` 是节点健康检查周期，不受此设置影响，项目仍默认生成 `300`。

> [!WARNING]
> 使用固定自定义 provider 名称时，缓存路径也会保持不变。更换订阅 URL 后，如果同时使用 `interval:0`，Mihomo 可能继续使用已有缓存，直到用户手动刷新或清理对应缓存文件。

补充说明：

* 有效范围是 `0` 到 `2147483647` 的十进制整数；不支持 `none`、负数或 `1h` 等单位写法
* 同一条订阅重复设置 `interval:` 会返回 HTTP 400
* `interval:` 不适用于节点 URI 或 `list=true`；当前支持 Clash/ClashR、Quantumult X 与 Surge 远程订阅
* 不提供请求级的全局 `provider_interval` 参数
* 已有顶层请求参数 `&interval=` 仍用于托管配置的更新提示，与 `proxy-provider` 的更新周期无关

### Quantumult X `[server_remote]`

`target=quanx` 生成完整配置时，HTTP(S) 订阅默认写入 `[server_remote]`，由 Quantumult X 下载和解析；SubConverter-Extended 不会预先下载这些订阅。节点 URI 仍由 Legacy 解析器处理并写入 `[server_local]`，两类输入可以混用。

```text
url=provider:Airport-A,https://a.example/sub|ss://example-node
```

逐条提供 `interval:` 时，Quantumult X 输出使用 `update-interval`。正整数保持原值；`interval:0` 会转换为 `update-interval=-1`，表示关闭自动同步。省略时不生成该字段，由 Quantumult X 使用客户端默认同步间隔。

为避免静默丢失旧功能，只要最终有效配置仍要求服务端处理节点，例如 `include`/`exclude`、`filter_script`、节点改名、Emoji 增删、排序、弃用节点过滤、UDP/TFO/证书/TLS 选项覆盖，或策略组、`!!import:` 无法等价下放，请求就会在下载前确定为旧版 Legacy 路径。`list=true` 也继续由服务端展开订阅。以上判断不是远程解析失败后的回退。

新版示例配置默认不再启用节点改名与旧 Emoji 清理，使新部署可以直接使用 `[server_remote]`。已有配置文件不会被改写；其中已启用的节点预处理会继续触发 Legacy，保持原有结果。部署者确认不再需要这些处理后，可自行关闭对应选项以启用客户端远程读取。

`[server_remote]` 不会自动启用 `opt-parser`，也不会注入第三方 `resource_parser_url`。上游需要根据 Quantumult X 的 User-Agent 返回客户端可识别的节点资源；需要自定义资源解析器时，应由部署者在 Quantumult X 基础配置中自行配置并评估脚本来源。

该能力不增加主配置文件字段，旧版 `pref.ini`、`pref.yml` 和 `pref.toml` 无需迁移，也不会因缺少新参数而启动失败。

### Surge `policy-path`

`target=surge` 生成 Surge 3 或更高版本的完整配置时，符合条件的单个 HTTP(S) 订阅会写入策略组的 `policy-path`，由 Surge 下载和解析。SubConverter-Extended 不会下载或检查远程订阅内容；订阅服务商需要直接返回 Surge 可读取的代理列表或完整 Surge 配置。Surge 2 输出继续使用 Legacy。

```ini
[Proxy Group]
Proxy = select,policy-path=https://example.com/surge.conf,policy-regex-filter=".*"
```

节点 URI 仍由 Legacy 解析器处理。Surge 生成器能够表示的节点会写入 `[Proxy]`；例如 VLESS 等 Surge 不能表示的协议会被统计并跳过。请求只包含不受支持的节点且没有 `policy-path` 时，接口返回 HTTP 400。远程订阅与节点 URI 混用时，`policy-path` 继续生成，不受支持的本地节点不会进入 `[Proxy]`；日志事件 `SURGE_NODE_GENERATION` 和 Explain 报告会列出数量及协议。旧配置仍含全局节点处理选项时，`SURGE_POLICY_PATH_TRANSFORM_SCOPE` 会用数量说明远程节点由客户端处理、服务端处理只作用于直连节点，不记录规则正文或节点名称。

第一版仅对一个远程订阅启用 `policy-path`。多个远程订阅、`list=true`、`!!import:`、本次请求或用户显式外部配置要求的服务端节点过滤、改名、Emoji 增删、排序、节点选项覆盖，以及无法准确转换的策略组选择器，会在下载订阅前确定使用 Legacy。该行为不是远程解析失败后的再次尝试，不会先调用 Surge 再回退。

主配置中已有的全局节点整理选项不会阻止 Surge 使用 `policy-path`，也不会作用于 Surge 自行下载的远程节点；它们仍作用于本项目实际解析的直连节点。这样旧配置无需关闭全局重命名、Emoji 清理或排序即可进入客户端远程读取，同时请求中明确提出的节点处理要求仍不会被静默忽略。

逐条提供正数 `interval:` 时，Surge 输出使用 `update-interval`。省略时不生成该字段，由客户端使用默认值。Surge 的 `interval:0` 返回 HTTP 400；需要客户端默认更新行为时，应省略该前缀。

部署者可以使用以下可选配置关闭 Surge 原生远程订阅：

```toml
[remote_subscription]
surge_policy_path = false
```

YAML 使用 `remote_subscription.surge_policy_path`，INI 使用 `[remote_subscription]` 下的 `surge_policy_path`。缺少整个配置节或字段时，默认值为 `true`。旧配置文件无需增加字段即可启动；配置热重载时，删除该字段也会恢复为默认值。无法准确表达的复杂策略组仍使用 Legacy；需要强制保留全部服务端节点预处理时，可将该开关设为 `false`。

`target=clash` 和 `target=clashr` 的 Mihomo 解析与 `proxy-provider` 分流不读取这个开关。Quantumult X 的 `[server_remote]` 与 Surfboard 的 `policy-path` 分流也不读取这个开关。

### Surfboard `policy-path`

`target=surfboard` 生成完整配置时，符合条件的单个 HTTP(S) 订阅会写入策略组的 `policy-path`，由 Surfboard 下载和解析。SubConverter-Extended 不会下载或检查远程订阅内容；订阅服务商需要直接返回 Surfboard 可读取的代理列表，或者包含 `[Proxy]` 的 Surfboard 配置。

```ini
[Proxy Group]
Proxy = select,policy-path=https://example.com/surfboard.conf,policy-regex-filter=".*"
```

节点 URI 仍由 Legacy 解析器处理，并在 Surfboard 能够表示时写入 `[Proxy]`。请求只包含 Surfboard 无法表示的节点且没有 `policy-path` 时返回 HTTP 400；远程订阅和节点 URI 可以混用。日志事件 `SURFBOARD_NODE_GENERATION` 与 Explain 报告会分别说明本地节点生成结果和实际远程后端。

Surfboard 的 `policy-regex-filter` 使用完整匹配。项目会把自定义组中原本按节点名称搜索的正则转换为等价的完整匹配表达式。Surfboard 策略组的测速 URL 只接受 HTTP；如果自定义组配置了 HTTPS 测速 URL，输出会改用 `http://www.gstatic.com/generate_204`，并记录不包含组名的 `SURFBOARD_TEST_URL_NORMALIZED` 日志。

第一版仅对一个远程订阅启用 `policy-path`。多个远程订阅、`list=true`、`!!import:`、本次请求或用户显式外部配置要求的服务端节点过滤、改名、Emoji 增删、排序、节点选项覆盖，以及无法准确转换的策略组选择器，会在下载订阅前确定使用 Legacy。主配置中已有的全局节点整理选项不会阻止 Surfboard 使用 `policy-path`，也不会作用于 Surfboard 自行下载的远程节点；这些选项仍作用于本项目实际解析的直连节点。

Surfboard 官方格式没有为 `policy-path` 定义独立的订阅更新间隔参数，因此 `interval:` 前缀不适用于 `target=surfboard`。顶层 `&interval=` 仍用于 `#!MANAGED-CONFIG` 的更新提示，单位为秒；Surfboard 要求该值至少为 900 秒。

部署者可以使用以下可选配置关闭 Surfboard 原生远程订阅：

```toml
[remote_subscription]
surfboard_policy_path = false
```

YAML 使用 `remote_subscription.surfboard_policy_path`，INI 使用 `[remote_subscription]` 下的 `surfboard_policy_path`。缺少整个配置节或字段时，默认值为 `true`；现有配置文件无需增加字段即可启动，配置热重载时删除该字段也会恢复默认值。

Surfboard 开关不影响 Clash/ClashR、Quantumult X、Surge 或其他目标。

### Loon `[Remote Proxy]`

`target=loon` 生成完整配置时，兼容的 HTTP(S) 订阅默认写入 `[Remote Proxy]`，由 Loon 下载并解析；SubConverter-Extended 不会预先下载远程订阅内容。订阅服务商需要根据 Loon 的请求返回客户端可识别的节点资源。节点 URI 仍由 Legacy 解析器处理并写入 `[Proxy]`，两类输入可以混用。

```ini
[Remote Proxy]
Airport_A = https://a.example/sub
Airport_B = https://b.example/sub
```

第一版支持多个远程订阅。`provider:` 用于指定资源别名；未指定时按请求顺序生成 `SubConverter_Remote_1`、`SubConverter_Remote_2`。别名会经过安全清理并避开基础模板中已有的本地节点、远程资源、筛选器和策略组名称，发生冲突时稳定追加数字后缀。远程 URL 不会被重复解码，配置分隔符逗号会保留为百分号编码。

普通节点名正则、`!!GROUP=`、`!!GROUPID=` 和 `!!PROVIDER=` 会转换为 `[Remote Filter]` 的 `NameRegex` 筛选器或直接引用远程资源。筛选正则使用双引号保护其中的配置分隔符；策略组引用最终的去重别名。`list=true`、`!!import:`、本次请求或用户显式外部配置要求的服务端节点过滤、改名、Emoji 增删、排序、节点选项覆盖，以及 Loon 无法准确表达的组类型或选择器，会在下载订阅前确定使用 Legacy，不会先走 Loon 再回退。

主配置中已有的全局节点整理选项不会阻止 Loon 使用 `[Remote Proxy]`，也不会作用于 Loon 自行下载的远程节点；它们仍作用于本项目解析的直连节点。日志事件 `LOON_REMOTE_TRANSFORM_SCOPE` 会以数量说明这一作用域，不记录规则正文、订阅凭据或节点名称。

Loon 的远程订阅路径不接受 `interval:` 或 `proxy_direct:` 前缀。请求只包含 Loon 生成器无法表示的本地节点时返回 HTTP 400；远程订阅与此类节点混用时，远程资源仍正常生成，不支持的本地协议会由 `LOON_NODE_GENERATION` 和 Explain 按协议计数。

部署者可以使用以下可选配置关闭 Loon 原生远程订阅：

```toml
[remote_subscription]
loon_remote_proxy = false
```

YAML 使用 `remote_subscription.loon_remote_proxy`，INI 使用 `[remote_subscription]` 下的 `loon_remote_proxy`。缺少整个配置节或字段时，默认值为 `true`；旧配置文件无需增加字段即可启动，配置热重载时删除该字段也会恢复默认值。已有但未知或失效的旧字段仍按原有宽容规则忽略。

Loon 开关不影响 Clash/ClashR 的 Mihomo 与 `proxy-provider` 路径，也不影响 Quantumult X、Surge、Surfboard 或其他目标。Loon 官方说明订阅节点由客户端负责下载和解析，并提供当前的[节点格式](https://nsloon.app/docs/Node/)、[节点筛选](https://nsloon.app/docs/Node/nodefilter/)和[策略组](https://nsloon.app/docs/Policy/policygroup/)文档。

### `proxy_direct` 前缀（仅适用于 Clash/ClashR 订阅链接）

默认情况下，项目为每个新生成的 `proxy-provider` 显式生成 `proxy: DIRECT`，保持既有行为。部署者可以将主配置文件中的 `proxy_provider.proxy_direct` 设为 `false`；用户也可以使用已有请求参数 `&provider_proxy_direct=false`，为本次请求中所有未单独覆盖的 provider 改变默认值。

需要逐条控制时，在订阅链接前添加 `proxy_direct:true,` 或 `proxy_direct:false,`。它与 `provider:`、`tag:`、`interval:` 前缀可以任意排序：

```text
url=provider:A,proxy_direct:false,https://a.example/sub|provider:B,interval:21600,proxy_direct:true,https://b.example/sub|provider:C,https://c.example/sub
```

生效优先级是：单条订阅的 `proxy_direct:` 前缀 > 请求参数 `&provider_proxy_direct=` > 主配置文件 `proxy_provider.proxy_direct` > 兼容默认值 `true`。

* `proxy_direct:true` 会明确生成 `proxy: DIRECT`
* `proxy_direct:false` 会完全省略 `proxy` 字段，不会生成 `proxy: false`、空字符串或 `null`
* 省略 `proxy` 字段并不保证一定走代理，而是让 Mihomo 按自身规则和运行模式决定 provider 的下载路径
* 如果代理路径本身依赖这个尚未完成初次下载的 provider，可能形成启动循环；因此本项目继续使用 `true` 作为兼容默认值
* 接受 `true`、`false`、`1`、`0`；同一条订阅重复设置或使用其他值会返回 HTTP 400
* `proxy_direct:` 不适用于节点 URI、`list=true` 或非 Clash/ClashR 目标

</details>

<details>
<summary><strong>sing-box 1.13/1.14 完整配置兼容基线</strong></summary>

仓库内置的 sing-box 完整配置模板使用 1.13 与 1.14 共同支持的现代结构：DNS 服务器采用带 `type` 的新格式，FakeIP 是独立 DNS 服务器，TUN 地址统一写入 `address`，嗅探与 DNS 劫持由路由动作表达；GeoSite/GeoIP 规则会转换为 sing-box 官方二进制远程规则集，不再输出 1.14 已移除的旧字段。

这一迁移不增加主配置参数，也不改变 `pref.ini`、`pref.yml` 或 `pref.toml` 的读取方式。旧配置文件可以直接启动；`snell_outbound=false` 时，内置完整配置同时通过固定的 sing-box 1.13 稳定版和 1.14 预发布版 `sing-box check`。启用 Snell 后，最低客户端版本仍为 1.14。

本项目只迁移仓库自带的 sing-box 基础模板和由项目生成的规则。部署者通过 `singbox_rule_base` 指定的自定义模板会按原内容保留，不会被服务端擅自重写；如果自定义模板仍含旧 DNS、TUN、嗅探或 GeoSite/GeoIP 字段，应由模板维护者按 sing-box 官方[迁移说明](https://sing-box.sagernet.org/migration/)更新。内置远程规则集需要客户端能够访问对应的 SagerNet GitHub Raw 地址。

</details>

<details>
<summary><strong>WireGuard 结构化转换与 sing-box 新旧模式</strong></summary>

Legacy 节点路径会保留 WireGuard 的多个本地地址和多个 Peer，而不再只保留第一项。当前可识别以下输入：

* Surge `[Proxy]` 与 `[WireGuard name]` 分节格式，包括重复或组合的 `peer`、Peer 级预共享密钥、保活时间、Allowed IP 和 Client ID；
* Loon 内联 `wireguard` 与 `peers=[{...}]` 格式；
* Mihomo 顶层单 Peer 与 `peers` 多 Peer 格式；
* sing-box 旧版 WireGuard outbound 和 1.11+ WireGuard endpoint。

Surge 输出使用官方 `[WireGuard name]` 分节格式，并为每个 Peer 保留独立参数；Loon 输出使用内联 `peers` 数组。Loon 只有节点级 `keepalive`，因此多个 Peer 的保活时间必须一致；不一致时该节点会按“不支持”处理，不会擅自选取某一个值。

缺少新配置项的旧部署继续输出旧版 WireGuard outbound，以保证配置文件平滑升级。仓库提供的新示例配置默认启用 sing-box 1.11+ endpoint；部署者也可以显式设置：

```toml
[singbox]
wireguard_endpoint = true
```

```yaml
singbox:
  wireguard_endpoint: true
```

```ini
[singbox]
wireguard_endpoint=true
```

缺少整个配置节或字段时，兼容默认值为 `false`；旧 `pref.ini`、`pref.yml` 和 `pref.toml` 无需增加字段即可启动，热重载时删除字段会恢复旧 outbound。sing-box 1.12 继续使用旧 outbound 时还需要设置官方兼容环境变量 `ENABLE_DEPRECATED_WIREGUARD_OUTBOUND=true`，1.13 已移除旧结构；使用这些新版本时应启用 endpoint。endpoint 模式会保留 Peer 级 `persistent_keepalive_interval`；旧 outbound 官方结构无法表示该字段，因此不会伪造或下放错误位置。日志事件 `SINGBOX_WIREGUARD_GENERATION` 只记录 `schema`、节点数和 Peer 数，不记录密钥、地址或节点名称。

该开关只控制 `target=singbox` 的 WireGuard 输出结构，不参与输入解析，也不改变 Clash/ClashR 的 Mihomo 解析、Canonical JSON 或 `proxy-provider` 分流。格式依据见 [Surge WireGuard 手册](https://manual.nssurge.com/policies/wireguard.html)、[Loon 节点格式](https://nsloon.app/docs/Node/)、[Mihomo WireGuard 配置](https://wiki.metacubex.one/config/proxies/wg/)、[sing-box 旧 outbound](https://sing-box.sagernet.org/configuration/outbound/wireguard/)和[新 endpoint](https://sing-box.sagernet.org/configuration/endpoint/wireguard/)。

</details>

<details>
<summary><strong>sing-box 1.14+ Snell outbound</strong></summary>

sing-box 从 1.14 开始提供 Snell outbound。由于 1.14 目前仍处于预发布阶段，而当前稳定版 1.13 不识别 `type: "snell"`，本项目不会默认提高部署者的客户端版本要求。旧配置缺少新字段时继续跳过 sing-box Snell 输出，行为与升级前一致。

确认使用 sing-box 1.14+ 后，可以显式启用：

```toml
[singbox]
snell_outbound = true
```

```yaml
singbox:
  snell_outbound: true
```

```ini
[singbox]
snell_outbound=true
```

开关只影响 `target=singbox` 的 Snell 节点生成，不参与 Clash/ClashR 的 Mihomo 解析、Canonical JSON 或 `proxy-provider` 分流。热重载时删除字段会恢复为 `false`，旧 `pref.ini`、`pref.yml` 和 `pref.toml` 无需迁移即可继续启动。

当前输出边界遵循 sing-box 官方结构：

* v4 支持 `psk`、`userkey`、`reuse`、`network`，以及 `none`/`http` 混淆；
* v6 支持 `psk`、`userkey`、`reuse`、`network` 和 `default`/`unshaped`/`unsafe-raw` 模式，并校验 PSK 为 12–255 字节；
* 不含 QUIC 扩展的历史 v5 节点按官方兼容说明规范化为 v4；v1–v3、v5 `udp-port`、Shadow TLS、未知 Dial 字段或其他无法等价表达的组合不会被静默降级；
* 只有实际生成 Snell 节点时，结果才要求 sing-box 1.14+。日志事件 `SINGBOX_SNELL_GENERATION` 记录启用状态、输入/输出数量、v5 规范化数量和最低版本，不记录服务器、PSK、userkey 或节点名称。

仓库内置完整模板已经通过固定的 sing-box 1.13 与 1.14 双版本校验；仓库示例仍默认 `snell_outbound=false`，因此不会无意提高现有部署者的客户端版本要求。格式依据见 [sing-box Snell outbound](https://sing-box.sagernet.org/configuration/outbound/snell/)。

</details>

---

## 🛠️ 配置说明

### 主配置文件

支持三种格式：`pref.toml`（推荐）、`pref.yml`、`pref.ini`。

关键配置项：

```toml
[managed_config]
managed_config_prefix = "http://localhost:25500"  # 托管配置前缀
```

非本机部署时，请将该项修改为 SubConverter-Extended 实际部署机的 IP 地址或域名。

### 安全档位

从本版本开始，主配置文件支持 `[security]` 安全档位，用于区分内网自用部署和公网暴露部署。

默认值为 `lan`，保持历史行为不变，适合家庭内网、NAS、软路由、旁路由、Docker 内网等自用场景。该档位允许访问本地资源、私有网段资源和 fake-ip 资源，因此现有部署通常无需额外修改配置。

升级不会自动更改安全档位、监听地址、端口映射或上传行为。缺省配置和显式 `lan` 都继续使用原有行为；Docker 与 Compose 用户也不需要为了升级新增配置项。

公网部署建议显式切换为 `public`：

```toml
[security]
profile = "public"
allow_public_upload = false
```

INI 配置示例：

```ini
[security]
profile=public
allow_public_upload=false
```

Docker 环境变量示例：

```bash
docker run -d \
  --name SubConverter-Extended \
  -p 25500:25500 \
  -e SUBCONVERTER_SECURITY_PROFILE=public \
  -e SUBCONVERTER_ALLOW_PUBLIC_UPLOAD=false \
  --restart unless-stopped \
  aethersailor/subconverter-extended:latest
```

| 配置项 / 环境变量 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `security.profile` / `SUBCONVERTER_SECURITY_PROFILE` | `lan` | 可选值：`lan`、`public`、`strict` |
| `security.allow_public_upload` / `SUBCONVERTER_ALLOW_PUBLIC_UPLOAD` | `false` | 仅 `public` 档位生效，用于显式允许公开请求触发上传 |

档位说明：

* `lan`：默认档位，保持旧行为，适合可信内网自用部署。
* `public`：公网推荐档位。限制公开请求参数、远程外部配置、公开 `!!import` 等不可信来源访问本地、私网和 fake-ip 字面量；项目自带本地模板、部署者配置的默认模板与可信本地配置仍可正常使用。
* `strict`：在 `public` 的基础上，始终禁止公开请求触发上传，即使设置 `allow_public_upload=true` 也不会放行。

`allow_public_upload=false` 的名字容易产生误解，但为保持兼容，其既有语义不变：`lan` 仍允许旧式公开请求上传，`public` 默认禁止，`strict` 始终禁止。需要判断实际结果时，以启动日志中的 `SECURITY_UPLOAD_EFFECTIVE` 为准。

启动时会输出可供日志系统检索的诊断事件：

* `SECURITY_PROFILE_EFFECTIVE`：最终生效档位及来源（内置默认、配置文件或环境变量）。
* `SECURITY_PROFILE_INVALID_FALLBACK`：档位拼写无效，为兼容旧部署回退到 `lan`。该回退不代表实例适合公网暴露。
* `SECURITY_UPLOAD_EFFECTIVE`：结合档位和开关计算后的实际上传策略。
* `SECURITY_EXPOSURE_POSSIBLE`：`lan` 监听所有接口时提示可能暴露，同时明确 `public_reachability=unknown`；程序不会把 `0.0.0.0` 误判成“已经公网可达”。

每个进入应用路由生命周期的 HTTP 响应都包含可关联服务端日志的 `X-Request-ID`。日志保留状态、耗时、解析路径和安全资源摘要，同时隐藏订阅、节点和凭据；轮转策略及完整脱敏边界见[日志与诊断](docs/logging-and-diagnostics.zh-CN.md)。

> [!NOTE]
> `public` 档位不会阻止正常域名在 OpenClash fake-ip DNS 环境下解析到 `198.18.0.0/15` 后继续访问；但会阻止请求方直接传入 `127.0.0.1`、私有地址或 fake-ip 字面量作为抓取目标。

---

## 🔍 Docker Hub 镜像标签

`latest` 与版本标签均为多架构镜像，当前支持 `linux/amd64`、`linux/arm64`、`linux/arm/v7`。

| 标签 | 用途 | 更新频率 |
| :--- | :--- | :--- |
| `latest` | 🟢 **稳定版本**（`master` 分支） | 发布 Release 时更新 |
| `dev` | 🟡 **开发版本**（`dev` 分支） | 每次 `dev` 分支推送后更新 |

---

## 🤝 致谢

开发者如需从源码构建或运行测试，请参阅 [构建与测试契约](docs/build-and-test.md)。

本项目使用或引用了以下开源项目，在此表示感谢：

* [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) - Clash 内核，提供节点链接解析能力
* [Aethersailor/Custom_OpenClash_Rules](https://github.com/Aethersailor/Custom_OpenClash_Rules) - OpenClash 订阅转换模板、规则集与教程项目
* [asdlokj1qpi233/subconverter](https://github.com/asdlokj1qpi233/subconverter) - 原版 subconverter 项目

---

## 📄 开源协议

本项目基于 [GPL-3.0](LICENSE) 协议开源。

> [!TIP]
> 内置的 Mihomo 解析器模块遵循 [MIT](https://github.com/MetaCubeX/mihomo/blob/Meta/LICENSE) 协议。

---

## ⭐ 记录

## Star History

<a href="https://www.star-history.com/?type=date&repos=Aethersailor%2FSubConverter-Extended">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=Aethersailor/SubConverter-Extended&type=date&theme=dark&legend=top-left&sealed_token=NKvX6WwN3no1B0JCAxO5Tkk4nqJLR5HppGP59Pp9IDkrygstiLYT8T8_MsYyG-hqMAuML_mTOU2N1PX79o9ZgwfXacAhIBKClQskYzigRVD1FQyH66FGwA" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=Aethersailor/SubConverter-Extended&type=date&legend=top-left&sealed_token=NKvX6WwN3no1B0JCAxO5Tkk4nqJLR5HppGP59Pp9IDkrygstiLYT8T8_MsYyG-hqMAuML_mTOU2N1PX79o9ZgwfXacAhIBKClQskYzigRVD1FQyH66FGwA" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=Aethersailor/SubConverter-Extended&type=date&legend=top-left&sealed_token=NKvX6WwN3no1B0JCAxO5Tkk4nqJLR5HppGP59Pp9IDkrygstiLYT8T8_MsYyG-hqMAuML_mTOU2N1PX79o9ZgwfXacAhIBKClQskYzigRVD1FQyH66FGwA" />
 </picture>
</a>

## 📊 数据统计

![Alt](https://repobeats.axiom.co/api/embed/c249ae5c34b99a067c78e9216600c1a5eac16c65.svg "Repobeats analytics image")

---

<div align="center">

**如果这个项目对你有帮助，欢迎给一个 ⭐ Star 支持。**

Made with ❤️ by [Aethersailor](https://github.com/Aethersailor)

</div>
