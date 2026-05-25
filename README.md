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
| **订阅链接处理** | 📥 拉取并解析订阅，容易被屏蔽 | 🔗 **生成 `proxy-provider`，由客户端 Mihomo 内核直接拉取订阅** |
| **协议维护方式** | ⏳ 依赖人工新增和维护 | 🔄 **编译时自动扫描 Mihomo 源码，跟进新协议支持** |
| **全局参数维护** | 📝 人工维护节点参数列表 | 🔍 **编译时自动识别硬编码参数和可覆写参数** |  

> [!WARNING]
> 1. 本项目优先适配 OpenClash，其次是各类 Clash 客户端；对其他客户端的支持不作保证。
> 2. 非 Mihomo 内核的客户端连接本项目，将继续调用继承自上游项目的人工维护解析器。
> 3. 开发者仅确保完美支持 Mihomo 内核，因代码调整造成的对其他内核客户端的支持范围缩减，原则上不单独回补。

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
    interval: 3600
    proxy: DIRECT  # 默认以直连方式拉取订阅
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

#### 4. 兼容性保证 🤝

* ✅ **无缝切换**：兼容常见传统 subconverter API 接口，客户端侧几乎无需学习成本即可迁移
* ✅ **模板兼容**：继续沿用传统外部模板，由后端内置逻辑确保 `proxy-provider` 模式在分流规则中正确生成
* ✅ **自动跟进**：编译时自动遍历 [Mihomo 内核源码仓库](https://github.com/MetaCubeX/mihomo/meta)，提取最新解析模块、协议格式与可覆写参数

#### 5. 新手友好 👶

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

#### 一键启动

```bash
docker run -d \
  --name SubConverter-Extended \
  -p 25500:25500 \
  --restart unless-stopped \
  aethersailor/subconverter-extended:latest
```

访问 `http://localhost:25500/version` 验证服务是否正常启动。

#### 自定义配置启动

```bash
# 删除可能存在的工作目录
rm -rf /opt/SubConverter-Extended

# 创建 SubConverter-Extended 工作目录
mkdir -p /opt/SubConverter-Extended/base

cd /opt/SubConverter-Extended

# 下载配置文件
wget -O base/pref.toml \
  https://gcore.jsdelivr.net/gh/Aethersailor/SubConverter-Extended@master/base/pref.example.toml

# 如需外部访问，请修改 base/pref.toml 中的 managed_config_prefix

# 启动容器并挂载配置
docker run -d \
  --name SubConverter-Extended \
  -p 25500:25500 \
  -v /opt/SubConverter-Extended/base/pref.toml:/base/pref.toml:ro \
  --restart unless-stopped \
  aethersailor/subconverter-extended:latest
```

也可以直接用环境变量覆盖常用配置：

```bash
docker run -d \
  --name SubConverter-Extended \
  -p 25500:25500 \
  -e MANAGED_CONFIG_PREFIX="http://your-domain-or-ip:25500" \
  -e SUBCONVERTER_SECURITY_PROFILE=public \
  -e SUBCONVERTER_ALLOW_PUBLIC_UPLOAD=false \
  --restart unless-stopped \
  aethersailor/subconverter-extended:latest
```

#### Docker Compose

```bash
# 删除可能存在的工作目录
rm -rf /opt/SubConverter-Extended

# 创建 SubConverter-Extended 工作目录
mkdir -p /opt/SubConverter-Extended/base

cd /opt/SubConverter-Extended

# 下载 docker-compose 配置文件
wget -O docker-compose.yml \
  https://gcore.jsdelivr.net/gh/Aethersailor/SubConverter-Extended@master/docker-compose.yml

# 下载配置文件
wget -O base/pref.toml \
  https://gcore.jsdelivr.net/gh/Aethersailor/SubConverter-Extended@master/base/pref.example.toml

# 如需外部访问，请修改 docker-compose.yml 中的 MANAGED_CONFIG_PREFIX，
# 或修改 base/pref.toml 中的 managed_config_prefix

# 启动容器
docker compose up -d
```

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

### 常用参数一览

| 参数 | 说明 | 示例 |
| :--- | :--- | :--- |
| `target` | 目标格式 | `clash`, `surge`, `quanx` |
| `url` | 订阅链接或节点链接（`\|` 分隔） | `https://sub.com\|vless://...` |
| `config` | 外部配置文件 | `https://config-url` |
| `include` | 包含节点（正则） | `香港\|台湾` |
| `exclude` | 排除节点（正则） | `过期\|剩余` |
| `emoji` | 添加 Emoji | `true` / `false` |
| `explain` | 返回本次转换的 JSON 诊断报告 | `true` |

### 常见调用示例

```text
https://api.asailor.org/sub?target=clash&url=https%3A%2F%2Fexample.com%2Fsub&config=https%3A%2F%2Fexample.com%2Fconfig.ini
```

```text
https://api.asailor.org/sub?target=clash&url=provider%3AHK%2Chttps%3A%2F%2Fexample.com%2Fsub&include=%E9%A6%99%E6%B8%AF&emoji=true
```

### `explain=true` 诊断模式

在 `/sub` 请求中追加 `explain=true` 后，后端会按同一组参数执行转换流程，但返回 JSON 诊断报告，而不是返回 Clash/Surge/QuanX 配置文件。

示例：

```text
https://api.asailor.org/sub?target=clash&url=https%3A%2F%2Fexample.com%2Fsub&explain=true
```

这个模式适合排查“参数是否生效”“是否进入 `proxy-provider` 模式”“外部配置是否加载成功”“规则集和节点数量是否符合预期”等问题。报告会包含目标格式、模式开关、输入数量、外部配置状态、规则集统计、provider 数量和输出大小等信息。

> [!NOTE]
> * `explain=true` 只改变响应内容，不改变实际转换逻辑。
> * 如果同一请求里包含上传参数，诊断模式会抑制上传，避免排障时产生托管配置写入。
> * 诊断报告不会直接回显原始订阅地址；provider 来源会以短哈希形式显示，便于区分来源又避免泄露完整链接。

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

> [!NOTE]
> * `/inspect` 只是 `explain=true` 诊断报告的可视化界面，不会改变实际转换逻辑。
> * 页面会隐藏敏感输入的明文，仅展示预览、长度和短哈希等排障信息。
> * 请求诊断台会保留原始 JSON 区域，方便复制给维护者进一步分析。

### `provider` 前缀（仅适用于 Clash/ClashR 订阅链接）

`provider` 不是独立参数，而是写在 `url=` 列表中、放在订阅链接前，并以逗号分隔，用于自定义 `proxy-providers` 名称；对节点链接不生效。

示例：

```text
url=provider:HK,https://example.com/sub
url=provider:HK,https://a|provider:HK,https://b
url=provider%3AHK%2Chttps%3A%2F%2Fexample.com%2Fsub
```

> [!NOTE]
> 在 OpenClash 这类预置“订阅地址”输入框的软件中，无需填写开头的 `url=`，直接填入等号后的内容即可。

补充说明：

* 支持中文名称；非法字符或空值会回退为默认 `Provider_<MD5>`
* 重名时会自动追加 `_1`、`_2` 等后缀

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

<a href="https://www.star-history.com/#Aethersailor/SubConverter-Extended&Date">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=Aethersailor/SubConverter-Extended&type=Date&theme=dark" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=Aethersailor/SubConverter-Extended&type=Date" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=Aethersailor/SubConverter-Extended&type=Date" />
 </picture>
</a>

## 📊 数据统计

![Alt](https://repobeats.axiom.co/api/embed/c249ae5c34b99a067c78e9216600c1a5eac16c65.svg "Repobeats analytics image")

---

<div align="center">

**如果这个项目对你有帮助，欢迎给一个 ⭐ Star 支持。**

Made with ❤️ by [Aethersailor](https://github.com/Aethersailor)

</div>
