<div align="center">

# SubConverter-Extended

**A Modern Evolution of subconverter**

![GitHub Tag](https://img.shields.io/github/v/tag/Aethersailor/SubConverter-Extended?style=for-the-badge&logo=github&label=VERSION&color=blue)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/Aethersailor/SubConverter-Extended/build-dockerhub.yml?branch=master&style=for-the-badge&label=Docker%20Build&logo=GitHub%20Actions)
[![Docker Pulls](https://img.shields.io/docker/pulls/aethersailor/subconverter-extended?style=for-the-badge&logo=docker)](https://hub.docker.com/r/aethersailor/subconverter-extended)
[![License](https://img.shields.io/badge/license-GPL--3.0-orange?style=for-the-badge)](LICENSE)

<h3>⚡ 现代化的订阅转换后端 | 完美兼容 Mihomo 内核 ⚡</h3>

<p align="center">
  <a href="#-项目简介">项目简介</a> •
  <a href="#-立项原因">立项原因</a> •
  <a href="#-核心特性">核心特性</a> •
  <a href="#-快速开始">快速开始</a> •
  <a href="#-使用文档">使用文档</a> •
  <a href="#-docker-部署">Docker 部署</a>
</p>

</div>

---

## 📖 项目简介

> [!NOTE]
> **SubConverter-Extended** 是基于 [asdlokj1qpi233/subconverter](https://github.com/asdlokj1qpi233/subconverter) 深度二次开发的订阅转换后端增强版本。

它专为协同 [Mihomo](https://github.com/MetaCubeX/mihomo) 内核工作优化，提供更现代、更强大的订阅转换服务。

**核心定位转变**：
SubConverter-Extended 不再充当客户端和机场之间的"中转站"，而是成为独立的 **"配置融合器"** ——只对客户端服务，不再连接机场订阅服务器。同时基于 Mihomo 内核源码，在编译时自动跟进协议支持。  

<div align="center">
<img width="719" height="442" alt="22" src="https://github.com/user-attachments/assets/506ab284-96cf-4aae-a844-bf69f15ce8df" />
</div>

> [!WARNING]
> SubConverter-Extended 优先服务 OpenClash，其次是各 Clash 客户端，对其他客户端的支持不作保证。对于修改代码造成的支持范围缩减不作修复。  

---

## 💡 立项原因

### 遇到的问题

在长期使用 subconverter 的过程中，我遇到了几个不如人意的痛点：

#### 1. 协议支持滞后 🐢

原版 subconverter 对节点参数的支持是否完善，完全取决于开发者的积极性，其解析器需要依靠人工进行维护。  

许多新兴协议（如 `hysteria2`、`tuic`、`anytls` 等）往往在相当长的时间内无法得到完善的支持，而一些老协议（如 `vless`），由于传输层协议等参数的更新，至今也未能做到完美的转换。  

在 subconverter 以及其流行分支的仓库中，可见大量相关的 issue。  

当然，这并不是开发者的错，任何一位开发者都没有一直为开源社区用爱发电的义务。  

我也曾 fork 过 subconverter 并试图解决对各个协议支持不完美的问题，最后得出的结论就是完全靠人工来维护这样一个项目，势必要花费不少时间和精力去测试，而且很有可能取得不了预期的结果。  

#### 2. 机场屏蔽问题 🚫

由于 subconverter 需要连接机场订阅服务器拉取节点，而部分机场出于安全考虑：

* 屏蔽海外 IP 访问
* 屏蔽 subconverter 的 User-Agent
* 限制非客户端的订阅请求

这导致了许多用户根本无法正常使用订阅转换服务。  

由于原版 subconverter 需要读取订阅链接内容，对于机场屏蔽特定地区 IP 请求订阅的限制完全无法通过其自身实现绕过。  

对于 UA 的限制虽然可以通过修改或者删除原版中的特定 UA 来绕过，但这无形中也人为制造了和机场运营方的一种对抗。  

#### 3. 新手友好度不足 🤯

由于上述问题，subconverter 逐渐被一些开发者和 UP 主视为"过时产物"，开始推崇使用 YAML 文件手动管理配置。但很多新手并没有兴趣和时间去研究 YAML 配置文件，更多的是希望“开袋即食”。  

但由于 subconverter 的种种问题，加上当下诸多机场的限制，许多用户常遇到不能解析节点/不能拉取节点/拉下来的节点参数无效等等奇怪的故障。对于很多新手来说，大部分人是并没有能力解决此类问题。  

**但也正是基于这一点，正如 [Custom_OpenClash_Rules](https://github.com/Aethersailor/Custom_OpenClash_Rules) 项目所坚持的：**

> [!IMPORTANT]
> **最适合新手和普通用户且最具普适性的操作流程，永远是基于 UI 界面的操作流程。**

用户应当拿着订阅链接，点几下鼠标就能根据自己的实际情况配置出最佳效果，并自动享受完善的分流规则更新。  

而不是繁琐的"手搓配置"、"上传文件"、"手动修改参数"，甚至还得到处提问，问的太蠢了还会被人喷，一点儿都不优雅。

### 🎯 我们的解决方案  

从单纯服务于 Clash 客户端的角度来讲，完全可以以使用现代 Clash 内核的既有的 `proxy-provider` 功能来取代原版 subconverter 的订阅链接解析功能。  

同样，对于节点链接的解析，也完全可以引入内核的解析模块，来替代过去的人工维护解析器，直接获得最完美的结果。  

**那就自己动手吧。** SubConverter-Extended 因此诞生，让转换工具更匹配现代 Clash 内核的使用场景，**服务于所有保留“订阅转换”接口且使用 Mihomo 内核的 Clash 客户端**。

---

## ✨ 核心特性

### 🚀 相对原版的重大改进

| 功能 | 原版 Subconverter | SubConverter-Extended |
| :--- | :--- | :--- |
| **完美协议支持** | 🛠️ 人工维护解析器，有限支持 | 🤖 **集成 Mihomo 内核的解析器模块，完美支持所有节点连接协议** |
| **订阅链接处理** | 📥 下载并解析节点，易被屏蔽 | 🔗  **生成 `proxy-provider`，不再连接机场，由用户的 Mihomo 内核直接拉取** |
| **未来自动跟进** | ⏳ 人工添加维护新协议 | 🔄 **全自动维护，编译时自动扫描 Mihomo 源码添加支持新协议** |
| **全局参数透传** | 📝 人工维护全局参数列表 | 🔍 **全自动维护，编译时自动扫描 Mihomo 源码，自动识别硬编码和可覆写参数** |

### 🔥 独特功能

#### 1. Proxy-Provider 模式 🛡️

**使用 Mihomo 的 Proxy-Provider 机制**  

订阅链接**不再下载解析**，而是生成客户端可直接使用的配置，交由用户客户端的 Mihomo 内核自行拉取订阅：

```yaml
proxy-providers:
  Provider_A1B2C3:
    type: http
    url: https://your-subscription-url  # <-- 客户端直接连接机场
    interval: 3600
    path: ./providers/provider_1.yaml
    health-check:
      enable: true
      interval: 600
      url: http://www.gstatic.com/generate_204
```

> [!NOTE]
> * 使用 proxy-provider 后，由你的客户端内核以**直连**的形式自行拉取订阅。  
> * 订阅是否能成功，**与本后端无关，与规则无关**。效果等同于你自己制作 yaml 并填写订阅链接。  
> * 如遇拉取不成功，说明你的订阅链接不正确，或者在国内无法正常直连访问（至少在你所在的位置是如此），请和机场客服对线。

> [!TIP]
> **优势**：
>
> * ✅ 不再干涉用户节点，交由内核原生处理
> * ✅ 订阅更新由客户端控制，无需重新转换
> * ✅ 避免机场屏蔽转换服务器的问题

#### 2. Mihomo 内核模块集成 🧩

对于节点链接的处理，直接使用 Mihomo Go 库解析节点链接，确保：

* ✅ 支持 Mihomo 内核可解析的所有节点连接协议（包括但不限于 `hysteria2`, `tuic`, `anytls` 等）
* ✅ 参数完全兼容，解析能力与 Mihomo 内核对齐，无需手动适配
* ✅ 新协议零延迟支持（编译时跟随 Mihomo 更新）

#### 3. 兼容性保证 🤝

* ✅ **无缝切换**：完全兼容传统 subconverter 的 API 接口，确保客户端用户零学习成本，无缝切换。
* ✅ **模板兼容**：继续沿用传统的订阅转换外部模板，无需修改任何内容，由后端内置逻辑确保 `proxy-provider` 模式在分流规则中正确生成。
* ✅ **无忧更新**：编译时自动遍历 [Mihomo 内核源码仓库](https://github.com/MetaCubeX/mihomo/meta)，自动提取内核解析模块，并读取当前最新支持的协议格式，自动识别可被全局参数覆盖的节点参数，确保永远对齐 Mihomo 内核支持解析的所有节点连接协议。

#### 4. 新手友好 👶

* ✅ 使用 **[Custom_OpenClash_Rules](https://github.com/Aethersailor/Custom_OpenClash_Rules)** 远程配置模板替代默认模板
* ✅ 锁死 API 模式，关闭 API 模式相关接口，避免新手误配置降低安全性
* ✅ 简化参数，专注核心功能

---

## 🚀 快速开始

### 🌍 使用公共后端 (无需部署)

如果你不想折腾服务器，可以直接使用我们提供的公共后端：

> [!TIP]
> **公共后端地址**：`https://api.asailor.org`

你可以在任何支持自定义后端的订阅转换网站或客户端中填入此地址即可使用。

### 🐳 自行部署 (Docker)

如果你拥有自己的服务器，推荐使用 Docker 进行部署。

> [!WARNING]
> **代码尚不完善，推荐优先使用公共后端。**
>
> *由于开发者业余时间有限，以下部署指南部分内容由 AI 生成，仅供参考。*

#### 1. 一键启动

```bash
docker run -d \
  --name SubConverter-Extended \
  -p 25500:25500 \
  --restart unless-stopped \
  aethersailor/subconverter-extended:latest
```

访问 `http://localhost:25500/version` 验证部署。

#### 2. 自定义配置启动

```bash
# 1. 创建配置目录
mkdir -p ~/SubConverter-Extended/base

# 2. 下载配置文件模板（可选）
wget -O ~/SubConverter-Extended/base/pref.toml \
  https://raw.githubusercontent.com/Aethersailor/SubConverter-Extended/master/base/pref.example.toml

# 3. 启动容器并挂载配置
docker run -d \
  --name SubConverter-Extended \
  -p 25500:25500 \
  -v ~/SubConverter-Extended/base/pref.toml:/base/pref.toml \
  --restart unless-stopped \
  aethersailor/subconverter-extended:latest
```

#### 3. Docker Compose
```yaml
services:
  sub:
    container_name: SubConverter-Extended
    hostname: SubConverter-Extended
    image: aethersailor/subconverter-extended:latest
    logging:
      driver: json-file
      options:
        max-size: 1m
    volumes:
      - ./pref.toml:/base/pref.toml
    ports:
      # 映射宿主机 25500 端口
      - "25500:25500"
    environment:
      - TZ=Asia/Shanghai
    restart: unless-stopped
    # 使用桥接的网络模式，bridge，host，none
    network_mode: bridge
```

---

## 📚 使用文档

使用方式与原版 subconverter 完全相同。  

> [!IMPORTANT]
> 默认输出**最简配置**，无 DNS 参数，请启用 Clash 客户端中的 DNS 覆写功能！  
> 例如 OpenClash > 覆写设置 > 自定义上游 DNS 服务器  
> 或者自行在生成的配置文件中人工补全 DNS 参数  

### 基础转换

将机场订阅转换为 Clash 配置：

```bash
curl "http://localhost:25500/sub?target=clash&url=https://your-sub-url"
```

### 🌟 推荐配置

配合 **Custom_OpenClash_Rules** 项目使用：

```bash
curl "http://localhost:25500/sub?target=clash&url=YOUR_SUB&config=https://raw.githubusercontent.com/Aethersailor/Custom_OpenClash_Rules/main/cfg/Custom_Clash.ini"
```

### 常用参数一览

| 参数 | 说明 | 示例 |
| :--- | :--- | :--- |
| `target` | 目标格式 | `clash`, `surge`, `quanx` |
| `url` | 订阅链接或节点链接（`\|` 分隔） | `https://sub.com\|vless://...` |
| `config` | 外部配置文件 | `https://config-url` |
| `include` | 包含节点（正则） | `香港\|台湾` |
| `exclude` | 排除节点（正则） | `过期\|剩余` |
| `emoji` | 添加 Emoji | `true`/`false` |

#### provider 前缀（仅 Clash/ClashR 订阅链接）

`provider` 不是独立参数，而是写在 `url=` 列表中、放在订阅链接前，用逗号分隔，用于自定义 `proxy-providers` 名称。节点链接不生效。

示例：

```
url=provider:HK,https://example.com/sub
url=provider:HK,https://a|provider:HK,https://b
url=provider%3AHK%2Chttps%3A%2F%2Fexample.com%2Fsub
```

补充说明：

* 支持中文；非法字符或空值会回退为默认 `Provider_<MD5>`
* 重名会自动追加 `_1`、`_2` 等后缀

---

## 🛠️ 配置说明

### 主配置文件

支持三种格式：`pref.toml`（推荐）、`pref.yml`、`pref.ini`。

关键配置项：

```toml
[managed_config]
managed_config_prefix = "http://localhost:25500"  # 托管配置前缀
```
非本机部署时，请将此项修改为 SubConverter-Extended 部署机的 IP 地址或域名。  
---

## 🔍 Docker Hub 镜像标签

| 标签 | 用途 | 更新频率 |
| :--- | :--- | :--- |
| `latest` | 🟢 **稳定版本**（master 分支） | 有 release 时更新 |
| `dev` | 🟡 **开发版本**（dev 分支） | 每次 dev 分支推送 |

---

## 🤝 致谢

本项目使用或引用了以下开源项目，在此表示感谢：

* [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) - Clash 内核，提供节点链接解析能力
* [Aethersailor/Custom_OpenClash_Rules](https://github.com/Aethersailor/Custom_OpenClash_Rules) - OpenClash 订阅转换模板、规则集和教程项目
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

</div>

---

<div align="center">

**如果这个项目对你有帮助，请给个 ⭐ Star 支持一下！**

Made with ❤️ by [Aethersailor](https://github.com/Aethersailor)
