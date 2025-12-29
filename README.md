<div align="center">

# SubConverter-Extended

**A Modern Evolution of subconverter**

[![Version](https://img.shields.io/badge/version-1.0.5-blue.svg)](https://github.com/Aethersailor/SubConverter-Extended/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/aethersailor/subconverter-extended.svg)](https://hub.docker.com/r/aethersailor/subconverter-extended)
[![License](https://img.shields.io/badge/license-GPL--3.0-orange.svg)](LICENSE)
[![Mihomo](https://img.shields.io/badge/mihomo-integrated-brightgreen.svg)](https://github.com/MetaCubeX/mihomo)

**现代化的订阅转换后端**

[特性](#-核心特性) • [快速开始](#-快速开始) • [使用文档](#-使用文档) • [Docker 部署](#-docker-部署)

</div>

---

## 📖 项目简介

SubConverter-Extended 是基于 [subconverter v0.9.9](https://github.com/asdlokj1qpi233/subconverter) 深度二次开发的订阅转换后端增强版本，专为协同 [Mihomo](https://github.com/MetaCubeX/mihomo) 内核优化，提供更现代、更强大的订阅转换服务。

**核心定位转变**：SubConverter-Extended 不再充当客户端和机场之间的"中转站"，而是成为独立的"配置融合器"——只对客户端服务，不连接机场订阅服务器。同时基于 Mihomo 内核源码，在编译时自动跟进协议支持。

---

## � 立项原因

### 遇到的问题

在长期使用 subconverter 的过程中，我遇到了几个不如人意的痛点：

#### 1. 协议支持滞后

subconverter 对新节点格式的支持完全取决于维护者的积极性。许多新兴协议（如 `hysteria2`、`tuic`、`anytls` 等）往往在相当长的时间内无法得到支持，而一些老协议至今也未能做到完美转换。

#### 2. 机场屏蔽问题

由于 subconverter 需要连接机场订阅服务器拉取节点，而部分机场出于安全考虑：

- 屏蔽海外 IP 访问
- 直接屏蔽 subconverter 的 User-Agent
- 限制非客户端的订阅请求

这导致许多用户根本无法正常使用订阅转换服务。

#### 3. 新手友好度不足

由于上述问题，subconverter 逐渐被一些开发者和 UP 主视为"过时产物"，开始推崇使用 YAML 文件手动管理配置。

**但作为 [Custom_OpenClash_Rules](https://github.com/Aethersailor/Custom_OpenClash_Rules) 项目的维护者**，我始终坚持认为：

> 最适合新手以及最具普适性的操作流程，永远是基于 UI 界面的操作流程。

用户应当拿着订阅链接，点几下鼠标就能根据自己的实际情况配置出最佳效果，并自动享受完善的分流规则更新，而不是繁琐的"上传文件"、"手动修改参数"，甚至还得到处问问题。

### 改进尝试

基于这一点，我想改变 subconverter，让它更匹配现代 Clash 内核的使用场景。

可惜的是，我最常使用的 subconverter 分支仓库无法提交 PR、无法发起 Issue，连 Star 都被屏蔽了（可能是被维护者拉黑了）。

**既然无法贡献，那就自己动手吧。**

这就是 SubConverter-Extended 诞生的原因。

---

## 🎯 设计理念

- **Proxy-Provider 优先**：不再解析任何机场订阅链接，直接生成 `proxy-provider` 配置并填入订阅 URL，无需担心节点兼容性和机场屏蔽问题
- **100% Mihomo 兼容**：放弃人工维护的解析器，集成 Mihomo 最新内核解析器，原生支持所有节点协议
- **智能链接识别**：自动区分订阅链接和节点链接，采用最优处理策略
- **兼容订阅转换模板**：在 `proxy-provider` 配置的前提下，改进了模板转换策略，实现现有转换逻辑与 `proxy-provider` 的无缝匹配
- **兼容未来协议**：编译时自动读取 Mihomo 仓库源码，识别当前最新的节点协议和参数
- **角色定位改变**：由"中转站"变为"终点站"，成为用户可以自由使用的独立工具，不连接第三方，不被第三方屏蔽
- **现代化架构**：优化的 CI/CD 工作流、自动化依赖更新、完善的容器化支持

---

## ✨ 核心特性

### 🚀 相对原版的重大改进

| 功能 | 原版 Subconverter | SubConverter-Extended |
|------|-------------------|------------------------|
| **协议支持** | 人工维护解析器 | 集成 Mihomo 内核，编译时自动扫描支持所有新协议 |
| **订阅链接处理** | 下载并解析节点 | 生成 `proxy-provider`，由用户的 Mihomo 内核直接拉取 |
| **节点链接处理** | 有限的协议支持 | Mihomo 解析器 100% 兼容 |
| **配置文件大小** | 展开所有规则和节点 | ✅ 使用 provider 模式，配置精简 |
| **新协议支持** | 人工添加维护 | ✅ 编译时扫描 Mihomo 源码仓库，自动添加 |
| **全局参数透传** | 人工维护参数列表 | ✅ 编译时扫描 Mihomo 源码，自动识别可覆写参数 |

### 🔥 独特功能

#### 1. Proxy-Provider 模式

**使用 Mihomo 的 Proxy-Provider 机制**

订阅链接**不再下载解析**，而是生成客户端可直接使用的配置，交由用户客户端的 Mihomo 内核自行拉取订阅：

```yaml
proxy-providers:
  provider_1:
    type: http
    url: https://your-subscription-url
    interval: 3600
    path: ./providers/provider_1.yaml
    health-check:
      enable: true
      interval: 600
      url: http://www.gstatic.com/generate_204
```

**优势**：

- ✅ 不再干涉用户节点，交由内核原生处理
- ✅ 订阅更新由客户端控制，无需重新转换
- ✅ 支持订阅健康检查和自动切换
- ✅ 避免机场屏蔽转换服务器的问题

#### 2. Mihomo 内核模块集成

直接使用 Mihomo Go 库解析节点链接，确保：

- ✅ 支持 Mihomo 的所有协议（包括 `hysteria2`, `tuic`, `anytls` 等）
- ✅ 参数完全兼容，无需手动适配
- ✅ 新协议零延迟支持（编译时跟随 Mihomo 更新）

#### 3. 新手友好

- ✅ 使用 [Custom_OpenClash_Rules](https://github.com/Aethersailor/Custom_OpenClash_Rules) 项目的远程配置模板替代了默认的内置模板
- ✅ 锁死 API 模式，避免新手部署时误配置降低安全性
- ✅ 简化参数，专注核心功能

---

## 🚀 快速开始

### Docker 一键部署（推荐）

#### 基础部署

```bash
docker run -d \
  --name subconverter \
  -p 25500:25500 \
  --restart unless-stopped \
  aethersailor/subconverter-extended:latest
```

访问 `http://localhost:25500/version` 验证部署。

#### 自定义配置部署

```bash
# 创建配置目录
mkdir -p ~/subconverter/base

# 下载配置文件模板（可选）
wget -O ~/subconverter/base/pref.toml \
  https://raw.githubusercontent.com/Aethersailor/SubConverter-Extended/master/base/pref.example.toml

# 启动容器并挂载配置
docker run -d \
  --name subconverter \
  -p 25500:25500 \
  -v ~/subconverter/base:/base \
  --restart unless-stopped \
  aethersailor/subconverter-extended:latest
```

### Docker Compose 部署

创建 `docker-compose.yml`：

```yaml
version: '3.8'

services:
  subconverter:
    image: aethersailor/subconverter-extended:latest
    container_name: subconverter
    ports:
      - "25500:25500"
    volumes:
      - ./base:/base  # 可选：挂载自定义配置
    restart: unless-stopped
    environment:
      - TZ=Asia/Shanghai  # 可选：设置时区
```

启动服务：

```bash
docker-compose up -d
```

---

## 📚 使用文档

使用方式与原版 subconverter 完全相同。

### 基础转换

将机场订阅转换为 Clash 配置：

```bash
curl "http://localhost:25500/sub?target=clash&url=https://your-sub-url"
```

### 推荐配置

配合 [Custom_OpenClash_Rules](https://github.com/Aethersailor/Custom_OpenClash_Rules) 项目使用：

```bash
curl "http://localhost:25500/sub?target=clash&url=YOUR_SUB&config=https://raw.githubusercontent.com/Aethersailor/Custom_OpenClash_Rules/main/cfg/Custom_Clash.ini"
```

### 常用参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `target` | 目标格式 | `clash`, `surge`, `quanx` |
| `url` | 订阅链接或节点链接（`\|` 分隔） | `https://sub.com\|vless://...` |
| `config` | 外部配置文件 | `https://config-url` |
| `include` | 包含节点（正则） | `香港\|台湾` |
| `exclude` | 排除节点（正则） | `过期\|剩余` |
| `emoji` | 添加 Emoji | `true`/`false` |

### 持久化配置

配置文件目录结构：

```
~/subconverter/base/
├── pref.toml           # 主配置文件
├── snippets/           # 配置片段
├── profiles/           # 配置文件
└── rules/              # 自定义规则
```

---

## 🛠️ 配置说明

### 主配置文件

支持三种格式：`pref.toml`（推荐）、`pref.yml`、`pref.ini`

关键配置项：

```toml
[common]
api_mode = true                    # API 模式（强制开启）
default_url = []                   # 默认订阅（已禁用，必须传 url 参数）
enable_insert = true               # 启用节点插入

[node_pref]
udp_flag = false                   # UDP 支持
tfo_flag = false                   # TCP Fast Open
skip_cert_verify_flag = false      # 跳过证书验证

[managed_config]
managed_config_prefix = "http://localhost:25500"  # 托管配置前缀
```

### 外部配置示例

外部配置文件示例（INI 格式）：

```ini
[custom]
clash_rule_base = https://your-template-url

[proxy_group]
custom_proxy_group = `[]🚀 节点选择`select`.*`[]🇭🇰 香港节点`[]🇨🇳 台湾节点

[ruleset]
ruleset = DIRECT,https://raw.githubusercontent.com/.../ChinaDomain.list
ruleset = Proxy,https://raw.githubusercontent.com/.../ProxyGFWlist.list
```

---

## 🤝 致谢

本项目使用或引用了以下开源项目，在此表示感谢：

- [Mihomo](https://github.com/MetaCubeX/mihomo) - Clash 内核，提供节点解析能力
- [OpenClash](https://github.com/vernesong/OpenClash) - OpenWrt 平台的 Clash 图形化管理工具
- [Custom_OpenClash_Rules](https://github.com/Aethersailor/Custom_OpenClash_Rules) - OpenClash 规则集项目
- [subconverter](https://github.com/asdlokj1qpi233/subconverter) - 原版项目

---

## 📄 开源协议

本项目基于 [GPL-3.0](LICENSE) 协议开源。

内置的 Mihomo 解析器模块遵循 [MIT](https://github.com/MetaCubeX/mihomo/blob/Meta/LICENSE) 协议。

---

<div align="center">

**如果这个项目对你有帮助，请给个 ⭐ Star 支持一下！**

Made with ❤️ by [Aethersailor](https://github.com/Aethersailor)

</div>
