<div align="center">

<p>
  <img src="design/favicon-light-proposal.svg#gh-light-mode-only" alt="SubConverter-Extended icon" width="96" height="96">
  <img src="design/favicon-dark-proposal.svg#gh-dark-mode-only" alt="SubConverter-Extended icon" width="96" height="96">
</p>

# SubConverter-Extended

**An enhanced subscription conversion backend for multiple proxy clients**

English · [简体中文](README-zh-CN.md)

[![GitHub Tag](https://img.shields.io/github/v/tag/Aethersailor/SubConverter-Extended?style=flat&logo=github&label=version&color=blue)](https://github.com/Aethersailor/SubConverter-Extended/releases/latest)
[![Release](https://img.shields.io/github/actions/workflow/status/Aethersailor/SubConverter-Extended/release.yml?style=flat&label=release&logo=githubactions)](https://github.com/Aethersailor/SubConverter-Extended/actions/workflows/release.yml)
[![Docker Pulls](https://img.shields.io/docker/pulls/aethersailor/subconverter-extended?style=flat&logo=docker)](https://hub.docker.com/r/aethersailor/subconverter-extended)
[![License](https://img.shields.io/badge/license-GPL--3.0-orange?style=flat)](LICENSE)
[![Wiki](https://img.shields.io/badge/Wiki-Full%20User%20Guide-2f81f7?style=flat&logo=github)](https://github.com/Aethersailor/SubConverter-Extended/wiki)

[🧭 Start by Task](#start-by-task) · [🔗 Related Projects](#related-projects) · [💡 Why This Project Exists](#why-this-project-exists) · [🚀 Quick Start](#quick-start) · [📚 Full Wiki](https://github.com/Aethersailor/SubConverter-Extended/wiki)

</div>

---

> [!WARNING]
> This software is intended solely for study and research outside the People's Republic of China.
>
> **Organizations and individuals are prohibited from accessing, downloading, deploying, or using any part of this project in mainland China. If you are in mainland China, close this page immediately.**
>
> Organizations and individuals must not use any part of this project for activities that violate applicable laws or regulations. Users are individually responsible for the legal consequences of their use.

The default branch, `dev`, is for development and contributions. This README describes the current stable release. For deployment, use the [latest stable release](https://github.com/Aethersailor/SubConverter-Extended/releases/latest) or its corresponding Docker `latest` image. The `master` branch is reserved for stable releases.

<a id="overview"></a>

## 📖 Overview

SubConverter-Extended builds on [asdlokj1qpi233/subconverter](https://github.com/asdlokj1qpi233/subconverter) and extends it into a conversion backend for multiple proxy clients and subscription formats.

The project provides a dedicated parsing bridge and Proxy Provider support for Mihomo. It can generate native remote resources for Surge, Quantumult X, Loon, Surfboard, and Stash. The backend converts subscriptions for sing-box, Quantumult, and several legacy formats. Each target uses a conversion path suited to its configuration capabilities.

> [!IMPORTANT]
> **Maintenance priority**. Mihomo is the project's main focus. Improvements to parsing, Proxy Providers, and protocol parameters for `clash` and `clashr` take priority. Support for other clients will continue to improve, with the goal of providing complete and reliable conversions within each format's capabilities.

> [!IMPORTANT]
> **Project scope**
>
> This project provides no proxy servers, proxy nodes, or node subscriptions for users. It operates no commercial or other proxy services and provides no internet access services. Neither the project nor its maintainers partner with, represent, or act as guarantors for such providers.

<a id="start-by-task"></a>

### 🧭 Start by Task

| Task | Where to start |
| :--- | :--- |
| Generate your first configuration using the public instance | [Getting Started](https://github.com/Aethersailor/SubConverter-Extended/wiki/Getting-Started) |
| Find the right `target` for your client | [Clients and Target Formats](https://github.com/Aethersailor/SubConverter-Extended/wiki/Compatibility) |
| Deploy your own instance | [Docker Deployment](https://github.com/Aethersailor/SubConverter-Extended/wiki/Docker-Deployment) · [Native Deployment](https://github.com/Aethersailor/SubConverter-Extended/wiki/Native-Deployment) |
| Use OpenClash templates and rules | [Custom_OpenClash_Rules](https://github.com/Aethersailor/Custom_OpenClash_Rules) |
| Troubleshoot a failure or file a redacted report | [Troubleshooting](https://github.com/Aethersailor/SubConverter-Extended/wiki/Troubleshooting) · [Report a Bug](https://github.com/Aethersailor/SubConverter-Extended/issues/new?template=bug_report.yml) |

<a id="related-projects"></a>

### 🔗 Related Projects

| Project | What it does | Relationship to SubConverter-Extended |
| :--- | :--- | :--- |
| [Custom_OpenClash_Rules](https://github.com/Aethersailor/Custom_OpenClash_Rules) | Provides OpenClash templates, rules, and tutorials | Can supply templates and rules for conversion. OpenClash can also use them directly. |
| **SubConverter-Extended** | Converts subscriptions, templates, and rules into configurations for target clients | It does not collect Mihomo `MATCH` domains or supply subscriptions or nodes. |
| [Rule-Bot Client](https://github.com/Aethersailor/Rule-Bot-Client) | Collects domains from Mihomo connections that match the `MATCH` rule, stores them locally by default, and can optionally submit them | Helps identify missing rules. Subscription conversion works independently of it. |
| [Rule-Bot](https://github.com/Aethersailor/Rule-Bot) | Checks domains and submits them to the target rules repository according to its policy | The public Rule-Bot instance targets Custom_OpenClash_Rules. Self-hosted instances can maintain other repositories. |

A common workflow is **Custom_OpenClash_Rules template → optional conversion with SubConverter-Extended → Mihomo/OpenClash**. The rule feedback workflow runs independently of conversion. It goes from **Mihomo `MATCH` → optional submission by Rule-Bot Client → Rule-Bot → target rules repository**. You can deploy either workflow on its own.

### 🎯 Long-Term Vision

SubConverter-Extended aims to unify configuration conversion across clients. Users would maintain their own conversion template or choose a public template, add their proxy information (subscription URLs or node links), and generate configuration files for different clients.

> [!NOTE]
> This goal is still in progress. Clients differ in configuration structure, how they represent remote resources, protocol fields, and template capabilities. Some use cases still require client-specific configuration and processing. The latest stable release and the Wiki's compatibility documentation describe what is currently supported.

> [!TIP]
> First-time users can start with [Getting Started](https://github.com/Aethersailor/SubConverter-Extended/wiki/Getting-Started) and [Clients and Target Formats](https://github.com/Aethersailor/SubConverter-Extended/wiki/Compatibility) in the Wiki. For self-hosting, choose [Docker Deployment](https://github.com/Aethersailor/SubConverter-Extended/wiki/Docker-Deployment) or [Native Deployment](https://github.com/Aethersailor/SubConverter-Extended/wiki/Native-Deployment).

### 🔀 Two Ways to Handle Remote Subscriptions

<p align="center">
  <img src="docs/images/readme-flow-overview-en.svg" alt="How SubConverter-Extended handles remote subscriptions and node links" width="1100">
</p>

Whether the client updates a remote subscription depends on the target format, request parameters, and input type. See the Wiki page [Remote Subscriptions and Client Fetching](https://github.com/Aethersailor/SubConverter-Extended/wiki/Remote-Subscriptions) for the full behavior.

### 🛡️ Mihomo Proxy Provider Workflow Comparison

> [!NOTE]
> The diagrams compare only the default workflows for remote HTTP subscriptions with `target=clash` or `target=clashr`. Requests with `list=true` and other client targets follow their own workflows.

<p align="center">
  <img src="docs/images/readme-flow-legacy-en.svg" alt="How traditional subconverter handles remote subscription links" width="820">
</p>

<p align="center">
  <img src="docs/images/readme-flow-extended-en.svg" alt="The SubConverter-Extended workflow for Mihomo Proxy Providers" width="820">
</p>

### 🧩 Target Formats in the Current Release

| Conversion mode | Targets |
| :--- | :--- |
| Mihomo node parsing and Proxy Providers | `clash`, `clashr` |
| Client-native remote resources | `surge`, `quanx`, `loon`, `surfboard`, `stash` |
| Full configuration conversion | `quan`, `mellow`, `singbox` |
| Basic subscription or share-link output | `ss`, `ssd`, `ssr`, `sssub`, `v2ray`, `v2rayn`, `v2rayng`, `shadowrocket`, `trojan`, `vless`, `hysteria2`, `mixed` |

> [!NOTE]
> The table lists the explicit targets in the current stable release. Supported node types, transport parameters, and minimum client versions vary by target. For closed-source clients, verify import and connectivity in the client version you use. See [Clients and Target Formats](https://github.com/Aethersailor/SubConverter-Extended/wiki/Compatibility) for details.

---

<a id="why-this-project-exists"></a>

## 💡 Why This Project Exists

SubConverter-Extended grew out of the maintainer's long-term experience using subconverter. The project began with three problems to solve.

### 🐢 Protocol Support Lag

The subconverter node parser requires manual updates as protocols, transports, and parameters evolve. New protocols such as `hysteria2`, `tuic`, and `anytls` need individual support. Existing protocols such as `vless` also introduce new compatibility requirements as their transport parameters evolve. When the parser falls behind clients, converted configurations may omit fields that clients already support.

### 🚫 Access Restrictions Imposed by Remote Subscription Providers

With traditional subconverter, the conversion backend connects to the remote subscription server, downloads the subscription, and parses the nodes. Some remote subscription providers restrict requests from overseas IP addresses, requests using subconverter's User-Agent, or requests made outside the client. A client may be able to update a subscription directly while the conversion backend is unable to fetch the same content.

Changing the User-Agent only addresses restrictions based on that header. Regional or egress IP restrictions still apply, and matching each provider's requirements adds maintenance work for the converter.

### 🤯 Learning Curve for New Users

When protocol parsing, subscription fetching, or parameter conversion fails, users often have to edit YAML configurations or investigate the conversion themselves. Some developers and content creators have therefore started recommending that users maintain their YAML files by hand. For newcomers and typical users, that approach shifts the burden of understanding configuration structure, protocol fields, and troubleshooting onto them.

This follows the same principle the maintainer advocates in [Custom_OpenClash_Rules](https://github.com/Aethersailor/Custom_OpenClash_Rules).

> [!IMPORTANT]
> **A UI-based workflow remains the most broadly accessible option for newcomers and typical users.**

Ideally, users provide a subscription link, generate a configuration suited to their needs with a few steps in the UI, and let the template and client keep remote resources up to date without first maintaining a full YAML file by hand.

### 🛠️ From Contributing Fixes to Starting a Project

The maintainer tried to contribute improvements to the subconverter fork they used regularly. At the time, they could not open pull requests or issues in that repository or star it. The reason could not be confirmed, so the maintainer had no way to submit those improvements through that repository.

> **If we can't contribute to the original fork, we'll build the improvements ourselves.**

That is how SubConverter-Extended began. The initial approach had three parts.

- Keep the subscription conversion interface and UI workflow familiar to users.
- Generate `proxy-providers` for remote Mihomo subscriptions so the client can update them directly.
- Use Mihomo's parser to process node links and reduce the cost of maintaining duplicate protocol parsing logic.

The `proxy-providers` path reduces access problems that arise when the conversion backend fetches subscriptions on behalf of the client. The Mihomo parser keeps pace with Mihomo's protocol and parameter support. The project has since expanded from its original Mihomo/Clash use case to multiple clients. Mihomo remains the main focus, and support for other clients will continue to improve within the capabilities of their respective formats.

---

<a id="improvements-over-upstream"></a>

## ✨ Key Improvements over Upstream

| Area | Behavior in the current SubConverter-Extended release |
| :--- | :--- |
| Remote subscriptions across targets | Generates Mihomo Proxy Providers and client-native remote resources for Surge, Quantumult X, Loon, Surfboard, and Stash. |
| Mihomo node parsing | Node links for `target=clash` and `target=clashr` go exclusively through the Mihomo parsing bridge. Protocol support comes from the pinned Mihomo dependency. |
| Target-specific output | Provides dedicated output and capability-based filtering for targets such as Stash, Shadowrocket, v2rayN, and v2rayNG. When a target cannot represent a node, the converter filters it out or returns an explicit error. |
| Request diagnostics | `explain=true` returns redacted JSON diagnostics. `/inspect` provides a visual diagnostics console. A server-generated `X-Request-ID` correlates responses and logs. |
| Runtime statistics | Optional `/dashboard` and `/dashboard/data` endpoints support persistence, time-window statistics, geographic breakdowns, and optional Basic Auth. |
| Deployment security | Provides `lan`, `public`, and `strict` security levels, with separate controls for caller-controlled fetching, trusted local configuration, and upload permissions. |
| Outbound access | `proxy_config`, `proxy_ruleset`, and `proxy_subscription` use explicit Direct, System, Explicit, and Cors modes and support `proxy_bypass`. |
| Rule extensions | Supports `ruleprepend` and `ruleappend` for external full Clash rules, as well as the `no-resolve` option for `clash-ipcidr`. |
| Distribution | Available through Docker Hub and GHCR, with multi-architecture Linux portable packages, a Windows portable package, and OpenWrt APKs. Verification manifests are published with releases. |
| Runtime reliability | Adds request coalescing, response microcaching, bounded rule processing tasks, connection reuse, graceful shutdown, redaction of sensitive log fields, and configurable resource limits. |

> [!TIP]
> SubConverter-Extended handles high concurrency on public instances with bounded admission, cooperative asynchronous conversion, request coalescing, connection reuse, response microcaching, and execution resource isolation. Operators of public instances can also enable `force_max` to maximize throughput within the resource limits detected by the application. This mode can substantially increase CPU, memory, thread, and connection usage. It is generally discouraged for personal deployments. See [`force_max` Performance Mode](https://github.com/Aethersailor/SubConverter-Extended/wiki/Force-Max-Mode) in the Wiki for use cases, configuration, runtime effects, and deployment requirements.

See [Upstream Relationship and Support Scope](https://github.com/Aethersailor/SubConverter-Extended/wiki/Support-and-License) for the full list of differences, limitations, and compatibility behavior.

### 🧰 Extended Parameter Examples

These extensions help with subscription updates and troubleshooting. The examples show common ways to use them. See [Extended Parameters and Syntax](https://github.com/Aethersailor/SubConverter-Extended/wiki/Feature-Parameters) for precedence, defaults, and error conditions.

```text
# Set a custom provider name and update interval
provider:HK,interval:21600,https://example.com/sub

# Omit proxy: DIRECT for this Mihomo provider
proxy_direct:false,https://example.com/sub

# Override the Mihomo provider's direct-connection policy for the entire request
&provider_proxy_direct=false

# Return a redacted diagnostics report in place of a configuration file
&explain=true
```

Rules and external configurations also support the following options.

- `ruleprepend` / `ruleappend` insert remote rule sources at the beginning or end of the full Clash rule list, respectively.
- `28800|no-resolve` adds `no-resolve` to a `clash-ipcidr` rule set reference.
- `provider_headers` selects allowed headers from the current request and writes them into Clash or Stash providers.
- `[proxy_provider]` sets deployment-wide defaults for the provider update interval and `proxy: DIRECT` behavior.

---

<a id="quick-start"></a>

## 🚀 Quick Start

You can use the public instance or deploy your own. The public instance requires no service maintenance on your part. Self-hosting gives you control over security policies, outbound access, and data boundaries.

### 🌍 Use the Public Instance

The public instance is available at the following address.

```text
https://api.asailor.org
```

Visit [`/version`](https://api.asailor.org/version) to check the current release identity, then follow [Getting Started](https://github.com/Aethersailor/SubConverter-Extended/wiki/Getting-Started) to generate your first request.

> [!WARNING]
> The public instance does not safeguard your subscription secrets. The conversion request can still contain the subscription URL even when the backend skips downloading the subscription content in Proxy Provider mode. Your browser, network ingress, CDN, or reverse proxy may also see request details. For sensitive subscriptions, self-host the service and read [Security and Privacy](https://github.com/Aethersailor/SubConverter-Extended/wiki/Security-and-Privacy).

> [!IMPORTANT]
> The dedicated Stash template is an exception to the usual default output, which is minimal and lacks full DNS settings. Enable DNS overrides in your client or use a custom base template with DNS settings. Without one of these, the client may fail to resolve node hostnames.

### 🐳 Self-Host with Docker

```bash
docker run -d \
  --name SubConverter-Extended \
  -p 25500:25500 \
  --restart unless-stopped \
  aethersailor/subconverter-extended:latest
```

Check the service at these endpoints.

```text
http://localhost:25500/version
http://localhost:25500/healthz
```

> [!NOTE]
> This minimal startup command does not persist custom configurations or statistics. The `-p 25500:25500` option also publishes the port on all host interfaces. To retain configurations or statistics, follow [Docker Deployment](https://github.com/Aethersailor/SubConverter-Extended/wiki/Docker-Deployment) in the Wiki to configure persistent directories, and choose the security level that fits your network exposure.

### 📦 Available Distribution Formats

| Distribution | Support in the current release |
| :--- | :--- |
| Docker | Docker Hub and GHCR for `linux/amd64`, `linux/arm64`, and `linux/arm/v7` |
| Linux portable packages | `amd64`, `arm64`, `armv7` |
| Windows portable package | `windows-amd64.zip` |
| OpenWrt APK | Unsigned packages for multiple `apk` architectures on OpenWrt 25.12 and later |
| Integrity verification | `SHA256SUMS` and `RELEASE-MANIFEST.json` |

Download from the [latest release](https://github.com/Aethersailor/SubConverter-Extended/releases/latest).

---

## 🧭 Documentation

| Task | Documentation |
| :--- | :--- |
| Check whether the project supports your client | [Clients and Target Formats](https://github.com/Aethersailor/SubConverter-Extended/wiki/Compatibility) |
| Use the public instance | [Getting Started](https://github.com/Aethersailor/SubConverter-Extended/wiki/Getting-Started) |
| Self-host with Docker | [Docker Deployment](https://github.com/Aethersailor/SubConverter-Extended/wiki/Docker-Deployment) |
| Deploy on Linux, Windows, or OpenWrt | [Native Deployment](https://github.com/Aethersailor/SubConverter-Extended/wiki/Native-Deployment) |
| Evaluate maximum-throughput mode for a public service | [`force_max` Performance Mode](https://github.com/Aethersailor/SubConverter-Extended/wiki/Force-Max-Mode) |
| Understand `/sub` and common parameters | [Basic Conversion](https://github.com/Aethersailor/SubConverter-Extended/wiki/Basic-Conversion) |
| Use extended parameters | [Extended Parameters and Syntax](https://github.com/Aethersailor/SubConverter-Extended/wiki/Feature-Parameters) |
| Configure templates and rules | [External Configuration and Templates](https://github.com/Aethersailor/SubConverter-Extended/wiki/External-Configuration) · [Rules and Rule Sets](https://github.com/Aethersailor/SubConverter-Extended/wiki/Rules-and-Rulesets) |
| Configure security for public deployments and outbound proxies | [Security and Privacy](https://github.com/Aethersailor/SubConverter-Extended/wiki/Security-and-Privacy) · [Outbound Proxy](https://github.com/Aethersailor/SubConverter-Extended/wiki/Outbound-Proxy) |
| Use the diagnostics console and dashboard | [Diagnostics](https://github.com/Aethersailor/SubConverter-Extended/wiki/Diagnostics) · [Dashboard and Statistics](https://github.com/Aethersailor/SubConverter-Extended/wiki/Dashboard-and-Statistics) |
| Troubleshoot conversion or deployment failures | [Troubleshooting](https://github.com/Aethersailor/SubConverter-Extended/wiki/Troubleshooting) |
| Find all API parameters | [API Reference](https://github.com/Aethersailor/SubConverter-Extended/wiki/API-Reference) |

See the [SubConverter-Extended Wiki](https://github.com/Aethersailor/SubConverter-Extended/wiki) for the full documentation index.

---

## 🔐 Security, Compliance, and Usage Boundaries

- The project does not provide subscription services or proxy nodes. Rule conversion does not grant the right to redistribute third-party content.
- The project cannot guarantee that every subscription can be fully represented in every target client.
- Self-hosted operators are responsible for TLS, access controls, firewalls, logs, backups, and updates.
- `lan` is the default security level for compatibility with existing deployments. Exposing a service with this setting directly to the internet can be unsafe.
- Project logs redact known sensitive fields. This redaction does not provide general-purpose data leak prevention.
- Report unpatched vulnerabilities privately through the [Security Policy](SECURITY.md). Keep exploitation details out of public issues.

> [!WARNING]
> The project remains neutral and provides no features for evading regulatory controls. It is intended only for learning computer technology and converting configurations in lawful contexts. Users must comply with local laws and regulations and with the terms of use of remote service providers.

---

## 📦 Get the Stable Release

Stable releases are the versions intended for users. Docker `latest` is updated after a stable release has been verified and points to that release's versioned image.

| Distribution | Where to get it | Use |
| :--- | :--- | :--- |
| Docker `latest` | Docker Hub or GHCR | Default installation and updates |
| Versioned Docker tag | The same `vX.Y.Z` as the stable release | Version pinning and rollback |
| Portable packages and OpenWrt APKs | [Latest release](https://github.com/Aethersailor/SubConverter-Extended/releases/latest) | Native deployment and integrity verification |

The feature descriptions apply to the current stable release. When reporting a problem, include the version and source revision shown by `/version`.

---

## 🤝 Acknowledgments and License

This project uses or references the following open-source projects.

- [asdlokj1qpi233/subconverter](https://github.com/asdlokj1qpi233/subconverter) is the upstream foundation.
- [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) provides Mihomo node parsing.
- [Aethersailor/Custom_OpenClash_Rules](https://github.com/Aethersailor/Custom_OpenClash_Rules) provides OpenClash templates, rules, and user tutorials.

SubConverter-Extended is released under [GPL-3.0](LICENSE). The Mihomo dependency used by the Mihomo parsing bridge is also under GPL-3.0. See `bridge/go.mod` for the exact dependency version.

---

## ⭐ Star History

<div align="center">
  <a href="https://www.star-history.com/?type=date&repos=Aethersailor%2FSubConverter-Extended">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=Aethersailor/SubConverter-Extended&type=date&theme=dark&legend=top-left&sealed_token=NKvX6WwN3no1B0JCAxO5Tkk4nqJLR5HppGP59Pp9IDkrygstiLYT8T8_MsYyG-hqMAuML_mTOU2N1PX79o9ZgwfXacAhIBKClQskYzigRVD1FQyH66FGwA">
      <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=Aethersailor/SubConverter-Extended&type=date&legend=top-left&sealed_token=NKvX6WwN3no1B0JCAxO5Tkk4nqJLR5HppGP59Pp9IDkrygstiLYT8T8_MsYyG-hqMAuML_mTOU2N1PX79o9ZgwfXacAhIBKClQskYzigRVD1FQyH66FGwA">
      <img alt="SubConverter-Extended star history" src="https://api.star-history.com/chart?repos=Aethersailor/SubConverter-Extended&type=date&legend=top-left&sealed_token=NKvX6WwN3no1B0JCAxO5Tkk4nqJLR5HppGP59Pp9IDkrygstiLYT8T8_MsYyG-hqMAuML_mTOU2N1PX79o9ZgwfXacAhIBKClQskYzigRVD1FQyH66FGwA">
    </picture>
  </a>
</div>

## 📊 Repository Activity

<p align="center">
  <img src="https://repobeats.axiom.co/api/embed/c249ae5c34b99a067c78e9216600c1a5eac16c65.svg" alt="SubConverter-Extended repository activity statistics">
</p>

---

<div align="center">

If you find the project useful, give it a ⭐ to support its continued maintenance.

Made with ❤️ by [Aethersailor](https://github.com/Aethersailor)

</div>
