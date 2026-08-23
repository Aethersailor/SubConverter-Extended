# 安全策略

## 支持范围

SubConverter-Extended 只为当前最新正式 Release 提供安全修复。请先通过 [`/version`](https://api.asailor.org/version) 记录版本和源代码修订，并在报告中说明部署方式。

Docker 用户应使用与最新正式 Release 对应的 `latest` 或版本标签。旧版本可能不再接受单独修复。

## 私密报告漏洞

如果问题可能导致未授权访问、服务端请求伪造（SSRF）、路径或文件边界绕过、凭据泄漏、远程代码执行或其他安全影响，请使用 GitHub 的私密报告入口：

<https://github.com/Aethersailor/SubConverter-Extended/security/advisories/new>

不要在公开 Issue、Discussion、PR 或社交平台中披露未修复漏洞的利用细节。

报告建议包含：

- 受影响的版本和源代码修订；
- 部署方式、安全档位和相关配置；
- 攻击前置条件、可观察影响和最小复现步骤；
- 已确认的缓解方式（如有）；
- 经过脱敏的状态码、`X-Request-ID` 和日志片段。

请不要提交真实订阅 URL、节点凭据、Token、Cookie、用户数据或无关系统的秘密。如果复现必须使用敏感材料，请先在私密报告中说明，不要上传到公开仓库。

## 非安全问题

一般转换失败、第三方订阅不可达、客户端不兼容或配置错误，请先阅读 [Wiki 故障排查](https://github.com/Aethersailor/SubConverter-Extended/wiki/Troubleshooting)，再使用 [Bug 反馈表单](https://github.com/Aethersailor/SubConverter-Extended/issues/new?template=bug_report.yml)。

---

## English summary

Security fixes target the latest stable Release. Report suspected vulnerabilities privately through [GitHub Security Advisories](https://github.com/Aethersailor/SubConverter-Extended/security/advisories/new). Do not publish exploit details or real subscription URLs, credentials, tokens, cookies, or user data in public issues.
