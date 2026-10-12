# 贡献指南

SubConverter-Extended 接受缺陷修复、兼容性改进、文档修正和可验证的功能建议。提交前，请先确认现有 README、[Wiki](https://github.com/Aethersailor/SubConverter-Extended/wiki) 和 [Issue](https://github.com/Aethersailor/SubConverter-Extended/issues) 尚未解决同一问题。

## 分支与文档边界

- `dev` 是代码和贡献的集成分支；所有 PR 都应以 `dev` 为目标分支。
- `master` 由发布流程从 `dev` 同步，用于正式 Release；不要直接向 `master` 提交 PR。
- README、Wiki 和 Docker Hub 说明面向用户，只描述当前正式 Release 和与之对应的 Docker `latest`。尚未发布的行为只应出现在贡献说明、代码注释或内部开发文档中。

## 提交流程

1. 从最新 `dev` 创建功能分支。
2. 只修改解决当前问题所必需的文件，并保留现有兼容性边界。
3. 使用 Conventional Commits：`<type>(<scope>): <concise description>`。
4. 完成与改动相关的构建和人工验证，记录实际结果及未验证的范围。
5. 向 `dev` 提交 PR，说明问题、方案、兼容性影响和验证结果。只在已有可跟踪项时引用实际 Issue；不要猜测编号。

## 人工验证

- 转换逻辑或配置解析变更：使用受影响的输入格式和目标客户端，检查实际转换结果；涉及兼容性时，同时检查原有用法。
- Mihomo 解析桥变更：按 [`bridge/README.md`](bridge/README.md) 的顺序运行生成器并重新构建，再检查受影响的订阅输入。
- 构建或打包变更：构建对应平台的制品，检查安装、启动和版本信息。
- 用户文档变更：核对命令、路径、默认值、内部链接和目标格式，并确认内容仅描述已发布能力。

仓库不再维护自动化测试或 PR 验证门禁。CodeQL 独立扫描 `dev` 的源码，不作为自动合并或发布的前置条件。构建和发布流程继续负责生成制品、记录版本身份和防止覆盖历史版本；功能与兼容性由维护者人工验证。

## 敏感信息和安全问题

不要在 Issue、PR、日志、截图、样例或复现数据中提交真实订阅 URL、节点凭据、Token、Cookie、私有主机名或其他秘密。使用 `example.com`、保留的测试网段和明确的占位符构造最小复现。

未修复的安全漏洞请通过 [GitHub 私密漏洞报告](https://github.com/Aethersailor/SubConverter-Extended/security/advisories/new) 提交，不要创建公开 Issue。
