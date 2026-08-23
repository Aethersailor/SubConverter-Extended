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
4. 运行与改动相关的现有测试和检查。
5. 向 `dev` 提交 PR，说明问题、方案、兼容性影响和验证结果。只在已有可跟踪项时引用实际 Issue；不要猜测编号。

## 验证入口

- C++ 、配置解析、安全基线或交付脚本变更：按 [PR Validation](.github/workflows/pr-validation.yml) 中的对应任务运行现有检查。
- Mihomo 解析桥变更：在 `bridge/` 中运行 `go test ./...`；生成能力文件时，按 [`bridge/README.md`](bridge/README.md) 的顺序执行生成器。
- 用户文档变更：核对命令、路径、默认值、内部链接和目标格式，并确认内容仅描述已发布能力。

CI 是必要验证，但不代替与改动对应的本地检查和实际输出验证。

## 敏感信息和安全问题

不要在 Issue、PR、日志、截图、样例或测试数据中提交真实订阅 URL、节点凭据、Token、Cookie、私有主机名或其他秘密。使用 `example.com`、保留的测试网段和明确的占位符构造最小复现。

未修复的安全漏洞请通过 [GitHub 私密漏洞报告](https://github.com/Aethersailor/SubConverter-Extended/security/advisories/new) 提交，不要创建公开 Issue。
