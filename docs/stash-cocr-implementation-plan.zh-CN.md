# Stash 与 COCR 分阶段实施和验收记录

本文档是 Stash 与 Custom_OpenClash_Rules（下称 COCR）后续工作的唯一阶段账本。每次实施应先更新本文件中的状态，再按既定顺序完成源代码、持续集成、镜像、开发环境和公开接口验收。任何一层没有通过，都不得用其他层的成功替代。

## 不可变边界

- SubConverter-Extended 只在 `dev` 分支实施；不合并 `master`，不创建 Release。
- 禁止本地编译。代码必须先提交并推送，再由 GitHub Actions 编译和运行测试。
- 不新增仓库测试文件；只扩展现有测试、现有 smoke 和临时外部 fixture。
- Clash、ClashR 与 Mihomo 路径必须保持隔离；既有 target、旧配置文件和旧外部配置不得要求迁移。
- Stash 使用独立 base、独立节点生成器、独立 proxy-provider 和独立 rule-provider 投影，不复用 Mihomo 专有输出字段。
- 不能被 Stash 官方格式精确表达的输入必须失败关闭，不能静默删除或降级。
- 没有 Stash 真机时，只能证明官方配置契约、服务端行为和真实开发容器输出；不得宣称客户端导入、刷新或代理连通已经通过真机验收。
- 用户未跟踪文件不得进入提交。当前必须排除 `.codex-version-build-id-fix-plan.md`。

## 固定推送与验收顺序

每个会改变运行结果的阶段均按以下顺序执行：

1. 更新本文件中的阶段设计、风险和停止条件。
2. 实施最小闭环修改，扩展既有测试；不在本机编译。
3. 独立复核工作树、目标隔离、敏感信息和旧配置兼容性。
4. 精确暂存所需文件，检查 staged diff，使用 Conventional Commits 提交。
5. 推送当前分支，记录产品提交 SHA；不得把自动生成的后继提交误当产品提交。
6. 等待该产品 SHA 对应的 Build/Test、Docker 和 CodeQL；任一失败即停止，定位后以新提交重跑。
7. 核对 Docker Hub 与 GHCR 的目标标签、平台 manifest、OCI revision 和镜像摘要。
8. 在 RackNerd 开发环境部署精确 OCI；部署前后复核现有 pref 和 Compose 文件哈希不变。
9. 验证 `/healthz`、带 CORS 头的 `/version`、容器 image ID、restart/OOM 状态和完整 smoke。
10. 只有前一仓库的公开开发接口通过后，才能修改依赖它的 COCR 模板。
11. COCR 推送后等待其验证、生成和发布链；识别自动生成的最终提交，并以最终公开文件为准验收。
12. 使用公开开发实例逐个验证模板：HTTP 状态、YAML 结构、Stash provider/rule-provider 引用闭包、Explain 统计、日志脱敏和不回源行为。

任何阶段失败时，先记录失败层、失败 SHA、Actions run 或 OCI revision，再修复并从该阶段第 2 步重新开始。不得跳过失败门禁继续部署。

## 阶段一：Stash rule-provider 独立投影

状态：`源码与既有测试已完成，等待推送及 Actions 验收`

目标：把 Stash 规则集生成从 `rulesetToClash` 中拆出，并让 Stash 直接读取符合官方契约的远程规则集，不再由服务端先抓取、展开再重写。

实施范围：

- 为规则集刷新增加 Stash 专用的保留模式。仅对明确的 HTTP(S) typed source 保留 URL；其他 target 继续沿用原抓取流程。
- 新增 `rulesetToStash`。官方可直接投影的矩阵为：
  - `clash-domain`：YAML、text、MRS；
  - `clash-ipcidr`：YAML、text、MRS，可保留 `no-resolve`；
  - `clash-classic`：YAML、text，不允许 MRS。
- `.mrs`、`.yaml`、`.yml` 可按无歧义后缀进入原生 provider；历史 `.txt`/`.list` 只有显式 `|stash-format=text` 时才进入原生 provider，否则继续复用启动时的服务端缓存，避免把 YAML payload 误标成 text。
- 生成官方字段 `behavior`、`format`、`url`、`path`、`interval`、`headers`（如来源有明确支持）；不得输出 Mihomo 的 `type: http`、`proxy`、`health-check`、`override` 等字段。
- provider 名称和本地 path 必须确定性生成、大小写无冲突，并与基础模板已有 provider 合并校验。
- inline 或必须服务端展开的规则只能使用 Stash 官方规则类型；遇到不支持类型、空规则集、未知格式、危险 URL、悬空引用或数量上限时返回 HTTP 400。
- 增加 Stash 规则统计：输入规则集、内联规则、远程 rule-provider、不支持规则集；写入 Explain 和脱敏日志。

兼容门禁：

- Clash/ClashR 对同一 fixture 的输出保持原行为。
- Stash rule-provider URL 不被服务端访问；dead URL 仍能生成 provider。
- 旧 INI/YAML/TOML 无新必填键，服务正常启动。
- 规则源 URL、请求头和 token 不得进入日志或 Explain 明文。

验收用例（扩展现有 compatibility baseline 和 smoke）：

- domain/ipcidr 的 YAML、text、MRS 正向用例；classical YAML/text 正向用例。
- classical MRS、未知后缀、不支持内联规则、provider/path 冲突、悬空 RULE-SET 负向用例。
- `no-resolve` 只出现在 ipcidr 引用。
- 覆盖 `overwrite_original_rules`、基础模板既有 rules/rule-providers、规则数量上限。
- Explain 计数与生成 YAML 一致；unsupported-only 请求必须 400。
- 同一规则 fixture 的 Clash 控制输出不变。

阶段证据：

- 产品提交：`待填写`
- Build/Test：`待填写`
- CodeQL：`待填写`
- OCI revision/digest：`待填写`
- RackNerd 开发环境：`待填写`

## 阶段二：开发镜像与当前 COCR 模板基线验收

状态：`待阶段一通过`

目标：证明新的 Stash 规则投影已进入真实开发镜像，并量化当前 COCR Clash 模板在 Stash 目标下仍存在的差异，避免把结构合法误报为完整兼容。

实施和验收：

- 部署阶段一的精确 OCI，不替换部署者现有 pref 或 Compose 文件。
- 运行完整 `--verify-non-clash` smoke，并增加 dead rule-provider、不回源、MRS、Explain 和日志脱敏检查。
- CI 的干净容器运行完整通用 smoke；挂载部署者旧 pref 的 RackNerd 环境不清空现有过滤设置，而是先冻结部署前代表请求的状态和正文哈希，部署后逐项对比，再运行与旧过滤无关的 Stash 专项请求。两类 smoke 的成功不能互相替代。
- 使用公开开发实例转换现有 COCR Standard、Lite、GFW、Full、Fallback 等模板。
- 记录每个模板的源 ruleset 数、生成 rule-provider 数、内联规则数、策略组数和失败原因。
- 明确标记当前 Clash 模板中的 Stash 不可移植内容，例如不受支持的规则类型、MRS behavior 错配、Clash 专用分组选项或不能证明等价的筛选表达式。

停止条件：任一现有非 Stash target 的回归、OCI revision 不匹配、配置哈希变化、容器重启/OOM、公开开发接口与容器输出不一致。

阶段证据：

- 部署前镜像和配置哈希：`待填写`
- 部署后 image ID/version：`待填写`
- 当前 COCR 矩阵：`待填写`

## 阶段三：COCR 的 Stash 专用模板生成

状态：`待阶段二通过`

目标：从 COCR 的共同规则意图确定性生成 Stash 专用模板；不手工复制形成第二套易漂移配置，也不修改现有 Clash 模板的语义和字节内容。

实施范围：

- 在 COCR 现有生成脚本中增加 Stash 模板投影，不新建测试文件。
- 生成 Standard、Lite、GFW、Full 及其 Fallback 变体；Mainland 仅在存在独立用户价值时生成，不复制 OpenClash 专用兼容文件。
- typed rule source 使用阶段一确认的 Stash rule-provider 矩阵。
- 把 Stash 不支持的 COCR 规则意图替换为有来源、可验证的等价形式；不存在等价形式时生成检查失败，不能静默删除。
- 删除或拒绝 Stash 无法精确保留的 Clash 分组测速参数。复杂筛选只有在 Stash 官方正则能力可证明时才进入 native provider；否则保持服务端解析并在文档中说明。
- 更新现有验证脚本和工作流路径，使源模板变化会检查生成结果是否同步；保留现有主分支写入串行化和自动生成提交识别。
- 为访客提供显式 `target=stash` 示例、公共实例 URL 结构、规则/provider 刷新契约和真机边界。

兼容门禁：

- 现有 `Custom_Clash*.ini` 和生成的 Clash 规则产物保持不变。
- COCR 生成器重复运行必须无 diff。
- 所有 Stash 模板必须能通过公开开发实例转换，且最终 YAML 引用闭包完整。
- 不把未验证的 Stash UA、私有 URI 或客户端行为写成确认事实。

阶段证据：

- COCR 产品提交：`待填写`
- 自动生成最终提交：`待填写`
- Actions：`待填写`
- 公开文件 URL 和哈希：`待填写`

## 阶段四：公开开发实例端到端验收

状态：`待阶段三通过`

目标：按真实用户路径验证“订阅 URL + COCR Stash 模板 + 公共开发实例”的完整服务端结果。

逐模板检查：

- `target=stash`、订阅 URL、远程 `.ini` 模板能成功组合。
- 输出包含 Stash DNS 安全默认、直连节点、proxy-provider、rule-provider、策略组和最终规则。
- provider URL 保持原样且未被服务端抓取；rule-provider 的 behavior/format/path/interval 与来源匹配。
- `RULE-SET`、`use`、`proxies`、`ssid-policy`、sub-rules 和 script 引用均闭合，不存在循环或重名。
- Explain 的 backend、provider/ruleset/node 计数与 YAML 一致；日志不含订阅 token、认证头、密码或完整私密 URL。
- unsupported-only 请求返回 400；混合输入只在契约允许时返回 200，并准确报告不支持项。
- Clash、ClashR、v2rayN/v2rayNG、Surge、QuanX、Loon、Shadowrocket 和 sing-box 的既有代表请求保持成功。

阶段证据：

- 公共开发实例 version：`待填写`
- 模板通过矩阵：`待填写`
- 日志与隐私审计：`待填写`

## 阶段五：最终审计和维护交接

状态：`待阶段四通过`

目标：确认代码、文档、CI、镜像、运行实例和公开模板引用同一组可追踪事实，并给出清晰的长期维护边界。

最终审计：

- 源提交、Actions head SHA、OCI revision、RackNerd `/version` 和 COCR 公共文件 SHA 可相互追踪。
- 两个仓库均无遗漏的产品文件、意外测试文件或用户未跟踪文件。
- 旧配置快照、热重载、安装/便携包资源和部署配置哈希保持兼容。
- README 面向用户说明：如何调用公共实例、provider/rule-provider 的上游内容契约、错误诊断和真机尚未验证的边界。
- 记录仍需真实 Stash 设备完成的独立验收：配置导入、provider 刷新、DNS 查询、规则命中和代理连通。

只有以上全部通过，才能把本轮服务端与公开模板工作标记为“完成”。
