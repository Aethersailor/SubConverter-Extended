# SubConverter-Extended force_max 综合最终实施方案

## 文档状态

- 状态：已授权实施；阶段 0～14 已完成，阶段 15 待开始。
- 目标分支：`dev`。
- 阶段 0 规划基线：`6d5dcddd2810bbe95fb7e2bbf4f924c7a4cc536f`。
- 范围：源码、测试、dev CI、dev OCI、HostBrr 测试实例和公开测试路径。
- 排除：`master`、正式实例、tag、Release、`:latest`。
- 本文是本轮 `force_max` 改造的唯一实施账本；既有 v2 和高并发文档保留历史证据，但未完成设计以本文为准。
- 每个阶段必须独立提交、独立验证、独立回滚；任一必需门失败时停止，不允许用后续阶段掩盖。

## 阶段执行账本

| 阶段 | 状态 | 产品源码 SHA | 验证/交付 | 备注 |
|---|---|---|---|---|
| 0 基线与账本 | 已完成 | `6d5dcddd2810bbe95fb7e2bbf4f924c7a4cc536f` | Linux CTest 28/28；Python 36/36；Go/Shell/Actionlint；本地 OCI smoke | 账本提交 `cb834f69` |
| 1 pipeline 拆分 | 已完成 | `f6c66b70271f7f816a3b5b85e94a40753116774a` | Linux CTest 28/28；本地 force_max OCI smoke；既有输出哈希断言 | 纯机械拆分；无线程和行为变化 |
| 2 预算数据合同 | 已完成 | `a3c219e4d277008657c9970d73de87adf3045095` | Linux CTest 28/28；确定性/单调/溢出/分数 CPU/低 FD 测试；OCI smoke | provisional 预算只进入诊断，未应用到运行参数 |
| 3 ComputeExecutor | 已完成 | `d252740ffc7edb9ee533a21497868078b9e507e8` | Release 与 ASan/UBSan CTest 各 28/28；生命周期/边界/取消/自 join 测试 | 尚未承载正式 flow |
| 4 async fetch 合同 | 已完成 | `ac810e50ea38b8cd37b56ed17e8430bb20634995` | Release 与 ASan/UBSan CTest 各 28/28；force_max OCI smoke | 无缓存 GET、绝对 deadline、冻结设置和启动/关闭已接通 |
| 5 ConversionFlow | 已完成 | `cbd0b2d5d1e9fb0e6a011b2732dd988ee34aa011` | Release 与 ASan/UBSan CTest 各 28/28；同步/重复 callback、取消、shutdown 矩阵 | 尚未切正式 force_max 入口 |
| 6 external config/import | 已完成 | `2729408a36ba4be2b42256284f50ed72024fd01a` | Release 与 ASan/UBSan CTest 各 28/28；异步嵌套 import + flow 恢复 | 候选路径完成，正式入口尚未切换 |
| 7 subscription/ruleset/base | 已完成 | `2414a6a6be39926fa49a29ceff723f11f635a19f`、`5eb577d3328d7a4d7db192f5b322fb0ed59034f1` | 两个子阶段 Release 与 ASan/UBSan CTest 各 28/28 | 候选路径完成，正式入口尚未切换 |
| 8 inja/upload/QuickJS | 已完成 | `4cfff0240f1615d14ed2d5ff164cd5cef9211b74`、`722ba148ace373226610e887cc0316ddaf2d9918`、`28c3596af6be24f34f8746aa495104a8efc3d668` | 三个子阶段 Release 与 ASan/UBSan CTest 各 28/28 | 候选路径完成，正式入口尚未切换 |
| 9 owner admission | 已完成 | `e11de11f39d993707596f57269e59ddef5e2adbd` | Release 与 ASan/UBSan CTest 各 28/28；force_max OCI smoke | cache/singleflight/owner 顺序已接通，follower 豁免 |
| 10 transport admission | 已完成 | `d5a8b6beaa63a70038841f46dcd787e09b27d75f` | Release 与 ASan/UBSan CTest 各 28/28；Beast hard-capacity/health；force_max OCI smoke | 软容量等待；硬包络返回完整响应 |
| 11 候选 flow/多线程 | 已完成 | `33b003c394d5b9c6ca7ba0df4bb1457d0f499bc7` | Release 与 ASan/UBSan CTest 各 28/28；legacy/candidate ABBA；force_max OCI smoke | simple target 默认走 flow；复杂路径暂保留 legacy |
| 12 全维度预算消费者 | 已完成 | `47196f0262218fa42eb9236b1d511088ceb07692` | 精确 SHA 的 Release 与 ASan/UBSan CTest 各 28/28；6C/12GiB OCI smoke | 全部容量在监听前一次性冻结并逐项核对 `applied=true` |
| 13 离线公式标定 | 已完成 | `4a5dacf66263a4d89c018c920152681c9cff3d4c` | 精确 SHA 的 Release 与 ASan/UBSan CTest 各 28/28；WSL 多包络和 HostBrr 低权重 ABBA | 冻结 `force-max-v1`；新增独立 inbound connection 预算 |
| 14 PressureGuard | 已完成 | `2e5f1653716530b417754c3bfb8d8cf004c7ab77` | 精确 SHA 的 Release 与 ASan/UBSan CTest 各 28/28；真实 cgroup memory/CPU shrink 注入 | 仅硬危险收紧；固定确认后一次恢复 Full |
| 15 原子启动/旧路径清理 | 待开始 | — | — | — |
| 16 最终验证与 dev 交付 | 待开始 | — | — | — |

## 阶段 0 基线证据

- 本地 `dev`、`origin/dev` 和规划产品源码均为 `6d5dcddd2810bbe95fb7e2bbf4f924c7a4cc536f`；写入本文前工作树无未提交产品改动。
- 依赖快照 SHA-256：`b38c85b594f99546619d8ffd2ac4bbf55c28980eaa18f72145a22a1c7d1232f7`。
- WSL Debian 通过锁定 Dockerfile 构建 Linux amd64 基线镜像；OCI image ID 为 `sha256:2a5dc2e53d8184dfd804d06227b57c2d117ae942d1e448b3dd0647c371dff26b`，大小 `55,471,378` 字节，OCI revision 精确等于基线源码 SHA。
- Linux Release 构建完成 194 个 C++/测试目标；完整 CTest `28/28` 通过，其中包含 Beast/httplib 两组完整兼容与安全基线、两组 shutdown、HTTP 错误、并发、缓存和持久化测试。
- WSL BuildKit 默认 `nofile=1024` 时，第一次完整测试由 Python high-FD 驱动自身耗尽 FD 而失败；服务的前五个 shutdown 场景均已通过。按目标运行环境显式设置 `nofile=524288` 后，同一源码、依赖和测试 `28/28` 通过。该差异记录为测试环境边界，不归因于产品源码。
- Python unittest `36/36` 通过；Go bridge 通过；全部 `scripts/ci/*.sh` Bash 语法检查通过；CI delivery/cleanup/dev-to-master contract 通过；Actionlint 检查 11 个 workflow，0 个错误。当前本机 Actionlint 未加载 ShellCheck/Pyflakes 外部规则，后续 CI 仍需提供完整验证。
- 本地真实 `force_max` 容器使用 `SUBCONVERTER_RESOURCE_CONTROL=force_max` 启动，完整 smoke 通过；运行期间 `restart=0`、`OOM=false`。启动日志确认异步 DNS、Curl multi 和 Beast 生效。
- 基线容器已删除；基线镜像 `codex-subconverter-force-max-baseline:6d5dcddd` 暂时保留供后续 ABBA。约 `4.95GB` BuildKit 缓存暂时保留供逐阶段复用；不得执行全局 prune。
- 阶段 0 未访问或修改 HostBrr，未部署远端容器，未触及 `master`、正式实例、tag、Release 或 `:latest`。

## 阶段 1 验证证据

- `conversion_pipeline.h/.cpp` 只承载参数与策略、依赖计划、订阅处理、目标生成、响应组装和阶段间取消检查的既有顺序；同步入口、线程模型、计时范围和错误正文不变。
- Linux Release 构建完成 196 个 C++/测试目标；完整 CTest `28/28` 通过。
- 本地真实 `force_max` 容器完整运行既有 smoke；其中固定历史输出 SHA-256 断言通过，容器 `restart=0`、`OOM=false`、退出码为 0。
- 本阶段未新增测试文件，未访问或修改 HostBrr，未部署远端容器，未触及 `master`、正式实例、tag、Release 或 `:latest`。

## 阶段 2 验证证据

- 新增不可变 `ResourceEnvelope` 和 `ForceMaxBudget` 数据合同；预算由纯函数一次性计算并验证内存分区、出站容量、队列容量和 QuickJS 子预算交叉不变量。
- provisional formula 不读取 CPU 型号、厂商、L3、部署者名称或历史请求，也不包含学习、试探和持久曲线；相同输入逐字段完全一致。
- 扩展既有 `concurrency_primitives_test`，覆盖确定性、CPU/内存单调性、500m CPU、无 cgroup/无 PSI、低 `nofile`、FD 耗尽和整数溢出拒绝；未新增测试文件。
- Linux Release 构建完成 202 个 C++/测试目标，完整 CTest `28/28` 通过；本地真实 `force_max` OCI smoke 和固定历史输出哈希断言通过，`restart=0`、`OOM=false`。
- 新预算只写入设置快照、Dashboard 诊断和启动日志，`applied=false`；现有 force_max 运行容量仍走 legacy adapter，本阶段没有提前切换容量。
- 本阶段未访问或修改 HostBrr，未部署远端容器，未触及 `master`、正式实例、tag、Release 或 `:latest`。

## 阶段 3 验证证据

- 新增单一有界 `ComputeExecutor`：任务同时受 queue entries、queue bytes、绝对 deadline 和取消令牌约束；拒绝或关闭路径均使 future/completion 确定结束。
- worker 使用独立缓存行指标，提供软亲和提示、线程命名、ready barrier、低/中/高 cost 公平调度和 500ms 老化；软亲和只在同一 cost 队列的有限窗口内选择，不绕过公平类别。
- 关闭分为 request 与逆序 join；worker 自 join 明确失败而不死锁，pending completion 使用原子 exactly-once claim，执行器内没有 caller-runs、busy-spin 或 worker 对同一执行器的同步等待。
- 扩展既有 `concurrency_primitives_test`，覆盖 entry/byte limit、deadline、取消、软亲和、自 join、pending shutdown、completion exactly-once、队列字节恢复和 worker-local 指标；未新增测试文件。
- Linux Release 完整 CTest `28/28` 通过；完整 ASan/UBSan CTest `28/28` 通过，包含 Beast/httplib 两组兼容与安全基线及两组 shutdown。
- 全局执行器接口和 Dashboard 诊断已建立，但本阶段未初始化全局实例，也未承载正式请求或改变现有线程拓扑。
- 本阶段未访问或修改 HostBrr，未部署远端容器，未触及 `master`、正式实例、tag、Release 或 `:latest`。

## 阶段 4 验证证据

- `webGetOwnedAsync` 支持 `cache_ttl=0` 的真实 Curl multi GET，不再把无缓存请求直接归为 Transport failure；GitHub Raw/jsDelivr fallback、代理路由、header 和 retained result lease 沿用同一异步传输合同。
- cache 与 no-cache 子操作均继承消费者的单一绝对 deadline；过期 deadline 在发起网络请求前确定完成，阶段内部不再生成新的 `now + requestDeadlineMs`。
- 每次异步 owned fetch 捕获一个不可变 `SettingsSnapshot`，冻结取源开关、TLS、安全、下载大小和 stale-cache fallback；异步 continuation 重新建立 scoped settings view，不跨挂起保存 thread-local RAII。
- owned fetch continuation 已从独立 WorkloadScheduler 迁入单一 `ComputeExecutor`；force_max 在监听前按 provisional budget 完成 worker ready，初始化失败在监听前退出，并显式 request shutdown 与并发安全 join。
- 扩展既有 settings snapshot/兼容基线，覆盖同步 completion、无缓存 GET、响应 header/正文/retained lease、绝对 deadline、cache owner/follower、部分消费者取消、pre-init failure、双 join 和资源归零；未新增测试文件。
- Linux Release 与完整 ASan/UBSan CTest 均为 `28/28`；本地真实 `force_max` OCI smoke 和固定历史输出哈希断言通过，启动日志确认 16 个 WSL 预算 worker 在监听前 ready，容器 `restart=0`、`OOM=false`。
- 本阶段未访问或修改 HostBrr，未部署远端容器，未触及 `master`、正式实例、tag、Release 或 `:latest`。

## 阶段 5 验证证据

- 新增 self-held `ConversionFlow` actor、串行 mailbox、明确 phase、operation ID + generation、weak callback handle 和 exactly-once terminal claim；flow 可变 phase/outstanding operation 只在 drain 中修改。
- 每个 mailbox event 执行前重建 `ScopedSettingsView` 与 `ScopedRequestContext`，事件返回即销毁；同步 callback 只入 mailbox，不重入当前阶段，重复 callback 在 operation claim 后被拒绝。
- ComputeExecutor 增加独立有界 control queue；普通 count/bytes 队列饱和时，已接受 flow 的 completion、取消、shutdown 和 lease cleanup 仍有前进通道，且 control task 不走 caller-runs。
- 全局 flow registry 只保留 weak reference；每个 flow 自保持到 terminal，terminal 时在锁内交换 mailbox/completion，在锁外销毁 event、注销取消回调、移除 registry 并调用外部 completion，避免锁内回调和引用环。
- 扩展既有 settings snapshot/兼容基线，覆盖 thread-local 恢复、phase generation、同步 callback、重复 callback、mailbox bytes 归零、client cancellation、shutdown、创建停止和 registry 归零；未新增测试文件。
- 首轮测试曾因 Release helper 中把有副作用的操作写进 `assert(expr)` 而超时；已改为显式执行并单独记录结果。修正后 Linux Release 与完整 ASan/UBSan CTest 均为 `28/28`，两种 HTTP 后端结果一致。
- 本阶段仍未把正式 force_max 请求切入 ConversionFlow；未访问或修改 HostBrr，未部署远端容器，未触及 `master`、正式实例、tag、Release 或 `:latest`。

## 阶段 6 验证证据

- 将外部配置加载拆成正文获取与 `loadExternalConfigFromContent` 解析/缓存边界；同步入口仍按原顺序调用该边界，既有行为不变。
- import 解析增加 request-scoped resolved view：CPU 解析只读取本地文件或已解析正文；遇到缺失远程 import 时收集去重依赖，不在 ComputeExecutor worker 内等待 future 或执行同步网络。
- 新增 `loadExternalConfigAsync`：顶层配置和多轮嵌套 import 使用 `webGetOwnedAsync`，全部继承同一 settings snapshot、RequestContext、绝对 deadline、取消和 retained byte lease；每轮依赖就绪后在单一 ComputeExecutor 重跑纯解析。
- 新增 `resolveExternalConfigOnFlow` 候选接线：flow 在 FetchingExternalConfig phase 登记 operation，网络 callback 只 post mailbox event，再在恢复事件中应用结果；同步 callback 同样不重入。
- import 数量使用现有 `maxAllowedRulesets` 硬边界；状态和 failure stage 为低基数诊断，不暴露原始 URL 或正文。异步状态和 source completion 均用原子 exactly-once，分配/回调异常确定终结。
- 最小异步测试暴露并修复了既有 `render_template` 在空 `request_params` 时对空 `_args` 执行 `erase(npos)` 的缺陷；非空参数输出不变，空参数现在生成空 `_args`。
- 扩展既有 fixture/helper，验证顶层 TOML、远程嵌套 custom-group import、解析结果、独立异步 API和 ConversionFlow 挂起/恢复；未新增测试文件。Linux Release 与完整 ASan/UBSan CTest 均为 `28/28`。
- 本阶段仍未切正式 force_max 请求入口；未访问或修改 HostBrr，未部署远端容器，未触及 `master`、正式实例、tag、Release 或 `:latest`。

## 阶段 7 验证证据

- subscription 子阶段新增 Curl multi fan-out batch；每个 slot 固定携带原始 `source_index`、URL、不可变 payload、header、failure 和 cancellation，完成顺序不影响结果顺序。
- `parse_settings` 增加显式 resolved subscription 正文/header；候选 CPU 解析设置 `require_resolved_subscription=true`，缺失正文时确定失败，禁止 ComputeExecutor worker 隐式同步回网。测试以两个 URL 验证输出 slot 和最终节点 group ID 均保持 0、1 顺序。
- ruleset/base 子阶段新增统一 immutable resolved resource batch，以 `ConversionResourceKind + source_index + payload` 表示规则集和 base；候选 generator 不接收 `shared_future`，callback 完成后按原始 index 消费。
- `resolveSubscriptionsOnFlow` 与 `resolveConversionResourcesOnFlow` 均先登记 flow operation，异步 callback 只 post mailbox；mailbox bytes 计入正文和 header，恢复后进入 Parsing phase。
- 两个 batch 均继承同一不可变 settings、RequestContext、绝对 deadline、取消与 retained lease；回调使用 exactly-once batch completion，空批次也同步确定完成。
- 扩展既有 fixture/helper：两个订阅并发下载与顺序解析、两个 ruleset + 一个 base 的混合 batch、两条 ConversionFlow 挂起/恢复路径、registry 归零；未新增测试文件。
- subscription 子提交和 ruleset/base 子提交分别通过 Linux Release `28/28` 与完整 ASan/UBSan `28/28`；正式 force_max 请求仍未切候选 flow。
- 本阶段未访问或修改 HostBrr，未部署远端容器，未触及 `master`、正式实例、tag、Release 或 `:latest`。

## 阶段 8 验证证据

- inja 子阶段增加 request-scoped resolver：未知动态 URL 只记录去重依赖并返回 `NeedsFetch`，Curl multi 获取完成后以同一冻结输入重新渲染；已解析 URL 不重复联网，依赖数、迭代次数、deadline、取消和驻留字节均有边界。
- Gist 上传拆成 Compute 准备、Curl multi POST/PATCH 和独立 cleanup 持久化三段；取消发生在发网前时不产生远端副作用，远端成功后即使请求取消也完成本地原子状态提交。POST `201` 与 PATCH `200` 分别验证，原正文、managed prefix、JSON request body 和响应正文均计入对应父预算。
- 新增独立 `QuickJsLane`：worker、queue entries/bytes、每 Runtime heap 与 VM stack 都由显式预算约束；每个任务在单一 lane worker 内独占 Runtime/Context，不跨线程共享，也不占普通 ComputeExecutor worker。
- quickjspp 的进程级 class ID 在启动 worker 前串行预热；解释器 interrupt handler 读取父请求的单一绝对 deadline、取消令牌和 lane shutdown。原生 `sleep` 改为取消可唤醒的等待，脚本同步 `fetch` 继承父 deadline/取消，`fileWrite` 在副作用前重新检查取消与 deadline。
- `runQuickJsOnFlow` 将 lane completion 仅作为 mailbox event 恢复；同步拒绝、正常完成、取消、deadline 和 shutdown 均走 exactly-once completion。候选测试证明脚本 sleep 期间普通 executor 仍可前进，queue count/bytes 可恢复，Runtime/Context 销毁后 lane 可逆序 join。
- 扩展既有测试而未新增测试文件；inja、上传和 QuickJS 三个独立子提交分别通过 Linux Release `28/28` 与完整 ASan/UBSan `28/28`。QuickJS 最终 Release OCI image ID 为 `sha256:e3fa1d4f55b426821c1c15300f1cc2ee96961d10c192cb29a0a94a0de09e499c`，插桩 image ID 为 `sha256:9142a32e6da29a7afc7137b23b57827955b097e9dbae3aba00252b230d203235`。
- 本阶段仍未把正式 force_max 请求切入 ConversionFlow 或 QuickJS lane；未访问或修改 HostBrr，未部署远端容器，未触及 `master`、正式实例、tag、Release 或 `:latest`。

## 阶段 9 验证证据

- 新增独立 `OwnerAdmission`，将准入等待与任务执行彻底分离；controller 只维护 active count/bytes、wait count/bytes 和 permit lease，不为每个等待请求占用 worker 或 OS 线程。
- 正式 force_max 异步 `/sub` 顺序已固定为 response micro-cache -> singleflight -> owner admission；同 key follower 直接附着并只计 socket、请求元数据和等待响应字节，不消耗 owner permit。
- 等待队列按 low/medium/high cost 使用 8:4:1 加权轮转，同 cost 保持 FIFO；等待超过 500ms 后由最老且当前可合法授予的 owner 优先，较大请求在字节恢复后不会被新小请求永久绕过。
- 每个 waiter 同时继承父请求的绝对 deadline 与取消状态；取消回调通过保存的 `std::list` iterator O(1) 移除，单一 timer 线程处理 deadline，不使用轮询线程或占用 ComputeExecutor。grant、取消、deadline、shutdown 均使用单次 claim。
- owner permit 由 move-only lease 持有：coalesced owner 持有到不可变结果发布，standalone owner 持有到转换 completion；同步拒绝、消费者全部离开、调度失败和异常均释放 count/bytes。shutdown 先停止新 owner 并清空 waiter，再继续现有 flow/cleanup。
- force_max 在 bind/listen 前按 `ForceMaxBudget` 初始化全局 admission；预算不合法、重复预算不一致或初始化失败均在监听前失败。Dashboard 使用 `force_max_waitable` 数据源公开 active/wait count/bytes、硬边界、取消、deadline、shutdown 和拒绝计数。
- 扩展既有并发测试，覆盖立即 grant、等待后 grant、O(1) 取消、timer deadline、硬 count/bytes 边界、加权公平、500ms 老化、shutdown、lease 归零、全局重复初始化与预算不匹配；未新增测试文件。
- Linux Release 与完整 ASan/UBSan CTest 均为 `28/28`。真实 force_max OCI smoke 通过，Release image ID 为 `sha256:b8e42cd4c0f79c611621fc132fc9f1a82303ed0dddfada4ed748b767b26d72a5`，插桩 image ID 为 `sha256:5a04a738bb825cc647f031c5e80437e8ed17876a8fa8aafa11ecb496bd6a0094`；容器 `restart=0`、`OOM=false`。
- 本阶段仍使用 legacy request-flow worker 执行转换，正式 `ConversionFlow` 切换留在阶段 11；未访问或修改 HostBrr，未部署远端容器，未触及 `master`、正式实例、tag、Release 或 `:latest`。

## 阶段 10 验证证据

- 新增独立全局 transport admission，复用阶段 9 的 waitable count/bytes/lease 合同；force_max 在 bind/listen 前从当前 `ForceMaxBudget` 和已探测请求字节边界初始化 active 与 wait 预算，初始化失败不监听。
- Beast 完整解析请求后异步等待 transport permit；等待期间只保留有界 session/request bytes，不占 handler worker。grant callback 回到 socket executor 后再投递业务 handler；deadline、客户端断开和 shutdown 均先取消 waiter，再返回确定响应。
- transport lease 持有到响应发送完成或 keep-alive 请求结束；下一请求前释放 count/bytes。Dashboard 的 `request_admission.source=force_max_waitable` 同时公开 active/wait count/bytes、取消、deadline、shutdown 和硬边界。
- Beast 连接硬边界不再对已 accept socket 直接 shutdown/reset。业务槽满时使用按 server worker 数派生的 reserved parse slots：`/healthz` 仍可完成，其他合法请求返回完整 `503 + Retry-After + X-Request-ID`；reserved keep-alive 被关闭且读等待限制为 1 秒，避免保留槽长期被占。
- reserved slots 全满时最多额外保留一个已 accept spill socket并暂停继续 accept，由内核 backlog 承接后续连接；任一业务或 reserved slot 释放后恢复，未引入固定 CPU/内存/连接 ceiling。
- httplib 兼容后端在 pre-routing 同样等待 transport permit；普通 handler 满时使用可取消、deadline-aware 的条件等待，并永久保留一个 health handler。该同步兼容路径会占用 httplib 自身请求线程，正式 force_max 高性能默认路径仍为 Beast。
- 扩展既有兼容基线：业务连接上限为 1 时，第二个已 accept 请求必须收到完整硬包络 503；第一个连接仍占满业务槽时 health 必须返回 200；释放后 health 持续可用。未新增测试文件。
- 最终 Linux Release 与完整 ASan/UBSan CTest 均为 `28/28`。真实 force_max OCI smoke 通过，Release image ID 为 `sha256:3dd126f10d74d457a6a65c716fe57e6e229fa856167eec4b386311c4076e070c`，插桩 image ID 为 `sha256:4808b52f2bee067858c5e3d9a1fe2c5444bfbcd7a56e5ecb481d9905eb040eb3`；容器 `restart=0`、`OOM=false`。
- 本阶段仍未切正式 `ConversionFlow`；未访问或修改 HostBrr，未部署远端容器，未触及 `master`、正式实例、tag、Release 或 `:latest`。

## 阶段 11 验证证据

- force_max Beast 的显式 simple target 已默认切入 `ConversionFlow`；`SUBCONVERTER_FORCE_MAX_FLOW=legacy` 可立即回到旧 request-flow，`candidate` 可显式锁定新路径。auto target、脚本、上传、import、本地/远程外部配置和需要 base/ruleset 的复杂目标暂留 legacy，避免半异步路径隐式阻塞 ComputeExecutor。
- 候选 flow 在 Preparing 阶段完成参数/策略纯解析，以 data URI 外部配置进入异步配置阶段；对订阅先运行无网络规划，收集全部确需服务端展开的 URL，再通过 Curl multi 一次 fan-out。client-managed provider/remote 资源不会被多余下载。
- 订阅 payload 按 URL、FetchContext 和请求头三元组去重并保持原 source index；全部完成后重建策略并以 `require_resolved_subscription=true` 解析，任何未解析回网企图均成为内部失败，ComputeExecutor worker 不调用同步 `webGet` 或等待 future。
- `addNodes` 增加 request-scoped resolver/missing-source 合同；legacy 直接正文指针和同步路径不变。异步缓存 owner/follower 同样执行高基数订阅 doorkeeper：首次旁路、复用请求声明持久化、并发 follower 可为同一 owner 请求落盘。
- flow mailbox 预算由 `ForceMaxBudget.flow_queue_entries/bytes ÷ active_flows` 派生；网络完成只投递 mailbox，解析和生成继续保持单 flow 串行，跨阶段使用既有软亲和与 worker-local 指标。多订阅的并行度来自请求间并行和 Curl fan-out，不新增线程池。
- 显式 ABBA 基线分别以 `legacy` 与 `candidate` 转换同一订阅，要求最终响应字节完全一致；Dashboard 同时证明 legacy 只增加旧 scheduler 计数，candidate 只增加 ConversionFlow created/completed，active 最终归零。
- 未在缺少 profile 证据时加入请求内 CPU sibling、中央队列分片、work stealing 重写或 PCRE2 compiled-plan 缓存；这些可选项为本阶段 No-Go，不阻塞已验证的异步 flow。
- 精确提交的 Linux Release 与完整 ASan/UBSan CTest 均为 `28/28`，真实 force_max OCI smoke 通过。Release image ID 为 `sha256:879f38ae9a7f49cf8e515d0dd054a365e9b646cbc9fa3541b1856502dcc091d0`，插桩 image ID 为 `sha256:3e52ad859c4612534eabd1293023197038399787f90f107e5396b6fcfce8e8d0`；容器 `restart=0`、`OOM=false`。
- 本阶段未访问或修改 HostBrr，未部署远端容器，未触及 `master`、正式实例、tag、Release 或 `:latest`。

## 阶段 12 验证证据

- 将预算公式升级为 `force-max-provisional-v2`，显式拆分 transport、owner、flow、blocking I/O 队列和 active byte 预算。`maxConcurThreads`、handler permit、active flow、请求/响应驻留、Curl active/open/idle、各队列和 listener backlog 均直接消费同一份启动预算，不再各自重新推导。
- 新增独立有界 blocking I/O executor，本地文件读取不再占普通 ComputeExecutor；ruleset executor 使用同一 I/O worker 数和 blocking I/O 队列条目边界。QuickJS 全局 lane、blocking I/O executor 和 Curl multi 均在 bind/listen 前构造并通过 ready 检查，初始化失败时不监听。
- response micro-cache、ruleset conversion cache 和 external config cache 从 `cache_bytes` 按固定比例分配，并支持启动时原子收紧；动态 LRU limit 的读写和淘汰均受同一互斥保护。运行期遥测只刷新可观测资源包络，不再重算已经下发的 `ForceMaxBudget`。
- Dashboard 的 `calculated_force_max_budget.applied` 不再是占位值，而是同时核对 Compute、blocking I/O、QuickJS、transport/owner admission、Curl、retained response、三个 cache、CPU permit 和服务设置的实际维度；任一消费者漂移都会显示 `false`。既有兼容基线要求 force_max 运行 2 秒后仍保持逐项相等。
- 精确产品提交的 Linux Release 与完整 ASan/UBSan CTest 均为 `28/28`。Release image ID 为 `sha256:b04999bca988cd65dc335d60bb521c00b4312cfa78ee27e9eca72045abbc4cb4`，插桩 image ID 为 `sha256:ad493c098935c8eb6cf4824009bb56c35884d00c3c82fdae4d76dc969cf2e92f`，两者 OCI revision 均精确等于产品 SHA。
- 使用 6 CPU、12 GiB、`pids=4096`、`nofile=524288` 的临时 OCI 包络验证当前 HostBrr 规格：预算自动得到 compute/I/O/QuickJS worker `6/2/3`、active flow `96`、active owner `48`、outbound active `96`，Dashboard 为 `applied=true`，完整 smoke 通过；优雅退出码为 0，`restart=0`、`OOM=false`。这些数值是当前包络的计算结果，不是项目硬编码上限，迁移到更强服务器会随探测结果重新计算。
- 本阶段未访问或修改 HostBrr，未部署远端容器，未触及 `master`、正式实例、tag、Release 或 `:latest`。

## 阶段 13 验证证据

- 离线标定使用临时仓库外 Python 驱动和不可变 Stage 11/Stage 13 OCI。驱动强制服务端展开 1,200 个节点，并逐响应验证节点正文、字节数和有序响应摘要；早期 provider-native 结果未实际展开节点，已明确作废且未用于结论。
- 首轮 HostBrr 边界测试发现 Stage 12 把 `active_flows=96` 同时用作 Beast 全部业务连接硬上限；冷请求或短暂 keep-alive 未释放时，96 个新请求中有 2 个进入 overload lane，返回完整 503。该结果违反包络内不拒绝门，测试立即停止并修正公式。
- 最终 `force-max-v1` 增加独立 `inbound_connections`：按可调度 CPU 派生，再与通用 FD 包络交叉收敛；出站与入站各使用最多一半可用 FD，active flow 同时受 inbound 二分之一约束。HostBrr 类 6C/高 FD 包络得到 384 inbound connection，而 compute/owner/flow/outbound 仍为 `6/48/96/96`。该比例不读取 CPU 型号、厂商、L3 或部署者名称，也不保存每机曲线。
- WSL 的有效负载 A-C-C-A 中，每轮均为 192/192 成功，单响应 141,068 字节且摘要相同。Stage 11 与 Stage 13 的平均吞吐约为 78.5/79.2 response/s，约 0.9% 差异；平均 p99 约为 1.50/1.53 秒，判定为噪声，因此未继续放大 compute、owner 或 outbound 比例。
- 同一候选在 1C/1GiB、2C/2GiB、4C/4GiB、8C/12GiB holdout 包络均为 100% 成功，`applied=true`，无 capacity 失败、OOM 或 restart。6C/12GiB 下 192 并发 384/384、384 并发 768/768 成功；超过 96 个 active flow 时由 admission 等待，不由连接硬上限提前拒绝。
- HostBrr 使用 `cpu-shares=64` 的短时低权重 A-C-C-A，未替换现有测试实例：每轮 192/192、141,068 字节、摘要一致。Stage 11 与 Stage 13 平均吞吐约为 34.8/36.8 response/s，候选提高约 5.9%；平均 p99 均约 3.65 秒。候选另通过 250 ms 慢上游、同 key 384 follower 洪峰，384/384 成功且无 503。
- 精确产品提交的 Linux Release 与完整 ASan/UBSan CTest 均为 `28/28`。Release image ID 为 `sha256:a1d6d712025760aa89b825c8500ae87419d38272ccede0e387db1e3d6fc80b77`，插桩 image ID 为 `sha256:3fd0b81af19816a6142b05d3effb258fae8692993fd7b93454e98e77fb2add2b`，两者 OCI revision 均精确等于产品 SHA。
- HostBrr 只加载临时 benchmark image 并运行临时低权重容器；未修改 Compose、现有容器或公网路由。临时远端文件、容器和 image tag 均已清理；正式与测试实例最终均为 healthy、`restart=0`、`OOM=false`。未触及 `master`、tag、Release 或 `:latest`。

## 阶段 14 验证证据

- force_max 不再进入通用逐级 governor；新增固定 `Full -> Guarded -> RecoveryConfirm -> Full` 状态机。硬危险持续时保持同一 Guarded 额度；连续 3 个清除样本后一次性恢复完整预算，不逐级增加 permit。遥测缺失或采样异常直接保持/恢复 Full，并报告 `telemetry_unavailable_full` 或 `telemetry_error_full`。
- 触发源仅包括 memory high/max/OOM/OOM-kill/socket-throttled 事件、内存逼近硬边界、memory/nofile/pids/CPU 硬限额缩小，以及 FD/PID 最低前进余量耗尽。CPU 满载、CPU PSI、普通 backlog、队列增长、到达量和吞吐均不进入 force_max guard 判定。
- Guarded 使用启动 full budget 的固定二分之一，并在外部硬限额缩小时与当前确定性 envelope 重新计算结果取更小值。动态收紧 CPU permit、owner/transport active count/bytes、retained response bytes 和三个 cache；已活动 lease 不取消，即使当前占用高于新上限也只阻止新 grant，待自然排空后再放行。
- `OwnerAdmission::setActiveLimits` 在自身锁内只更新额度和收集可 grant waiter，在锁外执行 completion；恢复 Full 时立即按原公平/老化规则继续 grant。Dashboard 增加 guarded、activation、recovery 和 repeated activation 诊断，并通过实际 admission/CPU/cache/retained 值反映当前状态。
- 真实 2 CPU/2 GiB OCI 注入中，两个 `yes` 进程满载 4 秒后仍为 Full、`applied=true`、activation 0。memory 2 GiB -> 1 GiB 后进入 `memory_limit_shrink`，CPU/owner/transport 从 `2/16/32` 收紧为 `1/8/16`；恢复 2 GiB 后一次回到 `2/16/32` 和 `applied=true`。随后 CPU quota 2 -> 1 触发第二次 Guarded，恢复后 activation/recovery/repeated 为 `2/2/1`。全过程 health 可用，优雅退出码 0，`restart=0`、`OOM=false`。
- 精确产品提交的 Linux Release 完整 CTest 最终为 `28/28`；首次 exact build 曾有一次与本阶段路径隔离的 `webserver_error_httplib` 终态计数时序失败，审计测试路径后使用同一构建缓存复跑为 `28/28`，ASan/UBSan 完整 CTest 同样为 `28/28`。Release image ID 为 `sha256:ccba00389ccbac8ef6880d0f793d54510b507c988cd2716d45c4bf14355df990`，插桩 image ID 为 `sha256:24afd463af5f29b61f6fc182b5574dc8c4e63f78bf35737d3ba21c8ba82a53c7`，OCI revision 均精确等于产品 SHA。
- 本阶段未访问或修改 HostBrr，未部署远端容器，未触及 `master`、正式实例、tag、Release 或 `:latest`。

## 一、固定范围与不可改变的决策

### 1.1 范围

- 单实例部署；不设计宿主机双实例资源协调。
- 性能和资源策略只针对 `resource_control=force_max`。
- `compat`、`adaptive` 的公开行为、默认值和容量策略不属于本项目；共享的纯函数/解析核心可以复用，但不得因本改造产生可观察语义变化。
- 开发、提交、CI、OCI 和测试实例阶段限定在 `dev`。未经后续明确授权，不触及 `master`、正式实例、tag、Release 或 `:latest`。

### 1.2 force_max 的唯一运行语义

- 启动时直接进入完整、确定性的最大安全性能状态。
- 在 bind/listen 前完成资源探测、`ForceMaxBudget` 计算、worker/执行器/Curl/admission 初始化和可信静态资源预热。
- 第一批请求与稳定运行时使用相同完整预算。
- 不存在机器学习、AIMD、运行期容量探测、warm-up 升档、历史容量曲线、持久化训练结果、空闲降档或渐进恢复。
- 正常状态始终为 `applied == ForceMaxBudget`。
- 在线逻辑只允许 `PressureGuard` 在明确硬资源危险时临时限制新工作；危险解除后经过固定短确认窗口，一次性恢复完整预算。
- CPU 满载、CPU PSI 上升、存在 backlog 或队列增长本身不能触发降档。

### 1.3 明确排除

- 不采用 AVX/AVX2/AVX-512 特化、运行时 ISA multiversion、`-march=native`、`-march=znver4`、x86-64-v3/v4 专用二进制。
- 不根据 CPU vendor/model、HostBrr、6C/12GB、256MB L3 或 CCD/CCX 数量决定策略。
- 不做 CPU 硬绑核、SMT 开关、NUMA/LLC 分片或按 L3 大小设置软件缓存。
- 不引入机器学习、长期学习、线上自校准、按时间预测洪峰或用户数据训练。
- 本方案不包含 LTO、PGO、allocator 更换、Go/C++ ABI 重写、Curl reactor 分片或多进程扩展。这些若未来有新证据，必须另立独立方案，不能混入本次实施。
- 不新增仓库测试文件；只扩展现有测试和使用仓库外临时压测语料。

## 二、完成后的目标架构

```text
启动期
  读取配置
    -> ResourceEnvelope
    -> ForceMaxBudget
    -> RuntimeCoordinator 全量初始化
    -> 可信静态资源预热
    -> publish budget/runtime snapshot
    -> Beast bind/listen

请求期
  Beast session
    -> TransportAdmission（连接/请求字节硬边界）
    -> response cache / singleflight
    -> WaitableOwnerAdmission（owner/count/bytes/cost/deadline）
    -> ConversionFlow 串行 mailbox
         -> 短 CPU continuation
         -> 异步 external-config/import fetch
         -> 异步 subscription fan-out
         -> 异步 ruleset/base/template fetch
         -> QuickJS 有界兼容 lane
         -> 可选异步上传
    -> ImmutableResponse
    -> Beast async_write
```

- 网络、规则集、singleflight、重试、上传和准入等待不占普通 OS worker。
- 参数解析、配置解析、节点解析、规则转换、节点变换、目标生成和响应组装继续作为同步、短时 CPU kernel。
- 每个唯一 owner 对应一个 `ConversionFlow`；同 key follower 共享 owner 和不可变响应。
- flow callback 只投递 mailbox event，flow 可变状态只在串行 continuation 中访问。

## 三、核心数据与组件

### 3.1 ResourceEnvelope

建议位于 `src/utils/resource_probe.h/.cpp`，至少包含：

- affinity 可用 CPU；
- cpuset 可用 CPU；
- `cpu.max` 的实际毫核数，允许小于 1000；
- 可调度 CPU 数和拓扑可信度；
- `memory.high`、`memory.max`、host memory fallback；
- `nofile` soft/hard、当前打开 FD；
- `pids.max`、当前 PID/thread；
- Windows Job/Processor Group 能力；
- Linux/OpenWrt cgroup/PSI/memory.events 能力；
- checked arithmetic 和数据来源状态。

优先级为 affinity/cpuset/quota 的实际交集。分数 CPU 不得先被强制整数化。拓扑缺失时只使用 CPU 数量，不推断 SMT、CCD、L3 或 NUMA。

### 3.2 ForceMaxBudget

建议位于 `src/utils/force_max_budget.h/.cpp`，是纯函数计算结果，至少包含：

- `formula_revision`；
- `compute_workers`、`compute_permits`；
- `io_runners`、`handler_permits`；
- `active_owners`、`active_flows`；
- `outbound_active`、`outbound_per_host`、`outbound_open`、`outbound_idle_cache`；
- transport/owner/flow queue entries 和 bytes；
- retained response、fetch、cache 和工作内存父预算；
- QuickJS compatibility lane worker/queue/bytes，以及每 worker heap/VM stack；
- health/overload response 的 FD 和内存保留量。

同一 `ResourceEnvelope + formula_revision` 必须得到逐字段完全相同的预算。预算必须单调、受硬边界约束、使用 checked arithmetic。`16 x CPU`、flow 256、Curl 1024、Beast I/O 1 等旧值不能继续作为项目 ceiling。

### 3.3 RuntimeCoordinator

建议位于 `src/runtime/runtime_coordinator.h/.cpp`，职责仅为：

- 按固定顺序初始化各组件；
- 等待 worker 和 reactor 报告 ready；
- 在监听前原子发布完整预算；
- 管理反向关闭顺序；
- 初始化失败时在监听前退出，不静默切旧 `force_max` 引擎。

### 3.4 ComputeExecutor

建议位于 `src/runtime/compute_executor.h/.cpp`：

- 一个共享、有界的短 CPU continuation 执行器；
- count/bytes/deadline/cancellation 边界；
- worker-local 状态和低争用计数；
- flow 软亲和：相邻 continuation 优先回原 worker；队列不平衡时允许 steal；
- park/unpark 和线程命名接口；
- 第一版先保留简单公平调度，不在没有 profile 时上复杂无锁结构。

不得创建 Beast -> blocking flow -> conversion -> ruleset 多层嵌套线程池。不得在 executor worker 内同步等待同一 executor 的任务。

### 3.5 ConversionFlow

建议位于 `src/runtime/conversion_flow.h/.cpp`，phase 至少包含：

- Preparing；
- FetchingExternalConfig；
- FetchingSubscriptions；
- FetchingRulesets；
- Parsing；
- Generating；
- Uploading；
- Publishing；
- Completed。

每个 event 执行前重新建立 `ScopedSettingsView`、`ScopedRequestContext` 和日志上下文；执行后销毁 thread-local scope。不得让 thread-local RAII 跨异步挂起。

### 3.6 WaitableOwnerAdmission

建议位于 `src/runtime/owner_admission.h/.cpp`：

- 固定顺序：cache -> singleflight -> owner admission；
- follower 不消耗 owner/compute permit；
- 软饱和进入严格有界的 count/bytes/cost/deadline 队列；
- 使用 owner 公平、cost fairness 和等待老化；
- deadline、客户端断开、最后消费者离开和 shutdown 立即移除 waiter 并归还所有字节；
- 包络内不返回容量拒绝；硬包络不足时返回确定 HTTP 响应，不静默 close/reset。

### 3.7 PressureGuard

建议位于 `src/runtime/pressure_guard.h/.cpp`：

- 只处理 memory high/max event、OOM 风险、FD/PID 硬边界、cgroup 限额缩小和确定的服务器容量故障；
- 使用离线验证的固定 guarded budget，不学习、不拟合、不持久化；
- 只阻止新工作，不取消已接受的合法活动任务，不销毁 worker 或热缓存；
- CPU 满载、CPU PSI、backlog 和高利用率不能单独触发；
- 危险解除后经过固定短确认窗口，一次恢复完整 `ForceMaxBudget`；
- 重复进入 guard 视为预算公式或环境异常，必须告警并进入后续离线修正，不能在线稳定在较低“学习结果”。

## 四、网络、模板和脚本边界

### 4.1 webGetOwnedAsync

- 支持 `cache_ttl=0`；
- 使用消费者绝对 deadline，禁止重新生成 `now + requestDeadlineMs`；
- 携带冻结的 settings/fetch 派生值；
- completion 可以同步发生，因此不得持 flow mutex 调用；所有 completion 统一 post 到 mailbox；
- 正文、headers、cookies、缓存回退、GitHub/jsDelivr 回退、代理、SSRF/TLS、下载大小和 retained bytes 与同步路径一致；
- 纳入 RuntimeCoordinator 启动和关闭，不再只在测试中初始化 continuation runtime。

### 4.2 外部配置与 import

拆成：来源候选计划 -> 异步取得正文 -> inja/template 处理 -> 同步解析/校验/应用。用户外部配置与默认 fallback 的顺序、状态码和错误归因必须保持。

### 4.3 Subscription

拆成：来源分类 -> 并发异步下载 -> 按原始索引同步解析 -> 按原顺序合并。必须保持 group ID、节点顺序、provider/native remote、`Subscription-UserInfo` 和 `skip_failed_links`。

### 4.4 Ruleset 与 base

- 新路径使用 descriptor + immutable resolved content，不向 generator 传递 `shared_future`；
- 并发 fetch 后按配置顺序存入结果槽；
- CPU worker 不再 `.get()` 等待；
- base template 在生成前取得。

### 4.5 inja

- 使用 request-scoped resolver；未知 URL 返回 `NeedsFetch`；
- 获取后用相同冻结输入重新渲染；
- 已取得 URL 不重复请求；
- 设置最大迭代/依赖数、整请求 deadline 和字节预算，防止动态循环；
- 只有输出、副作用和错误语义完整一致才保留该路径。

### 4.6 QuickJS

- 保持旧同步 `fetch`、`fileWrite` 等副作用语义；禁止通过重新执行脚本模拟异步；
- 每个脚本请求进入独立、严格有界的兼容 lane；
- 不共享 QuickJS Runtime/Context 给多个线程；
- QuickJS lane 不占普通 continuation worker，仍共享 deadline、取消和父级字节预算。

### 4.7 可选上传

- Gist POST/PATCH 改为异步；
- 取消后不得继续上传；
- side effect exactly-once；
- 上传失败保持现有响应语义，不能把成功转换正文错误覆盖。

## 五、通用多线程优化

### 5.1 必须实施

- 单一 ComputeExecutor；
- worker-local 指标和安全缓存行布局，避免主动制造 false sharing；
- flow 软亲和但不硬 pin；
- 请求间公平优先；
- 长 CPU 阶段支持 cooperative chunking，避免单任务长期占用 worker；
- per-worker 计数按固定周期聚合，线程退出时完整汇总。

### 5.2 机会式请求内并行

只在以下条件同时满足时启动 sibling task：

- 全局 owner backlog 为 0；
- runnable owners 少于可用 compute permits；
- 当前 flow 有可证明独立、无副作用的任务；
- 内存、deadline 和取消预算足够。

首批允许候选：

- 多个订阅正文解析到独立局部 vector；
- 多个已取得 ruleset 的独立转换。

每个子任务复用同一 executor、RequestContext、deadline、取消源和父级字节预算；写入按原始索引分配的结果槽，最后严格按输入顺序合并。出现全局 backlog 后不再为单个请求启动新 sibling task。

### 5.3 只有 profile 后才进入的候选

- 中央 scheduler mutex 明确成为热点后，评估“全局公平 admission + worker-local deque + work stealing”；
- singleflight/cache/statistics 锁明确成为热点后逐项分片；相同 key 必须进入同一 shard，所有 shard 共用同一父级 bytes budget；
- 静态 include/exclude 规则重复编译成为热点后，评估 request-scoped PCRE2 compiled plan/JIT；动态 `GROUP/GROUPID/TYPE/PORT/SERVER` 规则必须保留原语义；
- 大 CPU 阶段 p99 成为热点后评估更细 cooperative chunking。

每个候选独立提交、独立 ABBA、独立 No-Go。无收益候选完整回退，不阻塞主架构。Go/C++ ABI、allocator、PGO、LTO 和 ISA 优化不在本方案内。

## 六、确定性预算与启动行为

### 6.1 公式产生方式

- 公式只在开发/隔离环境通过离线 ABBA、并发阶梯和 soak 确定；
- 分别扫描 CPU、内存、FD/PID、I/O runner、flow、出站连接、队列和 retained bytes；
- 网络容量公式使用可控本地 fixture，公网只做韧性验证；
- 使用简单、单调、可审计的缩放公式，并以未参与拟合的资源包络做 holdout；
- holdout 失败时回到离线修正，不允许线上学习补救；
- HostBrr 6C/12GB 只是样本，不能形成部署档位或常量。

### 6.2 force_max 启动顺序

```text
读取并验证配置
  -> 探测 ResourceEnvelope
  -> 计算并完整校验 ForceMaxBudget
  -> 初始化 MemoryBudget/TransportAdmission/OwnerAdmission
  -> 创建并等待 ComputeExecutor ready
  -> 创建 QuickJS compatibility lane
  -> 初始化 Curl multi/resolver/cache/fetch runtime
  -> 初始化 ConversionFlow registry
  -> 预热可信内置模板、规则和缓存目录
  -> 初始化 PressureGuard
  -> 创建全部 Beast I/O runner 和 handler permit
  -> 发布 budget/runtime snapshot
  -> bind/listen
```

- force_max 不允许 lazy worker/capacity initialization；
- `/healthz` 只有在完整预算已应用且所有必要组件 ready 后才返回 ready；
- 初始化失败在监听前退出，禁止静默切到旧引擎、compat 或较小预算；
- 缓存、DNS 和未知用户订阅可能是冷的，但 CPU/I/O/flow/outbound 能力必须已经全量启用。

### 6.3 运行时资源变化

- cgroup/affinity/cpuset 缩小时立即按同一确定性公式重算并 clamp 新工作；
- 外部资源扩大时，读取到稳定的新边界后一次性重算并应用完整新预算，不逐级增长；
- 这属于外部资源变化响应，不是容量探索；
- 重要变化写结构化日志并更新 budget snapshot，不记录用户请求内容。

## 七、配置兼容与可观测性

- 唯一公开入口仍为 `resource_control=force_max`；本方案不暴露十几个内部调优参数。
- `max_concurrent_threads`、`max_server_threads`、`max_pending_connections` 在其他模式保持原语义；force_max 使用 `ForceMaxBudget`，仅在 Dashboard 显示这些旧值未参与最终预算。
- `request_deadline_ms`、下载大小、SSRF/TLS、代理、安全 profile、参数含义和输出保持有效，force_max 不覆盖 deadline。
- `force_max_curve_fingerprint` 保持解析兼容并标记 deprecated；不得因硬件不匹配阻止 force_max 满性能启动。建议一个兼容周期后移除功能，只保留 warning。
- 开发期间允许仅供 ABBA 的内部 `legacy|flow` 和逐轴预算覆盖；未知值拒绝启动；正式交付前必须删除。

Dashboard/安全诊断至少显示：

- envelope 来源与完整性；
- formula revision；
- calculated/applied/guarded budget；
- runtime ready 和启动阶段；
- compute worker busy/idle、queue age、flow active/waiting/suspended；
- owner/follower、admission count/bytes；
- Curl pending/active/open/cache/per-host；
- retained/fetch/cache bytes；
- PressureGuard 状态、触发原因和恢复次数；
- event-loop lag、上下文切换和低基数阶段耗时；
- server/upstream/user/client/capacity 失败归因。

不得记录原始 URL、token、header、正文或可逆用户身份。

## 八、严格实施顺序

以下每项应独立提交；标题为计划标题，实际提交前按 staged diff 确定最终 Conventional Commit 标题。

### 阶段 0：冻结基线与建立最终账本

- 计划标题：`docs(performance): define final force max implementation plan`
- 未来开工时重新记录当前 `dev` exact SHA、工作树、依赖锁、配置、现有测试入口、镜像和运行态；`6d5dcddd` 仅作为本轮规划参考。
- 在仓库外建立可恢复的 ABBA 语料、命令和结果目录，不提交私密订阅或大规模压测结果。
- 修正现有文档关于 sanitizer 和旧硬件指纹语义的漂移。
- 完成门：基线输出/hash、错误、取消、deadline、singleflight、缓存、上传副作用、阶段耗时和资源恢复可稳定复现。
- 回滚：无产品源码变化。

### 阶段 1：机械拆分 conversion pipeline

- 计划标题：`refactor(conversion): extract conversion pipeline stages`
- 文件：`interfaces.cpp`；新增 `conversion_pipeline.h/.cpp`；更新 `CMakeLists.txt`。
- 只拆分参数解析、策略、依赖计划、节点处理、目标生成和响应组装，不改变调用顺序或线程模型。
- 完成门：完整兼容/安全基线、smoke 和输出 hash 一致。
- 回滚：整体回退本提交。

### 阶段 2：建立预算数据合同，不应用最终预算

- 计划标题：`refactor(resource): define deterministic force max budget`
- 文件：`resource_probe.*`、`force_max_budget.*`、`resource_control.*`、settings snapshot、statistics、main、CMake。
- 定义显式不可变数据和 legacy adapter；此阶段不改变 force_max 请求能力，不宣称满性能完成。
- 新组件只能接收显式预算，禁止自行读取型号或散落推导隐藏常量。
- 完成门：确定性、单调、溢出、分数 CPU、无 cgroup/无 PSI/低 nofile 输入测试通过。
- 回滚：保留旧 snapshot adapter，回退新类型。

### 阶段 3：建立共享 ComputeExecutor

- 计划标题：`refactor(runtime): add bounded compute executor`
- 文件：新增 `compute_executor.*`；调整 `workload_scheduler.h`、`cooperative_cpu.h`、main、statistics、CMake。
- 先不承载正式 flow；实现生命周期、有界队列、deadline、取消、worker-local metrics、软亲和接口和反向 join。
- 完成门：无自 join、悬挂 future、忙等、线程泄漏或 completion 丢失；ASan/UBSan 通过。
- 回滚：执行器尚未切流，可独立删除。

### 阶段 4：补全 webGetOwnedAsync

- 计划标题：`refactor(fetch): complete async owned fetch lifecycle`
- 文件：`webget.h/.cpp`、fetch context、main、statistics。
- 支持无缓存 GET、绝对 deadline、冻结设置、同步 callback、完整 retained lease 和启动/关闭。
- 完成门：同步/异步 fetch 的状态、正文、header、cache、fallback、代理和安全语义一致；等待不占 compute worker；ASan/UBSan 通过。
- 回滚：保留同步入口，回退异步接线。

### 阶段 5：建立 ConversionFlow mailbox

- 计划标题：`refactor(runtime): add serialized conversion flow`
- 文件：新增 `conversion_flow.*`；调整 conversion service、interfaces、request context、CMake。
- 暂不切正式 force_max；完成 phase、mailbox、thread-local 恢复、exactly-once、取消和 shutdown。
- 完成门：重复 callback、同步 callback、owner/follower 取消和 shutdown 压力矩阵通过；ASan/UBSan 必跑。
- 回滚：入口未切流，可完整删除。

### 阶段 6：异步化外部配置与 import

- 计划标题：`refactor(config): resolve external dependencies asynchronously`
- 文件：conversion pipeline、interfaces、settings、templates。
- 完成门：候选顺序、fallback、渲染、解析、错误状态和安全边界一致。
- 回滚：独立回退本子阶段。

### 阶段 7：异步化 subscription、ruleset 与 base

- 计划标题：`refactor(conversion): separate fetch from parsing`
- 文件：nodemanip、multithread、ruleconvert/ruleset output、generators、conversion pipeline。
- 分别完成 subscription 和 ruleset/base 两个可独立提交子阶段。
- 完成门：原始顺序、group ID、provider/native remote、规则顺序、缓存和失败链接语义一致；慢上游不增加 compute busy worker。
- 回滚：每个子阶段独立回退。

### 阶段 8：处理 inja、上传和 QuickJS

- 计划标题：`refactor(template): suspend dynamic I/O safely`
- 文件：templates、upload、interfaces、script_quickjs。
- inja resolver、异步上传和 QuickJS compatibility lane 分三个独立提交。
- 完成门：动态 fetch 不重复；上传/脚本副作用 exactly-once；QuickJS 不阻塞普通 executor。
- 回滚：各候选独立回退。

### 阶段 9：建立 waitable owner admission

- 计划标题：`feat(runtime): add waitable force max admission`
- 文件：新增 owner admission；调整 conversion service、interfaces、request context、statistics。
- 完成 cache/singleflight/admission 固定顺序、follower 豁免、有界公平等待和取消移除。
- 完成门：包络内无容量拒绝；无 permit/bytes 泄漏；最老合法请求不饥饿。
- 回滚：候选 flow 尚未默认启用，可恢复 legacy admission。

### 阶段 10：修正 Beast transport admission

- 计划标题：`refactor(server): wait for force max transport capacity`
- 文件：Beast/httplib/server/request context。
- 已 accept 连接达到业务硬边界时返回确定 HTTP 响应；health/overload response 保留独立资源；不得直接 shutdown/close。
- 完成门：软饱和无 503/reset，硬包络响应完整，health 不被普通 backlog 饿死。
- 回滚：恢复旧 transport admission，新 flow 仍不默认启用。

### 阶段 11：接通候选 flow 和通用多线程优化

- 计划标题：`perf(runtime): run force max on conversion flow`
- 文件：interfaces、conversion service/pipeline、compute executor、nodemanip、statistics。
- 仅内部 ABBA 开关启用新 force_max；加入软 flow 亲和、worker-local metrics、cooperative chunking。
- 机会式请求内并行单独提交；中央队列分片/work stealing、PCRE2 compiled plan 仅在 profile 证明后作为可选子提交。
- 完成门：单重请求延迟改善；多 owner 高峰吞吐、公平性、p95/p99、CPU/request 和上下文切换不退化。
- 回滚：每个性能候选独立关闭/回退，正确的异步 flow 不受可选 No-Go 阻塞。

### 阶段 12：让所有容量维度显式消费预算

- 计划标题：`refactor(resource): apply force max budget to all runtimes`
- 文件：resource control/budget、compute executor、webget、Beast、owner admission、interfaces、main、statistics。
- CPU、flow、Curl、I/O runner、handler、transport/owner queue、retained/cache bytes 全部消费同一个 provisional `ForceMaxBudget`。
- 隔离 ABBA 可使用内部逐轴覆盖；正式交付前删除。
- 完成门：Dashboard 可证明 detected -> calculated -> applied；无散落旧 ceiling。
- 回滚：内部开关切回 legacy，逐组件恢复 adapter。

### 阶段 13：离线标定并冻结确定性公式

- 计划标题：`perf(resource): calibrate deterministic force max budget`
- 前置：最终执行拓扑、准入和多线程路径已经稳定；此前不得确定最终 active-flow/outbound 等公式。
- 在隔离环境逐轴 ABBA，覆盖不同 CPU/内存/cgroup/FD 和 workload；使用 holdout 包络验证。
- 将通过的简单单调公式写入 `force_max_budget.*`，增加 formula revision。
- 排除 AVX、型号字符串、L3、在线学习和每机持久曲线。
- 完成门：每个已声明包络内 100% server-attributable success、0 capacity rejection/reset/OOM/restart，吞吐提高且尾延迟/公平性不退化。
- 回滚：回退公式提交，不影响新运行时正确性。

### 阶段 14：实现 PressureGuard

- 计划标题：`feat(runtime): guard force max hard resource pressure`
- 文件：pressure guard、resource control、admission、compute、webget、statistics、main。
- 只接硬资源危险；固定 guarded budget；不取消活动任务；一次性恢复 full budget。
- 完成门：CPU 满载/backlog 不误触发；注入 memory/FD/cgroup shrink 时保护新工作；解除后一次恢复；重复 guard 被报告为公式缺陷。
- 回滚：关闭 guard 后保持静态 full budget，绝不回到 AIMD。

### 阶段 15：原子启动切换与旧 force_max 路径清理

- 计划标题：`refactor(runtime): activate immediate full force max startup`
- 文件：main、runtime coordinator、resource control、interfaces、conversion service、Beast、webget、multithread、statistics、配置示例/文档。
- 固化启动和关闭顺序；监听前完整 ready；删除 force_max 的 legacy blocking flow、AIMD/online shadow/gradual recovery 和内部 ABBA override。
- `compat/adaptive` 不在本方案内，不改变可观察行为。
- 完成门：冷启动第一批请求已使用完整预算；初始化失败监听前退出；旧 digest 可回滚。
- 回滚：运行态只使用前一不可变 OCI digest，不保留进程内半新半旧 fallback。

### 阶段 16：最终验证、交付和证据账本

- 计划标题：`docs(runtime): record force max validation evidence`
- 完成下文全部正确性、性能、跨平台、CI、OCI、测试实例、回滚和 soak 门。
- 本阶段仍不包含 master、正式实例、tag、Release 或 latest。

## 九、测试与验证合同

### 9.1 不新增测试文件

复用并扩展：

- `tests/concurrency_primitives_test.cpp`
- `tests/settings_snapshot_test_helper.cpp`
- `tests/settings_view_test.cpp`
- `tests/webserver_error_test.cpp`
- `tests/curl_handle_pool_test.cpp`
- `tests/statistics_v2_test.cpp`
- `tests/upload_persistence_test.cpp`
- `tests/compatibility_security_baseline.py`
- `tests/shutdown_process_test.py`
- `scripts/run-subconverter-smoke.py`

每个提交运行现有 fast CTest；每个行为边界阶段运行完整 CTest。所有 mailbox、取消、队列、reactor、共享正文、字节租约、worker 生命周期变化立即运行完整 ASan/UBSan。并发阶段重复运行现有 concurrency/shutdown 场景，不能用一次通过代替竞态证明。

### 9.2 离线 ABBA

- A 为未来开工时记录的 exact baseline SHA 构建的不可变镜像；若立即实施，可使用 `6d5dcddd`，否则必须刷新。
- B 为候选 exact SHA；A/B 使用相同依赖锁、编译模式、配置、fixture 和 cgroup。
- 每个关键点至少执行 `A-B-B-A`，基线噪声稳定后停止，不机械扩展低价值长矩阵。
- 冷启动和热缓存分开测；冷启动每轮使用新进程和空应用缓存，验证第一个快照已经 full budget。
- 资源维度分开扫描：CPU、内存、FD/PID；覆盖分数 CPU、低资源、HostBrr 6C/12GB 和更大 holdout 点。
- HostBrr 可从 24/48/96/192 并发开始，再围绕吞吐拐点二分；这些数字只写测量账本，不进入配置。

Workload 至少覆盖：

- 本地 CPU-heavy；
- 单个重 owner 和 2～3 个重 owner；
- 大量不同 owner；
- 相同请求 singleflight 洪峰；
- provider/cache hit；
- 多 subscription、多 ruleset、大响应；
- inja 动态 fetch、QuickJS、上传；
- slow upstream、retry、永久失败；
- owner/follower 分别断开、全部消费者离开；
- 低/中/高 cost 混合公平性；
- 瞬时突发、重复洪峰和压力后恢复。

### 9.3 通过门

已声明容量包络内必须同时满足：

- 输出正文、顺序、响应头、状态码、deadline、重试、取消和失败归因与基线一致；
- server-attributable success 100%；
- capacity rejection、静默 close/reset、OOM、restart 为 0；
- 正确完成 response/s 与 owner/s 提升超过基线噪声；
- p50/p95/p99、TTFB、最老等待、各 cost class 公平性不出现超出噪声的恶化；
- CPU/request、run queue、context switch、RSS/PSS、FD、线程、连接、TIME_WAIT、Curl pending/active、retained bytes 可解释；
- 压力结束后 flow、fetch、队列、FD、线程、连接、缓存和字节租约恢复稳定；
- 冷启动首批请求无 warm-up、probe、learning 或 permit 增长过程。

机会式请求内并行还必须证明：

- 空闲时单重请求完成时间下降超过噪声；
- 高峰时总吞吐、公平性、p99、CPU/request 和 context switch 不退化；
- 不满足即独立 No-Go，不阻塞异步主架构。

### 9.4 全局 No-Go

- 任一输出/顺序/安全/取消/副作用语义漂移；
- flow/mailbox completion 重入、重复终态、数据竞态、资源泄漏或 shutdown 悬挂；
- deadline 被内部阶段重置；
- follower 消耗 owner permit；
- 包络内容量拒绝或静默 socket close；
- 第一批请求未使用完整预算；
- PressureGuard 把正常满载当危险、逐级恢复或在线学习；
- 可选性能候选收益未超过噪声；
- 性能收益来自延长 deadline、扩大无界队列或增加不可恢复资源；
- 旧不可变 digest 无法回滚。

## 十、跨平台、CI、OCI 与测试实例

### 10.1 跨平台

- Linux amd64：完整功能、性能和 sanitizer 主目标；
- arm64、armv7：编译和现有 smoke，不引入 x86 假设；
- Windows amd64：完整 CTest、Beast/httplib、取消和启动预算 fallback；
- OpenWrt：无 cgroup/无 PSI/低内存/低 nofile fallback、APK 和真实 rootfs smoke；
- 不把固定测试数量作为永久合同，按测试名称与行为验收。

### 10.2 证据链

```text
baseline exact SHA/image
  -> candidate exact SHA
  -> fast/full CTest
  -> exact-SHA ASan/UBSan
  -> exact-SHA CodeQL + dev open alerts review
  -> Linux amd64 smoke
  -> arm64/armv7 non-publishing cross-build
  -> Windows amd64 build/smoke
  -> OpenWrt non-publishing smoke
  -> Docker Hub/GHCR dev same digest
  -> OCI revision == candidate SHA
  -> HostBrr test image@digest
  -> direct/public health, version, smoke, hash, budget snapshot
  -> old digest rollback and verification
  -> candidate restore and verification
```

### 10.3 HostBrr

- 测试实例当前旧 revision 不能代替 future exact baseline；先部署 exact baseline image。
- 候选必须固定 digest、禁用测试服务自动漂移，只重建测试 project。
- 正式实例继续在线时，只做低负载交付验收；高压 ABBA/24h soak 需要独占 staging 或明确 HostBrr 独占维护窗口。
- 记录并核对正式容器在测试前后 ID、镜像、StartedAt、restart、OOM 未变化。

### 10.4 Soak

- 先 1 小时预检，再 24 小时最终 soak；
- 持续负载取离线实测拐点以下的安全高位，每小时加入短时突发；
- 不允许 OOM、restart、server/capacity failure；
- RSS/PSS、FD、线程、连接、缓存、flow/fetch 和 retained bytes 不得单调增长；
- 每次突发后必须恢复稳定；
- 最后重跑语义/hash smoke。

## 十一、回滚原则

- 每个结构阶段独立提交、独立测试、独立回滚；可选性能候选 No-Go 时只回退自身。
- 开发期内部 `legacy|flow` 开关只用于 ABBA，不能成为正式长期 fallback。
- 正式候选初始化失败必须在监听前退出，不能隐式变成 compat 或旧 force_max。
- 运行态回滚使用前一不可变 OCI digest；必须实际演练旧 digest -> 候选 -> 旧 digest -> 候选。
- 超时或命令失败后先检查最终状态，不能盲目重复部署。

## 十二、实施执行规则

本次实施必须：

1. 先读取本文件全文；
2. 重新核对当前 `dev`、工作树、文档、测试、CI、HostBrr test runtime 和授权边界；
3. 将本方案写入项目 `docs` 形成正式实施账本并提交阶段 0；
4. 严格按阶段 1 -> 16 顺序执行，不跳阶段，不提前标定最终预算；
5. 每个阶段更新账本、检查 staged diff、使用 Conventional Commit、验证后再继续；
6. 不新增测试文件，不触碰 master/正式实例/tag/Release/latest，除非用户后续明确扩大授权；
7. 任一必需门失败时停止并回滚当前阶段；不得用后续阶段掩盖失败；
8. 完成的定义是 exact source/CI/OCI/test runtime/public behavior/rollback/soak 全链证据，不是代码写完或 CI 绿色。

## 十三、强制安全合同

## ConversionFlow actor 合同

- 每个 flow 同时最多存在一个 mailbox drain task；callback 只能提交带 operation ID 和阶段 generation 的事件，不能直接修改 flow 状态。
- 登记 outstanding operation 后必须在锁外调用 fetch，以承受 cache hit、`data:` 和拒绝路径的同步 completion。
- terminal 使用原子 exactly-once claim；迟到事件只能释放自身 lease，不能再次发布、写缓存或修改统计。
- flow 自保持到 terminal；异步 callback 使用 weak reference，禁止 flow/operation/callback 引用环。
- mailbox 必须保留 terminal/cleanup 前进通道。普通 continuation 队列满时，已接受 flow 仍必须能够完成或释放资源。
- 禁止嵌套持有 singleflight、flow、cache、admission 和 transport session 锁；completion、取消注册销毁和外部回调一律在锁外执行。

## Fetch 与快照合同

- `SettingsSnapshot` 必须冻结代理、TLS、安全、缓存、下载大小、deadline、重试和源切换；异步阶段禁止重新读取可变 `effectiveSettings()`。
- 所有子操作继承同一个绝对 deadline，不得按阶段重置。
- 除活动连接外，pending fetch count/bytes、每 flow fan-out 和每源站上限也必须受预算约束。
- 磁盘缓存和同步文件 I/O 不得运行在 Beast reactor；若会阻塞 continuation，则使用独立有界 blocking-I/O lane。
- `force_max` 缺少异步 DNS 能力时，必须提供有界异步解析替代或在监听前启动失败；禁止静默退回同步 fetch。

## Admission 与执行器合同

- follower 虽不占 owner/compute permit，仍必须计入 socket、FD、请求元数据和等待字节。
- grant、deadline、client disconnect、shutdown 使用 exactly-once claim；取消 waiter 必须可 O(1) 移除。
- 保留 health、错误响应、completion、cleanup 和 lease release 所需的独立 FD/内存/执行许可。
- ComputeExecutor worker 内禁止 `future.get()`、condition wait、caller-runs、busy-spin、提交同一 executor 后同步等待。
- task group 通过 mailbox join event 完成；软 flow 亲和不能绕过 owner/cost 公平与老化。
- 机会式 sibling permit 必须原子获取；不能依据可能过期的 idle 快照批量启动。

## QuickJS 合同

- Runtime/Context 单 worker 独占，不跨线程共享。
- worker、queue entries/bytes、QuickJS heap/stack 均计入 `ForceMaxBudget`。
- interrupt handler 检查绝对 deadline 和取消；原生 sleep 改为可取消等待。
- QuickJS lane 饱和属于软等待，不能占住普通 continuation worker；副作用严格 exactly-once。

## ForceMaxRuntime 事务启动

- 使用临时 runtime 完成 envelope 读取、checked budget、交叉不变量、全部组件创建和能力校验。
- 创建完成后再次读取硬资源边界；启动期间边界变化则销毁候选并进行有界重算。
- 全部成功后原子发布 runtime，最后 bind/listen；任何失败不能留下半初始化全局 static。
- 总内存 ledger 必须包含当前 RSS、程序基线、线程栈、socket buffer、request/flow/fetch/cache/QuickJS/response，并预留 health/cleanup headroom；各子预算不能重复获得整机比例。
- 预算是派生运行态，不回写用户配置。

## PressureGuard 前进性

- 固定状态仅为 `Full -> Guarded -> RecoveryConfirm -> Full`。
- Guarded 先停止新 owner、机会式 sibling 和投机预热，再限制新连接/新出站。
- 已接受 flow、completion、cleanup 和 lease release 的最低前进通道永远保留，否则 guard 会形成资源无法释放的自锁。
- 遥测失败保持完整启动预算并告警，不逐秒减 permit。
- 外部硬限额缩小在线 clamp；外部增加资源默认通过重启重新执行预监听预算计算，不把热扩容变成在线探索。

## 显式关闭顺序

1. 停止 accept 和新 owner admission。
2. 取消等待者和 flow，但保留 transport、mailbox 和 ComputeExecutor。
3. 停止新依赖，取消 Curl、QuickJS 和 blocking-I/O 活动。
4. 让迟到 callback 投递 terminal/cleanup event。
5. drain flow、发布关闭响应、释放全部 lease。
6. join QuickJS 与 blocking-I/O lane。
7. join ComputeExecutor。
8. drain transport write，最后关闭 I/O reactor。

禁止 worker join 自身；任一步超过 shutdown deadline 必须留下明确阶段、计数和非零诊断，不能静默挂死。
