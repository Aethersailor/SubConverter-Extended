# 日志与诊断

本项目的日志以排障为目的，同时避免把订阅、节点或凭据复制到持久化日志。默认级别为 `info`；配置文件中的 `advanced.log_level` 会在导入节点、规则集和任务前生效。`print_debug_info=true` 会覆盖该设置并启用 `verbose`。

## 请求关联

每个进入应用路由生命周期的 HTTP 响应都会包含服务端生成的 `X-Request-ID`，相同 ID 也会写入该请求同步处理期间的日志。客户端传入的同名请求头不会被信任或复用。响应微缓存和并发请求合并也不会复用其他请求的 ID。HTTP 解析器在进入应用路由前直接拒绝的畸形或超限请求不在此保证内。`X-Request-ID` 表示本次到达源站的 HTTP 交互；如果外部 CDN 直接返回缓存响应，它不是新的源站处理证据。

稳定事件 `HTTP_RESPONSE_PREPARED` 包含方法、安全路径、状态码、处理耗时和可确定的响应字节数。该事件表示服务端已经准备好响应，不代表客户端一定完整接收了响应。

排查转换问题时，建议按以下顺序检索同一个 `request_id`。如果先看到 `SUB_REQUEST_COALESCED`，该请求是等待者；请改用事件中的 `owner_request_id` 查找实际执行转换的请求：

1. `AUTO_TARGET_RESOLVED`：`target=auto` 的最终目标和 UA 家族。
2. `SUB_ROUTE_RESULT`：节点解析器或 provider 路径、调用次数和失败次数。
3. 具体错误事件：例如 `NODE_PARSER_FAILED`、`HTTP_UNEXPECTED_EXCEPTION`。
4. `HTTP_RESPONSE_PREPARED`：最终 HTTP 状态和耗时。

## 脱敏边界

日志保留以下排障信息：

- 请求 ID、HTTP 方法、安全路径、状态码、耗时和响应大小；
- 目标客户端、解析器策略、分支、静态原因码和计数；
- URL 协议、HTTP(S) 安全主机摘要和原始长度；
- 是否提供、是否生效、是否回退等布尔状态。

日志会隐藏或摘要化以下内容：

- token、密码、API key、Authorization、Cookie 和代理认证信息；
- 完整订阅 URL、查询参数、节点 URI、请求体和配置正文；
- 原始 User-Agent、设备 ID、上传路径、Base64 配置和未知参数值；
- 解析成功日志不会逐节点输出由订阅控制的节点名称。

所有中央日志在写出前都会执行已知敏感格式脱敏、控制字符转义和单事件长度限制，因此远程内容不能伪造新的日志行。QuickJS 异常和堆栈也经过同一出口。不过这不是通用 DLP：无法识别、没有字段语义的任意文本仍可能保留；受信任脚本显式调用 `console.log` 的输出也不是中央脱敏诊断通道。部署者不应在脚本异常消息、显式控制台输出或节点名称中主动拼接裸凭据。

`/sub?explain=true` 响应采用同一原则：敏感值和稳定短哈希不返回，仅保留长度、数量、是否配置及必要的安全 URL 摘要。摘要只包含协议、可安全显示的 HTTP(S) 主机名和原始长度；对当前目标完全未使用的参数，只报告“未使用”。Explain 响应设置 `Cache-Control: private, no-store` 和 `Pragma: no-cache`，不会进入响应微缓存；相同并发请求仍可在进程内临时合并以避免重复工作。

## 日志文件与轮转

`-l <path>` / `--log <path>` 以追加方式重定向 stderr，不会清空已有文件。打开或重定向失败时，服务会继续使用原 stderr，并记录不包含文件路径的失败阶段和系统错误码。

程序不在进程内轮转日志：

- 仓库提供的 Docker Compose 使用 `json-file`，默认 `max-size=10m`、`max-file=3`；
- systemd 部署建议使用 journald；
- 原生 `-l` 部署应由服务管理器或外部工具轮转。程序不会感知普通的“重命名旧文件后创建新文件”：可靠方式是停服、轮转、再启动。`copytruncate` 可避免重启，但复制与截断之间存在少量日志丢失窗口。当前 `SIGHUP` 仍表示优雅停机，不用于重新打开日志文件。

正常的 `SIGTERM`、`SIGINT`（以及 POSIX 下既有的 `SIGHUP`、`SIGQUIT`）不再误报为 FATAL；当日志阈值包含 INFO 时，会记录 `SHUTDOWN_REQUESTED`。
