# 安全档位与平滑迁移

## 推荐默认方案

现有部署默认保持 `lan` 档位。该档位保留历史行为，适合家庭内网、NAS、软路由、旁路由、Docker 内网等自用部署，用户仍可通过项目访问本地资源、私有网段资源和 fake-ip 资源。

公网部署建议显式切到 `public`：

```ini
[security]
profile=public
```

或使用环境变量：

```bash
SUBCONVERTER_SECURITY_PROFILE=public
```

## 三个档位

- `lan`：默认值，兼容旧行为。公开请求、外部配置、规则集、订阅链接仍可访问本地、私有网段和 fake-ip 资源。
- `public`：公网推荐值。仅限制由公开请求控制的不可信拉取目标，例如 `/sub?url=...`、`/sub?config=...`、`/getruleset?url=...`、公开外部配置里的远程 import/fetch。项目自带本地模板、部署者配置的默认模板和本地 base 文件继续可用。
- `strict`：在 `public` 的拉取限制基础上，始终禁用公开请求触发的 Gist 上传。

升级后不自动切换档位，也不要求已有用户修改配置。缺省、显式 `lan`、已有启动命令、环境变量、Docker/Compose 端口和 API 行为都保持不变。

## 公网模式不会阻止什么

`public` 不会阻止项目读取自带的 `base/` 模板、部署者在配置文件里指定的本地模板，以及受信任默认配置里的本地资源。限制只挂在“请求方可控”的来源上。

## 上传开关

`lan` 保持旧上传行为。`public` 默认禁用公开请求触发的上传，如确实需要可显式开启：

```ini
[security]
profile=public
allow_public_upload=true
```

也可以使用：

```bash
SUBCONVERTER_ALLOW_PUBLIC_UPLOAD=true
```

`strict` 下即使设置 `allow_public_upload=true` 也不会允许公开上传。

这里必须按“最终有效策略”理解 `allow_public_upload`：

| 档位 | 配置为 `false` | 配置为 `true` |
| :--- | :--- | :--- |
| `lan` | 允许（历史兼容） | 允许 |
| `public` | 禁止 | 允许 |
| `strict` | 禁止 | 禁止 |

因此本次整改不会静默修正这个容易误解的旧命名，否则会让合法 LAN 用户升级后突然失去上传能力。

## 启动诊断

启动日志新增以下稳定事件名，便于人工检查和日志告警：

- `SECURITY_PROFILE_EFFECTIVE`：显示最终生效的档位和来源；环境变量覆盖文件时，同时显示文件候选来源。
- `SECURITY_PROFILE_INVALID_FALLBACK`：配置值或环境变量拼写无效，按历史行为回退 `lan`。这是兼容回退，不是安全认可。
- `SECURITY_UPLOAD_VALUE_INVALID`：上传环境变量无法识别，按历史行为得到 `false`。
- `SECURITY_UPLOAD_EFFECTIVE`：显示实际允许或禁止上传，以及是 LAN 兼容、public 开关还是 strict 策略决定。
- `SECURITY_EXPOSURE_POSSIBLE`：`lan` 监听 `0.0.0.0` 或 IPv6 全接口时提示“可能暴露”。事件固定标记 `public_reachability=unknown`，因为程序无法仅根据监听地址判断宿主防火墙、云安全组、NAT、端口发布和反向代理。

无效 `security.profile` 继续回退 `lan` 是为了让旧部署无感升级；公网部署者看到该告警时，应修正拼写并显式选择 `public` 或 `strict`，而不是依赖回退值。

## Docker 与 Compose 的端口发布

仓库继续保留 `25500:25500`，以免改变现有局域网部署者的访问方式。它会把容器端口发布到宿主机全部接口，属于潜在运维暴露面，但不能单独证明实例已经公网可达。

只允许宿主机访问时，可自行使用 `127.0.0.1:25500:25500`；确实对公网提供服务时，继续保留所需端口映射，并显式设置 `security.profile=public` 或 `strict`，同时检查防火墙、云安全组和反向代理访问控制。

## 推荐迁移步骤

1. 内网自用部署不需要改配置，继续使用默认 `lan`。
2. 对公网暴露的实例，先更新镜像但保持 `lan`，确认业务正常。
3. 将公网实例切到 `public`，观察日志里是否有被阻止的私有地址访问。
4. 如果被阻止的是业务必须访问的内网资源，说明该实例更适合作为内网服务运行；不要直接暴露到公网。
