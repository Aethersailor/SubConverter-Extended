# SubConverter-Extended

SubConverter-Extended 是面向多种代理客户端的订阅转换后端增强版，重点完善 Mihomo 节点解析、Proxy Provider、多客户端远程资源、请求诊断和公网部署边界。

## 支持范围

- 为 Mihomo/Clash 生成 Proxy Provider，并使用 Mihomo 解析桥处理节点链接。
- 为 Surge、Quantumult X、Loon、Surfboard 和 Stash 生成客户端原生远程资源或兼容输出。
- 支持 Sing-box、Quantumult 以及多种传统订阅和分享链接目标。
- 提供 `explain=true`、`/inspect`、`X-Request-ID`、安全档位和可选运行统计。

不同目标格式的能力和限制不同。完整范围见[Wiki 的客户端与目标格式](https://github.com/Aethersailor/SubConverter-Extended/wiki/Compatibility)。

## 快速启动

> [!WARNING]
> 下方命令只用于本机首次检查，不会持久化自定义配置或统计数据，并且只把端口绑定到宿主机回环地址。需要让局域网或公网访问时，请先阅读 [Docker 部署文档](https://github.com/Aethersailor/SubConverter-Extended/wiki/Docker-Deployment)，再配置持久化、安全档位、访问控制和 TLS。

```bash
docker run -d \
  --name SubConverter-Extended \
  -p 127.0.0.1:25500:25500 \
  --restart unless-stopped \
  aethersailor/subconverter-extended:latest
```

然后访问：

```text
http://localhost:25500/version
http://localhost:25500/healthz
```

`latest` 对应已验证的最新正式 Release；`vX.Y.Z` 标签用于固定版本和回滚。

不要把宿主机整个 `base` 目录挂载到容器的 `/base`；这会遮盖镜像内的模板、规则和 snippets。需要持久化时，请按 Docker 部署文档只挂载需要修改的配置文件和数据目录。

## 文档

- [README](https://github.com/Aethersailor/SubConverter-Extended)
- [完整 Wiki](https://github.com/Aethersailor/SubConverter-Extended/wiki)
- [最新 Release](https://github.com/Aethersailor/SubConverter-Extended/releases/latest)
- [安全与隐私](https://github.com/Aethersailor/SubConverter-Extended/wiki/Security-and-Privacy)
- [故障排查](https://github.com/Aethersailor/SubConverter-Extended/wiki/Troubleshooting)

## 许可证

SubConverter-Extended 按 [GNU General Public License v3.0](https://github.com/Aethersailor/SubConverter-Extended/blob/master/LICENSE) 发布。Mihomo 解析桥所使用的 Mihomo 依赖同样遵循 GPL-3.0。
