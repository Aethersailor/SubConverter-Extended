# Mihomo Parser Bridge

## 📦 概述

本目录用于为 SubConverter-Extended 集成 Mihomo 的节点解析器能力，当前方案通过 CGO 调用相关模块。

## 📁 新增文件

| 文件 | 用途 |
| :--- | :--- |
| `bridge/converter.go` | Go 封装层，负责调用 Mihomo 解析逻辑 |
| `bridge/go.mod` | Go 依赖管理文件 |
| `bridge/build.sh` | 本地编译脚本 |
| `src/parser/mihomo_bridge.h` | C++ 头文件 |
| `src/parser/mihomo_bridge.cpp` | C++ 实现文件 |

## 🛠️ 修改文件

| 文件 | 修改内容 |
| :--- | :--- |
| `CMakeLists.txt` | 增加 Go 静态库链接逻辑 |
| `Dockerfile` | Alpine 版本镜像增加 Go 编译阶段 |
| `Dockerfile.debian` | Debian 版本镜像增加 Go 编译阶段，用于生成 glibc 二进制 |

## 🚀 编译方式（Docker）

```bash
# 在项目根目录执行（Alpine 版本）
docker build -t subconverter:mihomo .

# 或使用 Debian 版本
docker build -f Dockerfile.debian -t subconverter:mihomo-debian .
```

编译流程如下：

1. 第一阶段：使用 Go 编译 `libmihomo.a`
2. 第二阶段：编译 C++ 主程序并链接 Go 静态库
3. 第三阶段：打包最终镜像

首次构建通常约需 7 分钟；有缓存时约 4 分钟。

## 🧪 测试方式

### 1. 运行容器

```bash
docker run -d -p 25500:25500 subconverter:mihomo
# 默认时区为 Asia/Shanghai，如需覆盖可传入：
# docker run -d -p 25500:25500 -e TZ=Asia/Shanghai subconverter:mihomo
```

### 2. 测试节点解析

```bash
# 测试 SS 链接
curl "http://localhost:25500/sub?target=clash&url=ss://..."

# 测试 VMess 链接
curl "http://localhost:25500/sub?target=clash&url=vmess://..."
```

### 3. 验证 Mihomo 兼容性

对比生成结果与 Mihomo 原生解析结果，理论上应保持一致。

## ⚠️ 已知问题

### IDE Lint 报错

某些 IDE 可能提示缺少 `libmihomo.h`。这是预期现象，因为该文件是在 Docker 构建阶段生成的。

如需本地开发，可按以下步骤处理：

1. 本地安装 Go
2. 运行 `cd bridge && bash build.sh`
3. 重新加载 IDE 索引

## 📝 后续计划

1. ✅ 构建系统已完成集成
2. ⏳ 等待 Docker 构建验证
3. ⏳ 集成到 `src/handler/interfaces.cpp`，调用 `mihomo::parseSubscription`
4. ⏳ 补充单元测试

## 💡 更新 Mihomo

```bash
cd bridge
go get -u github.com/metacubex/mihomo
go mod tidy
```

完成后重新构建 Docker 镜像即可。

## 📄 许可证

本模块（`bridge/`）使用的 Mihomo 解析器源自 [metacubex/mihomo](https://github.com/metacubex/mihomo)，遵循 **MIT License**。

整个 SubConverter-Extended 项目遵循 **GPL-3.0 License**。根据许可证兼容性，MIT 代码可以并入 GPL-3.0 项目，但项目整体仍受 GPL-3.0 约束。
