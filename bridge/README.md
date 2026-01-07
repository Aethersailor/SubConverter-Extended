# Mihomo Parser Bridge - Quick Start Guide

## 📦 What's Been Done

已为 subconverter 集成 mihomo 的节点解析器（通过 CGO）。

### 新增文件

| 文件 | 用途 |
|------|------|
| `bridge/converter.go` | Go 包装函数（调用 mihomo） |
| `bridge/go.mod` | Go 依赖管理 |
| `bridge/build.sh` | 本地编译脚本 |
| `src/parser/mihomo_bridge.h` | C++ 头文件 |
| `src/parser/mihomo_bridge.cpp` | C++ 实现 |

### 修改文件

| 文件 | 修改内容 |
|------|----------|
| `CMakeLists.txt` | 链接 Go 静态库 |
| `Dockerfile` | Alpine 版，添加 Go 编译阶段 |
| `Dockerfile.debian` | Debian 版，用于 glibc 二进制 |

## 🚀 如何编译（Docker）

```bash
# 在项目根目录执行（使用 Alpine 版）
docker build -t subconverter:mihomo .

# 或使用 Debian 版
docker build -f Dockerfile.debian -t subconverter:mihomo-debian .
```

**编译流程**：

1. 第一阶段（Go）：编译 `libmihomo.a`
2. 第二阶段（C++）：编译 subconverter 并链接 Go 库
3. 第三阶段：打包最终镜像

**预期时间**：首次约 7 分钟（有缓存后 ~4 分钟）

## 🧪 如何测试

### 1. 运行容器

```bash
docker run -d -p 25500:25500 subconverter:mihomo
# 默认时区已设为 Asia/Shanghai，如需覆盖可传入：
# docker run -d -p 25500:25500 -e TZ=Asia/Shanghai subconverter:mihomo
```

### 2. 测试节点解析

```bash
# 测试 SS 链接
curl "http://localhost:25500/sub?target=clash&url=ss://..."

# 测试 VMess 链接
curl "http://localhost:25500/sub?target=clash&url=vmess://..."
```

### 3. 验证 mihomo 兼容性

对比生成的配置与 mihomo 原生解析的结果应该完全一致。

## ⚠️ 已知问题

### IDE Lint 错误

当前 IDE 会报错（缺少 `libmihomo.h`），这是正常的，因为该文件在 Docker 编译时生成。

**解决方案**：

1. 本地安装 Go（如果需要本地开发）
2. 运行 `cd bridge && bash build.sh`
3. IDE 错误会消失

## 📝 后续步骤

1. ✅ 构建系统已集成
2. ⏳ 等待 Docker 构建测试
3. ⏳ 集成到 `src/handler/interfaces.cpp`（调用mihomo::parseSubscription）
4. ⏳ 添加单元测试

## 💡 如何更新 mihomo

```bash
cd bridge
go get -u github.com/metacubex/mihomo
go mod tidy
```

然后重新构建 Docker 镜像即可。

## 📄 许可证

本模块（`bridge/`）使用的 Mihomo 解析器源自 [metacubex/mihomo](https://github.com/metacubex/mihomo)，遵循 **MIT License**。

整个 subconverter 项目遵循 **GPL-3.0 License**。根据许可证兼容性，MIT 代码可以在 GPL-3.0 项目中使用，但整体项目仍然受 GPL-3.0 约束。
