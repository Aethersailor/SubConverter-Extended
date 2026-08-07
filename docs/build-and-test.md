# 构建与测试契约

本文面向源码构建和测试维护者；现有二进制、Docker、Compose、配置与 API 使用方式不受影响。

## 构建基线

- 项目最低支持 CMake 3.13。项目使用 C++20 与 `target_link_directories`；CMake 3.5 无法满足当前构建图。
- 正式构建保持 `Release`，默认 `BUILD_TESTS=OFF`，不改变单二进制交付方式。
- 开启测试使用 `-DBUILD_TESTS=ON`。性能基准不会默认构建；需要时同时加入 `-DBUILD_BENCHMARKS=ON`。
- `BUILD_STATIC_LIBRARY=ON` 仍沿用原有静态库路径，不会隐式启用服务端测试或 benchmark。

示例：

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build build -j
```

## 测试集合

| 集合 | 命令 | 含义 |
| --- | --- | --- |
| default | `ctest --test-dir build --output-on-failure` | 默认测试构建中的全部正确性测试；默认不构建 benchmark |
| fast | `python3 scripts/run-test-suite.py --build-dir build --mode fast` | 标签为 `fast` 的确定性单元和组件回归 |
| full | `python3 scripts/run-test-suite.py --build-dir build --mode full` | 全部正确性测试，包括服务级兼容基线；明确排除 benchmark |
| benchmark | `python3 scripts/run-test-suite.py --build-dir build-benchmark --mode benchmark` | 显式性能测量；需使用 `BUILD_BENCHMARKS=ON` 的构建目录 |

benchmark 会打印墙钟时间、吞吐量、内存估算和持久化尺寸。墙钟数据只用于观察，不以单次机器负载波动判定构建失败；确定性 Statistics v2 正确性由 `statistics_v2` 测试负责。

Docker 的 `BUILD_TESTS=true` 路径运行 `full` 正确性集合，不会隐式运行 benchmark。
