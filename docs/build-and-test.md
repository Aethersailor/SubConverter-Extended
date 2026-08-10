# 构建与测试契约

本文面向源码构建和测试维护者；现有二进制、Docker、Compose、配置与 API 使用方式不受影响。

## 构建基线

- 项目最低支持 CMake 3.13。项目使用 C++20 与 `target_link_directories`；CMake 3.5 无法满足当前构建图。
- 正式构建保持 `Release`，默认 `BUILD_TESTS=OFF`，不改变单二进制交付方式。
- 开启测试使用 `-DBUILD_TESTS=ON`。
- `BUILD_STATIC_LIBRARY=ON` 仍沿用原有静态库路径，不会隐式启用服务端测试。

示例：

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build build -j
```

## 测试集合

| 集合 | 命令 | 含义 |
| --- | --- | --- |
| default | `ctest --test-dir build --output-on-failure` | 默认测试构建中的全部正确性测试，包括服务级兼容基线 |
| fast | `ctest --test-dir build --output-on-failure --label-regex '^fast$'` | 标签为 `fast` 的确定性单元和组件回归 |

Docker 的 `BUILD_TESTS=true` 路径运行全部正确性测试。日常 `dev` 镜像在 amd64 候选构建中运行一次。master 和正式 Release 复用已经通过的源码测试结果，只执行跨架构构建、打包和交付物 smoke。

## 分支验证策略

- `dev` push：并行运行源码级 Python/Go/工作流校验和 amd64 C++ 正确性测试。候选镜像通过运行时 smoke 后，工作流才发布带精确源码 revision 的 `:dev` 镜像。
- dev 环境：部署同一 `:dev` 镜像，验证真实 `/version`、订阅转换、健康状态以及容器重启/OOM 状态。
- 同步前：确认当前完整 dev SHA 的 CI、镜像身份和 dev 实机验收全部成功。同步工作流只负责合并和生成版本标识，不替代这些验证。
- `master`/正式 Release：不重新运行已经在 dev 通过的源码正确性测试，只验证跨架构编译、打包、镜像身份和交付物 smoke。
- 历史 Release：依靠不可变 Release、不可变版本标签和校验清单保护，不在每次 dev 开发时重复下载和测试。

测试应验证可观察行为、输入输出或发布身份。不要为了验证工作流 YAML 中是否存在某段文本、复制一份工作流状态机、冻结可由源码直接计算的哈希，或在无受控资源环境中测量耗时而新增第二套“测试实现”。需要性能结论时，应在目标资源限制和真实工作负载下单独测量。
