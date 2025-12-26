# Subconverter 补丁管理

本目录包含在同步上游代码后自动应用的补丁（patches）。

## 📋 当前补丁列表

### 1. 隐藏指纹补丁
- **文件**: `0001-chore-hide-subconverter-fingerprints-when-fetching.patch`
- **目标文件**: `src/handler/webget.cpp`
- **功能**: 隐藏 Subconverter 的指纹特征
  - 将 User-Agent 从 `subconverter/VERSION` 修改为 `clash.meta`
  - 移除 `SubConverter-Request` 和 `SubConverter-Version` 请求头
- **原因**: 避免部分订阅服务器识别并屏蔽 Subconverter

## 🔄 工作流程

sync-upstream.yml 工作流会按以下顺序执行：

1. **同步上游** → `upstream-master` 分支（纯净上游代码）
2. **Rebase** → 将上游更新应用到 `master` 分支
3. **应用补丁** → 自动应用本目录中的所有 `.patch` 文件
4. **恢复配置** → 恢复 `.github/` 和 `Dockerfile` 等定制配置文件
5. **推送** → 更新远程仓库

## ➕ 添加新补丁

要添加新的补丁：

```bash
# 1. 在 master 分支上进行修改并提交
git add <modified-files>
git commit -m "your message"

# 2. 生成补丁文件
git format-patch -1 <commit-hash> -o .patches/

# 3. 提交补丁文件
git add .patches/
git commit -m "chore: add new patch for <purpose>"
git push
```

## ⚠️ 注意事项

- 补丁按**文件名字典序**应用
- 如果补丁应用失败，工作流会自动中止并恢复状态
- 补丁只应修改**源码文件**，不要修改 `.github/` 或构建配置文件
