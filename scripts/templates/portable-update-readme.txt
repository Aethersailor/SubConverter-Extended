SubConverter-Extended 便携版自动更新

更新来源固定为本项目的最新稳定 GitHub Release。更新器会依次尝试内置公共反向代理和 GitHub 直连，并验证仓库、稳定版本、平台、架构、文件大小、SHA-256 与 BUILD-INFO.json。

Linux 命令：

  ./update.sh status
  ./update.sh check
  ./update.sh apply
  ./update.sh rollback

启用自动检查和自动安装：

  ./update.sh enable-auto

禁用自动安装：

  ./update.sh disable-auto

选择更新连接模式：

  ./update.sh set-proxy auto
  ./update.sh set-proxy gh-proxy
  ./update.sh set-proxy yylx
  ./update.sh set-proxy direct

默认不自动检查或安装。执行 enable-auto 后，start.sh 会按更新配置检查稳定 Release；有新版时，更新器先在独立端口验证候选程序，再原子交换程序目录。升级会继承 pref.toml、pref.yml、pref.yaml、pref.ini、generate.ini、gistconf.ini、profiles、cache，以及默认的 stats 或 base/stats 目录。

自定义模板、规则、脚本或非默认统计目录建议放在程序目录之外，并通过配置文件引用。更新前仍应保留独立备份。

持久更新数据保存在 SubConverter-Extended.update 目录。该目录与 SubConverter-Extended 程序目录位于同一父目录。移动便携版时，需要同时移动这两个目录。删除 SubConverter-Extended.update 会删除更新配置、状态和可回滚版本，但不会删除当前程序目录中的用户配置。

apply 和 rollback 返回退出码 10 时，表示程序目录已经切换。start.sh 会自动重新进入新版本；从终端手动执行 update.sh 时，可以重新启动主程序。

如果 status 显示 error，不要删除 SubConverter-Extended.update/pending.json。先执行：

  ./update.sh recover

recover 验证事务两侧的 BUILD-INFO.json 和运行行为，只接受能够确认身份的程序目录。恢复失败时，停止更新并保留 SubConverter-Extended.update 以便排查。
