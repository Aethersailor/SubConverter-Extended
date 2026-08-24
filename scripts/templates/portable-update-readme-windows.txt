SubConverter-Extended Windows 便携版自动更新

更新来源固定为本项目的最新稳定 GitHub Release。更新器会依次尝试内置公共反向代理和 GitHub 直连，并验证仓库、稳定版本、平台、架构、文件大小、SHA-256 与 BUILD-INFO.json。

PowerShell 命令：

  .\update.ps1 status
  .\update.ps1 check
  .\update.ps1 apply
  .\update.ps1 rollback

也可以使用 update.bat 执行相同命令。

启用自动检查和自动安装：

  .\update.ps1 enable-auto

禁用自动安装：

  .\update.ps1 disable-auto

选择更新连接模式：

  .\update.ps1 set-proxy auto
  .\update.ps1 set-proxy gh-proxy
  .\update.ps1 set-proxy yylx
  .\update.ps1 set-proxy direct

默认不自动检查或安装。执行 enable-auto 后，start.ps1 和 start.bat 会在主程序启动前检查稳定 Release；有新版时，更新器先在独立端口验证候选程序，再切换程序目录。升级会继承 pref.toml、pref.yml、pref.yaml、pref.ini、generate.ini、gistconf.ini、profiles、cache，以及默认的 stats 或 base\stats 目录。更新期间不要同时启动主程序。

自定义模板、规则、脚本或非默认统计目录建议放在程序目录之外，并通过配置文件引用。更新前仍应保留独立备份。

持久更新数据保存在 SubConverter-Extended.update 目录。该目录与 SubConverter-Extended 程序目录位于同一父目录。移动便携版时，需要同时移动这两个目录。

如果目录切换被系统断电中断，程序目录可能暂时不可见。不要删除 SubConverter-Extended.update。运行以下命令：

  powershell -NoProfile -ExecutionPolicy Bypass -File .\SubConverter-Extended.update\recover.ps1

恢复脚本验证事务两侧的 BUILD-INFO.json 和运行行为，只接受能够确认身份的程序目录。恢复失败时，停止更新并保留 SubConverter-Extended.update 以便排查。
