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

默认不自动检查或安装。执行 enable-auto 后，start.sh 会按更新配置检查稳定 Release；有新版时，更新器先在独立端口验证候选程序，再切换程序目录。支持 RENAME_EXCHANGE 的文件系统使用原子交换；不支持时使用可恢复的分步重命名。升级会继承 pref.toml、pref.yml、pref.yaml、pref.ini、generate.ini、gistconf.ini、profiles、cache，以及默认的 stats 或 base/stats 目录。

如果旧版更新器已因不支持 RENAME_EXCHANGE 而失败，需要先手动完成一次便携包升级。反复执行旧更新器无法获得此修复。手动升级时保留用户配置、统计目录及持久更新目录。

自定义本地配置、规则和模板可以放在程序目录之外，避免升级时被新便携包替换；必须先在主配置中明确指定受信任目录。以 /volume1/subconverter-custom 为例，在 base/pref.toml 中设置：

  [common]
  base_path = "/volume1/subconverter-custom"

  [template]
  template_path = "/volume1/subconverter-custom/templates"

base_path 是本地资源的信任根，不是路径前缀，不会自动改变 clash_rule_base 等配置项的路径。保留默认的 base/all_base.tpl 等设置即可继续使用便携包自带的模板，无需复制到外部目录，也无需自行跟进这些内置文件。

外部 INI 中可以用绝对路径引用自定义规则和基础模板，例如：

  [custom]
  enable_rule_generator=true
  overwrite_original_rules=true
  ruleset=DIRECT,/volume1/subconverter-custom/rules/custom.list
  clash_rule_base=/volume1/subconverter-custom/templates/custom.yaml

config= 参数也可指向该受信任目录中的配置文件；作为 URL 查询参数时，需要对文件路径进行 URL 编码。本地相对路径相对于主配置文件所在目录解析，不相对于外部 INI 所在目录解析。默认 Linux 启动器使用程序目录下的 base/pref.toml。

template_path 单独限制模板 include 的读取范围；设置后，相对 include 名称从该目录解析。未设置时，include 仍受主配置工作目录限制；public/strict 的公开请求还必须通过已有的受信任目录检查。路径校验使用真实路径，符号链接和 .. 不能绕过配置的边界。仅信任专用资源目录，不要把 / 或整个卷设为信任根。

明确指定的本地规则集不存在、不可读或越界时，转换会返回错误，并在日志中记录 RULESET_LOCAL_SOURCE_UNAVAILABLE，不再成功返回缺少这些规则的配置。远程规则下载失败沿用原有处理方式。

程序目录中的自建子目录不会因为位于 base/ 下就自动迁移；自动保留范围以上述列表为准。自定义脚本和非默认统计目录需按各自配置项设置外部路径。更新前仍应保留程序目录、持久更新目录和外部资源的独立备份。

持久更新数据保存在 SubConverter-Extended.update 目录。该目录与 SubConverter-Extended 程序目录位于同一父目录。移动便携版时，需要同时移动这两个目录。删除 SubConverter-Extended.update 会删除更新配置、状态和可回滚版本，但不会删除当前程序目录中的用户配置。

apply 和 rollback 返回退出码 10 时，表示程序目录已经切换。start.sh 会自动重新进入新版本；从终端手动执行 update.sh 时，可以重新启动主程序。

如果 status 显示 error，不要删除 SubConverter-Extended.update/pending.json。先执行：

  ./update.sh recover

如果分步切换被断电或进程终止打断，程序目录可能暂时不存在。此时从程序目录的父目录执行：

  ./SubConverter-Extended.update/recover.sh

如果程序目录使用其他名称，替换命令中的 SubConverter-Extended。恢复入口和独立更新器在分步切换前写入持久更新目录。不要手动删除 pending.json、staging、rollback 或 .exchange-old 目录。

recover 验证事务两侧的 BUILD-INFO.json 和运行行为，只接受能够确认身份的程序目录。恢复失败时，停止更新并保留 SubConverter-Extended.update 以便排查。
