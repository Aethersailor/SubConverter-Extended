# External Clash rules

SubConverter-Extended supports importing complete Clash/Mihomo rules from an
external configuration. This is an Extended-only syntax: traditional
`tindy2013/subconverter` ignores `ruleprepend` and `ruleappend`, so it may still
produce a configuration without importing these rules.

INI is the recommended format. Repeated keys are processed in declaration
order:

```ini
[custom]
ruleprepend=https://example.com/first.list
ruleprepend=https://example.com/second.list
ruleappend=https://example.com/last.yaml
```

YAML and TOML external configurations use arrays:

```yaml
custom:
  ruleprepend:
    - https://example.com/first.list
  ruleappend:
    - https://example.com/last.yaml
```

```toml
[custom]
ruleprepend = ["https://example.com/first.list"]
ruleappend = ["https://example.com/last.yaml"]
```

The first version supports only `target=clash`. It rejects `clashr`, node-list
output (`list=true`), and Clash Script mode (`script=true`). Sources must be
remote HTTP(S) URLs; local paths and data URLs are not accepted.

Each source may be either a plain-text list of complete rules or a YAML
document with a root `rules:` sequence. YAML `payload:` files are provider
payloads rather than complete rules and are not supported. Imported `MATCH`
and `FINAL` rules are also rejected because terminal rules remain owned by the
base configuration and configured rulesets.

The final order is:

```text
ruleprepend
base non-terminal rules
generated non-terminal rules
ruleappend
base and generated MATCH / FINAL tails
```

Source order and duplicate rules are preserved. `overwrite_original_rules=true`
removes only the base rules; it does not remove imported or generated rules.
The feature also works when `enable_rule_generator=false`.

Rule downloads use `proxy_ruleset`, a zero cache TTL, and
`Cache-Control: no-cache, no-store, max-age=0` plus `Pragma: no-cache`.
Network failures, non-success HTTP responses, and empty responses are logged
and skipped so later sources can still run. A fetched document that cannot be
parsed or contains an invalid rule stops the conversion with HTTP 400.

The total source count is limited by `max_allowed_rulesets`, the final rule
count by `max_allowed_rules`, and each download remains subject to
`max_allowed_download_size` and the request's normal SSRF policy.

OpenClash may apply later LuCI-side overrides after downloading the generated
configuration. Those later overrides can change the rule order again.

## 中文说明

`ruleprepend` / `ruleappend` 是 SubConverter-Extended 扩展语法；传统
`tindy2013/subconverter` 会忽略未知字段，因此可能继续生成配置，但不会导入
这些规则。第一版仅支持 `target=clash`，不支持 `clashr`、`list=true`、
`script=true` 或本地文件。

远程内容可以是包含完整目标策略的纯文本规则，也可以是根节点为 `rules:`
的 YAML；不支持 `payload:`，也不允许导入 `MATCH` / `FINAL`。多个来源及
来源内部规则均保持声明顺序，且不去重。拉取不使用本地规则缓存；网络或
HTTP 失败会跳过当前来源，内容解析或规则校验失败会以 HTTP 400 终止转换。
OpenClash 下载配置后仍可能通过 LuCI 覆写再次调整最终规则顺序。
