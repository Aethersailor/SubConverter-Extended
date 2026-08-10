# Outbound proxy policy

`proxy_config`, `proxy_ruleset`, and `proxy_subscription` use a deliberate
outbound policy rather than a truthy proxy string. Leading and trailing
whitespace is ignored.

| Value | Policy | Effect |
| --- | --- | --- |
| empty or `NONE` | Direct | Explicitly disables libcurl proxy environment variables for that request. `NONE` is case-insensitive. |
| `SYSTEM` | System | Resolves the platform system proxy. On Unix-like systems the first present value is `all_proxy`, `ALL_PROXY`, `http_proxy`, `HTTP_PROXY`, `https_proxy`, then `HTTPS_PROXY`; `NO_PROXY`/`no_proxy` is respected. Windows uses enabled Internet Settings proxy data. |
| `http://…`, `https://…`, `socks4://…`, `socks4a://…`, `socks5://…`, `socks5h://…` | Explicit | Uses that proxy unless the initial syntactic host matches `proxy_bypass`. `NO_PROXY` and `no_proxy` cannot change the policy. URI validation requires a supported scheme, host, and port. |
| `cors:https://…` | Cors | Compatibility HTTP CORS relay. It prefixes the requested URL and is transported directly; it is not a libcurl proxy. |

Malformed non-empty policies are rejected. They never become direct requests.

### Explicit proxy bypass

`proxy_bypass` is one comma-separated setting shared by `proxy_config`,
`proxy_ruleset`, and `proxy_subscription` when those settings contain an
explicit proxy URI. It does not replace the existing preference file and does
not alter `SYSTEM`, `NONE`, or `cors:` routing.

`LOOPBACK` is always retained. When `proxy_bypass` is absent, the default is
`PRIVATE`, which includes both loopback and ordinary private networks. Existing
INI, YAML, and TOML preference files therefore continue to start without adding
the field. Other presets are additive:

| Rule | Direct initial targets |
| --- | --- |
| `LOOPBACK` | `localhost`, the `.localhost` family, `127.0.0.0/8`, and `::1/128`. |
| `PRIVATE` | `LOOPBACK` plus RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and IPv6 ULA (`fc00::/7`). |
| `LAN` | `PRIVATE` plus IPv4 link-local (`169.254.0.0/16`), IPv6 link-local (`fe80::/10`), `.local`, and `.home.arpa`. |
| `CGNAT` | Adds the shared address range `100.64.0.0/10`; normally used as `LAN,CGNAT`. |
| `CIDR:address/prefix` | Adds one explicit IPv4 or IPv6 range. `/0` is rejected. |
| `DOMAIN:name` | Adds the named domain and its label-boundary subdomains. Use ASCII or Punycode; wildcards are rejected. |

For example:

```ini
; Upgrade-compatible default: LOOPBACK + RFC 1918 + IPv6 ULA
proxy_bypass=PRIVATE

; Explicitly keep only the narrower loopback behavior
proxy_bypass=LOOPBACK

; Broad coverage for common home and enterprise intranets
proxy_bypass=LAN,CGNAT

; Add deployment-specific routed networks and internal DNS trees
proxy_bypass=LAN,CGNAT,CIDR:10.200.0.0/16,CIDR:fd42:1234::/48,DOMAIN:corp.example
```

At most 64 custom `CIDR:` and `DOMAIN:` rules may be configured. Unknown,
empty, wildcard, malformed, and over-broad `/0` rules make configuration
loading fail instead of silently changing routing.

The presets deliberately do not include every IANA special-purpose range.
In particular, benchmark/fake-IP (`198.18.0.0/15`), documentation, multicast,
reserved, transition, and NAT64 ranges are not assumed to be an intranet.
Deployments that route other address space internally must list that space with
`CIDR:` or `DOMAIN:`. Hostnames are matched syntactically; the application does
not resolve an arbitrary name and then decide to bypass from its resolved IP.

This is a request-level routing decision rather than inherited `NO_PROXY`
state. A redirect from a bypassed initial host to a host outside its authorized
domain subtree therefore resumes using the explicit proxy. Conversely, a
request whose initial host does not match continues to use the proxy if it
redirects into a bypass range. Numeric addresses use a single-address `/32` or
`/128` transport pattern after the application has matched the configured
range; the full private range is never handed to libcurl for redirects.

Numeric single-address matching requires libcurl 7.86 or newer and is
available in the official Windows build. A custom build using an older libcurl
keeps numeric bypass targets on the proxy (fail closed); matching hostname
rules remain available.

The `public` and `strict` profiles reject public-request loopback targets before
transport and ignore `proxy_bypass` for all public requests. Trusted
configuration fetches may use the configured bypass under every profile;
requests accepted by the `lan` profile may also use it. Enabling `LAN` or custom
rules therefore grants those accepted requests direct access to the listed
targets and should be treated as an explicit trust decision. `SYSTEM` normally
inherits the platform `NO_PROXY`/`no_proxy` behavior. When a public request
resolves `SYSTEM` to a proxy, bypass inheritance is disabled so a redirect
cannot switch that request to a direct loopback connection. `cors:` remains an
HTTP relay rather than a libcurl proxy.

## Which setting applies

- `proxy_config`: external configurations, remote base templates, in-template
  `fetch`, cron scripts, QuickJS `fetch` without `proxy`, GeoIP helper calls,
  and Gist/auxiliary API requests.
- `proxy_ruleset`: downloaded and converted rulesets.
- `proxy_subscription`: backend expansion/download of a subscription, such as
  `list=true` or a non-Clash output.

QuickJS `fetch({url})` inherits `proxy_config`. An own `proxy` property may
override it with `NONE`, `SYSTEM`, or an explicit URI. An own explicit URI uses
the same `proxy_bypass`; an empty own value is Direct, not inherited.

For a default Clash Proxy-Provider request, SubConverter-Extended emits a
provider URL and does **not** download the subscription itself. Mihomo later
downloads it, so this process's `proxy_subscription` cannot govern that
client-side refresh. This is intentional.

## DNS, security, and deployment boundaries

`socks5://` asks libcurl to resolve a hostname locally before connecting to the
SOCKS server. `socks5h://` sends the hostname to the SOCKS server for remote
resolution. Remote resolution does not weaken the public-request SSRF checks:
literal/private and locally resolved private destinations remain denied under
the public profile. A proxy-resolved address that cannot be observed locally is
an unavoidable limit; do not rely on `socks5h` alone to enforce an SSRF allow
list.

Application policy controls this program's libcurl traffic. It cannot prove
that other processes, DNS resolvers, client-side Proxy-Provider refreshes, or
the host network will never use a native route. Deployments that must prohibit
all native IP egress need firewall/routing/namespace egress controls in
addition to this setting.

Remote TLS certificate and hostname verification are enabled by default. The
`advanced.allow_insecure_tls` migration escape hatch is off by default and
should be removed again after a controlled compatibility investigation; it is
not a retry or fallback mechanism.

Official Windows portable builds use the Windows native certificate stores for
both destination HTTPS and HTTPS-proxy TLS verification. Private or enterprise
roots therefore belong in the appropriate Windows trust store; the archive
does not require an MSYS2 CA bundle or a launcher-specific environment
variable. This changes only the source of trust and does not disable
certificate or hostname verification.

For idempotent GET/HEAD transfers only, one 200 ms retry is made after a
recoverable DNS/connect/timeout/send/receive/partial-transfer error. It never
retries authentication failures, TLS verification failures, policy/security
rejections, malformed URLs, HTTP status responses, POST, or PATCH; a retry
therefore cannot turn an explicit-proxy failure into a direct request.
Redirects are limited to HTTP and HTTPS.

## Diagnostics and secrets

Verbose logs report `Direct`, `System`, `Explicit`, or `Cors`, a redacted
scheme/host/port, whether supported libcurl can confirm proxy use, and a broad
error category. `/sub?...&explain=true` exposes the same redacted policy
summary. Proxy user information, credentials, authorization headers, and
common token-like URL query values are redacted before logging.
