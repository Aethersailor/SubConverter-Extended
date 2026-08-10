# Outbound proxy policy

`proxy_config`, `proxy_ruleset`, and `proxy_subscription` use a deliberate
outbound policy rather than a truthy proxy string. Leading and trailing
whitespace is ignored.

| Value | Policy | Effect |
| --- | --- | --- |
| empty or `NONE` | Direct | Explicitly disables libcurl proxy environment variables for that request. `NONE` is case-insensitive. |
| `SYSTEM` | System | Resolves the platform system proxy. On Unix-like systems the first present value is `all_proxy`, `ALL_PROXY`, `http_proxy`, `HTTP_PROXY`, `https_proxy`, then `HTTPS_PROXY`; `NO_PROXY`/`no_proxy` is respected. Windows uses enabled Internet Settings proxy data. |
| `http://…`, `https://…`, `socks4://…`, `socks4a://…`, `socks5://…`, `socks5h://…` | Explicit | Uses that proxy for non-loopback destinations. `NO_PROXY` and `no_proxy` cannot change the policy. An initial syntactic loopback target is handled as described below. URI validation requires a supported scheme, host, and port. |
| `cors:https://…` | Cors | Compatibility HTTP CORS relay. It prefixes the requested URL and is transported directly; it is not a libcurl proxy. |

Malformed non-empty policies are rejected. They never become direct requests.

### Explicit proxy and loopback targets

For trusted configuration fetches and requests accepted by the `lan` security
profile, an explicit proxy bypasses only an initial target whose URL host is
syntactically `localhost`, a subdomain of `localhost`, an address in
`127.0.0.0/8`, or the IPv6 loopback address. Hostnames use the reserved
`.localhost` family. Numeric addresses use a single-address `/32` or `/128`
match, not a wildcard or private-network range.

This is a request-level routing decision rather than inherited `NO_PROXY`
state. A redirect from that loopback host to a remote host therefore resumes
using the explicit proxy. Conversely, a request whose initial host is remote
continues to use the proxy if it redirects to a loopback address. Arbitrary
hostnames are not resolved to decide whether to bypass, and RFC 1918,
carrier-grade NAT, and link-local ranges are not bypassed automatically.

Numeric single-address matching requires libcurl 7.86 or newer and is
available in the official Windows build. A custom build using an older libcurl
keeps numeric loopback targets on the proxy (fail closed); the `localhost`
family is still handled directly.

The `public` and `strict` profiles reject public-request loopback targets before
transport and never enable this bypass. `SYSTEM` normally inherits the platform
`NO_PROXY`/`no_proxy` behavior. When a public request resolves `SYSTEM` to a
proxy, bypass inheritance is disabled so a redirect cannot switch that request
to a direct loopback connection. `cors:` remains an HTTP relay rather than a
libcurl proxy.

## Which setting applies

- `proxy_config`: external configurations, remote base templates, in-template
  `fetch`, cron scripts, QuickJS `fetch` without `proxy`, GeoIP helper calls,
  and Gist/auxiliary API requests.
- `proxy_ruleset`: downloaded and converted rulesets.
- `proxy_subscription`: backend expansion/download of a subscription, such as
  `list=true` or a non-Clash output.

QuickJS `fetch({url})` inherits `proxy_config`. An own `proxy` property may
override it with `NONE`, `SYSTEM`, or an explicit URI. An empty own value is
Direct, not inherited.

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
