#!/usr/bin/env python3
"""Run HTTP smoke checks against a running SubConverter-Extended instance.

The script does not build the project. Point --base-url at a local or remote
test server and it will verify health, normal conversion, and explain output.
Snapshots are optional; pass --snapshot-dir and --update-snapshots to create or
refresh them.
"""

from __future__ import annotations

import argparse
import base64
import difflib
import hashlib
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


SAMPLE_SS_LINK = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:8388#Smoke"
SECONDARY_SS_LINK = (
    "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@second.example.com:8389#Second"
)
MIERU_OFFICIAL_SIMPLE_URI = (
    "mierus://baozi:manlianpenfen@1.2.3.4?"
    "handshake-mode=HANDSHAKE_NO_WAIT&mtu=1400&"
    "multiplexing=MULTIPLEXING_HIGH&port=6666&port=9998-9999&"
    "port=6489&port=4896&profile=default&protocol=TCP&protocol=TCP&"
    "protocol=UDP&protocol=UDP&"
    "traffic-pattern=CCoQARoECAEQCiIYCAMQASoIMDAwMTAyMDMqCDA0MDUwNjA3"
)
MIERU_STANDARD_PROTOBUF_URI = (
    "mieru://CpsBCgdkZWZhdWx0ElgKBWJhb3ppEg1tYW5saWFucGVuZmVu"
    "GkA0MGFiYWM0MGY1OWRhNTVkYWQ2YTk5ODMxYTUxMTY1MjJmYmM4MGUzODVi"
    "YjFhYjE0ZGM1MmRiMzY4ZjczOGE0Gi8SCWxvY2FsaG9zdBoFCIo0EAIaDRAC"
    "Ggk5OTk5LTk5OTkaBQjZMhABGgUIoCYQASD4CioCCAQSB2RlZmF1bHQYnUYg"
    "uAgwBTgA"
)
DIRECT_SS_LINK = (
    "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@direct.example.com:8389#DirectSmoke"
)
V2RAY_CLIENT_VMESS_LINK = "vmess://" + base64.urlsafe_b64encode(
    json.dumps(
        {
            "v": "2",
            "ps": "V2RayClientSmoke",
            "add": "v2ray-client-smoke.example.test",
            "port": "443",
            "id": "33333333-3333-4333-8333-333333333333",
            "aid": "0",
            "scy": "auto",
            "net": "grpc",
            "type": "multi",
            "path": "smoke-service",
            "host": "",
            "tls": "tls",
            "sni": "v2ray-client-sni.example.test",
        },
        separators=(",", ":"),
    ).encode()
).decode().rstrip("=")
V2RAY_CLIENT_HY2_LINK = (
    "hysteria2://smoke-password@hy2-v2ray-client.example.test:8443"
    "?obfs=salamander&obfs-password=smoke-obfs"
    "&sni=hy2-v2ray-client.example.test#V2RayClientHy2"
)
V2RAYN_REALM_LINK = (
    "hysteria2+realm://smoke-token@realm-v2rayn.example.test:8443/smoke-id"
    "?auth=smoke-realm-password&stun=stun.example.test%3A3478"
    "&sni=realm-v2rayn.example.test&obfs=gecko"
    "&obfs-password=smoke-realm-obfs#V2RayNRealm"
)
V2RAYN_ANYTLS_LINK = (
    "anytls://smoke-password@anytls-v2rayn.example.test:443"
    "?sni=anytls-v2rayn.example.test#V2RayNAnyTLS"
)
SHADOWROCKET_HYSTERIA_LINK = (
    "hysteria://hy1-shadowrocket.example.test:36712"
    "?protocol=udp&auth=smoke-password&peer=hy1-shadowrocket.example.test"
    "&insecure=1&upmbps=100&downmbps=200&alpn=h3"
    "&obfs=xplus&obfsParam=smoke-obfs#ShadowrocketHy1"
)
SHADOWROCKET_ANYTLS_LINK = (
    "anytls://smoke-password@anytls-shadowrocket.example.test:443/"
    "?sni=anytls-shadowrocket.example.test#ShadowrocketAnyTLS"
)
SHADOWROCKET_LOSSY_ANYTLS_LINK = (
    "anytls://smoke-password@anytls-shadowrocket.example.test:443/"
    "?sni=anytls-shadowrocket.example.test&fp=chrome#LossyAnyTLS"
)
STASH_MIERU_LINK = (
    "mierus://stash-user:stash-password@mieru-stash.example.test?"
    "profile=default&port=9998-9999&protocol=TCP"
)
STASH_HYSTERIA2_LINK = (
    "hysteria2://stash-password@hy2-stash.example.test:8443/"
    "?sni=hy2-stash.example.test#StashHy2"
)
SHADOWROCKET_STAGE_ONE_SMOKE_SHA256 = (
    "7f12b33d4d71596e81abd0e9f79b1f95b59d964bbd8f80fe33b840f60f62ecc6"
)
V2RAYN_NAIVE_LINK = (
    "naive+https://smoke-user:smoke-password@naive-v2rayn.example.test:443"
    "?sni=naive-v2rayn.example.test#V2RayNNaive"
)
MIHOMO_ONLY_ROUTE_URI = (
    "socks5://user:pass@socks.example.test:1080#RouteProbe"
)
LEGACY_ONLY_ROUTE_URI = (
    "trojan-go://password@legacy.example.test:443"
    "?sni=example.test#LegacyRouteProbe"
)
VERIFIED_CLASH_AUTO_USER_AGENTS = (
    "clash.meta/1.19.29",  # Mihomo
    "clash.meta/mihomo",  # GUI.for.Clash
    "clash.meta/alpha-e89af72",  # Sparkle fallback
    "clash.meta/1.19.5",  # ClashBox default
    "clash-verge/v2.5.3",  # Clash Verge Rev
    "clash-verge/v2.4.5",  # OpenClash default
    "mihomo.party/v2.0.0 (clash.meta)",  # Clash/Mihomo Party
    "FlClash/v0.8.94 clash-verge Platform/windows",
    "clash-nyanpasu/v2.0.0",
    "ClashMetaForAndroid/2.11.32.Meta",
    "ClashMeta/1.19.29; mihomo/1.19.29",  # ClashMi default
    "ClashForAndroid/2.5.12",
    "ClashforWindows/0.20.39",
    (
        "ClashX/1.91.1 (com.west2online.ClashX; build:1.91.1; "
        "macOS 12.4.0) Alamofire/5.5.0"
    ),
)
CLASH_AUTO_COMPATIBILITY_ALIASES = (
    "mihomo/1.19.29",
    "clash-party/v1.7.5",
    "ClashMi/1.0.6 platform/android ClashMeta/1.19.29; mihomo/1.19.29",
    "ClashForWindows/0.20.39",
    "ClashX Meta/1.4.1",
    "OpenClash/0.46.075",
)
CLASH_AUTO_USER_AGENTS = (
    VERIFIED_CLASH_AUTO_USER_AGENTS + CLASH_AUTO_COMPATIBILITY_ALIASES
)
VERIFIED_CLASHR_AUTO_USER_AGENTS = (
    "ClashForAndroid/1.3.4R",
    "ClashForAndroid/1.3.3R2",
    "ClashForAndroid/1.1.10R3",
)
CLASHR_AUTO_COMPATIBILITY_ALIASES = (
    "ClashForAndroid/2.5.12R",
    "ClashR/1.0",
    "clashr/1.0",
)
CLASHR_AUTO_USER_AGENTS = (
    VERIFIED_CLASHR_AUTO_USER_AGENTS + CLASHR_AUTO_COMPATIBILITY_ALIASES
)
DISABLE_RULEGEN_CONFIG = "data:,enable_rule_generator=false"
PROVIDER_FILTER_CONFIG = "data:text/plain;base64," + base64.urlsafe_b64encode(
    b"\n".join(
        (
            b"enable_rule_generator=false",
            b"include_remarks=HK",
            b"include_remarks=JP",
            b"exclude_remarks=Expired",
            b"exclude_remarks=Traffic",
        )
    )
).decode("ascii")
PROVIDER_GROUP_TAG_CONFIG = "data:text/plain;base64," + base64.urlsafe_b64encode(
    b"\n".join(
        (
            b"enable_rule_generator=false",
            b"custom_proxy_group=Plain`url-test`Smoke`"
            b"https://www.gstatic.com/generate_204`1800,5,100",
            b"custom_proxy_group=OnlyPublic`url-test`!!GROUP=public!!Smoke`"
            b"https://www.gstatic.com/generate_204`1800,5,100",
            b"custom_proxy_group=ExcludePrivate`url-test`"
            b"!!GROUP=^(?!.*(myvps|home)).*$!!Smoke`"
            b"https://www.gstatic.com/generate_204`1800,5,100",
            b"custom_proxy_group=PublicAll`select`!!GROUP=public",
            b"custom_proxy_group=ByGroupId`select`!!GROUPID=2!!Smoke",
            b"custom_proxy_group=ExplicitProvider`select`!!PROVIDER=Public",
        )
    )
).decode("ascii")
LOCAL_GROUP_MATCHER_CONFIG = "data:text/plain;base64," + base64.urlsafe_b64encode(
    b"\n".join(
        (
            b"enable_rule_generator=false",
            b"custom_proxy_group=Plain`select`Smoke",
            b"custom_proxy_group=ByGroup`select`!!GROUP=public!!Smoke",
            b"custom_proxy_group=ByGroupCapture`select`!!GROUP=pub(lic)!!Sm(oke)",
            b"custom_proxy_group=BySecondaryGroup`select`!!GROUP=secondary!!Second",
            b"custom_proxy_group=ByPrimaryGroupId`select`!!GROUPID=0!!Smoke",
            b"custom_proxy_group=ByGroupId`select`!!GROUPID=1!!Second",
            b"custom_proxy_group=ByInsert`select`!!INSERT=-1!!Second",
            b"custom_proxy_group=ByType`select`!!TYPE=SS",
            b"custom_proxy_group=ByPortExact`select`!!PORT=8388",
            b"custom_proxy_group=ByPortRange`select`!!PORT=8380-8390",
            b"custom_proxy_group=ByPortLess`select`!!PORT=9000-",
            b"custom_proxy_group=ByPortMore`select`!!PORT=8000+",
            b"custom_proxy_group=ByPortNot`select`!!PORT=!8389",
            b"custom_proxy_group=LegacyNotRange`select`!!PORT=8000-9000,!7000-7100",
            b"custom_proxy_group=LegacyNegationOrder`select`!!PORT=!8388,!9999",
            b"custom_proxy_group=ByServer`select`!!SERVER=^example\\.com$",
            b"custom_proxy_group=MalformedGroup`select`!!GROUP=",
            b"custom_proxy_group=NoGroup`select`!!GROUP=missing!!Smoke",
            b"custom_proxy_group=NoPort`select`!!PORT=!8388!!Smoke",
            b"custom_proxy_group=LegacyNotRangeExcluded`select`!!PORT=!8000-9000",
            b"custom_proxy_group=NoInsertPositive`select`!!INSERT=1!!Second",
            b"custom_proxy_group=NoTypePartial`select`!!TYPE=S",
            b"custom_proxy_group=InvalidPlain`select`[",
            b"custom_proxy_group=InvalidGroup`select`!!GROUP=[!!Smoke",
        )
    )
).decode("ascii")
SELECT_HEALTH_URL = "http://wifi.vivo.com.cn/generate_204"
SELECT_HEALTH_CONFIG = "data:text/plain;base64," + base64.urlsafe_b64encode(
    "\n".join(
        (
            "enable_rule_generator=false",
            "custom_proxy_group=DIRECT-HEALTH`select`[]DIRECT`"
            + SELECT_HEALTH_URL,
        )
    ).encode()
).decode("ascii")
QUANX_REMOTE_CONFIG = "data:text/plain;base64," + base64.urlsafe_b64encode(
    b"enable_rule_generator=false\ncustom_proxy_group=Remote`select`.*\n"
).decode("ascii")
STASH_RULE_PROVIDER_CONFIG = "data:text/plain;base64," + base64.urlsafe_b64encode(
    b"\n".join(
        (
            b"enable_rule_generator=true",
            b"overwrite_original_rules=true",
            b"custom_proxy_group=RuleGroup`select`.*",
            b"ruleset=RuleGroup,clash-domain:https://127.0.0.1:1/"
            b"stash-smoke-domain.mrs?token=stash-rule-smoke-secret,3600",
            b"ruleset=RuleGroup,[]GEOSITE,telegram",
        )
    )
).decode("ascii")
AGE_PUBLIC_KEY = (
    "age1xh86kh9v23vattr58yedspm3f57sxvnswu9krr6ns438amekx5gsd09uma"
)


def build_url(base_url: str, path: str, params: dict[str, str] | None = None) -> str:
    base = base_url.rstrip("/")
    query = urllib.parse.urlencode(params or {})
    return f"{base}{path}" + (f"?{query}" if query else "")


def surge_contains_fixture_proxy(config: str, name: str, host: str) -> bool:
    for line in config.splitlines():
        entry_name, separator, definition = line.partition("=")
        if not separator:
            continue
        fields = [field.strip() for field in definition.split(",")]
        if entry_name.strip() == name or (len(fields) > 1 and fields[1] == host):
            return True
    return False


def decode_v2ray_internal_subscription(content: str) -> list[tuple[str, dict]]:
    profiles: list[tuple[str, dict]] = []
    for line in content.splitlines():
        prefix = "v2rayn://"
        if not line.startswith(prefix) or "/" not in line[len(prefix) :]:
            raise AssertionError(f"invalid v2rayN internal link: {line!r}")
        scheme, payload = line[len(prefix) :].split("/", 1)
        payload += "=" * (-len(payload) % 4)
        profile = json.loads(base64.urlsafe_b64decode(payload))
        if profile.get("ConfigVersion") != 4:
            raise AssertionError(f"invalid v2rayN ProfileItem: {profile!r}")
        profiles.append((scheme, profile))
    return profiles


def fetch_response(
    base_url: str,
    path: str,
    params: dict[str, str] | None,
    timeout: int,
    headers: dict[str, str] | None = None,
) -> tuple[str, dict[str, str]]:
    url = build_url(base_url, path, params)
    request = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = response.status
            body = response.read().decode("utf-8", errors="replace")
            response_headers = {
                key.lower(): value for key, value in response.headers.items()
            }
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise AssertionError(f"{url} returned HTTP {exc.code}\n{body}") from exc
    except urllib.error.URLError as exc:
        raise AssertionError(f"{url} failed: {exc}") from exc

    if status < 200 or status >= 300:
        raise AssertionError(f"{url} returned HTTP {status}\n{body}")
    return body, response_headers


def fetch(
    base_url: str,
    path: str,
    params: dict[str, str] | None,
    timeout: int,
    headers: dict[str, str] | None = None,
) -> str:
    body, _ = fetch_response(base_url, path, params, timeout, headers)
    return body


def assert_rejected(
    base_url: str,
    path: str,
    params: dict[str, str],
    timeout: int,
    label: str,
    headers: dict[str, str] | None = None,
) -> None:
    try:
        fetch(base_url, path, params, timeout, headers)
    except AssertionError as exc:
        if "returned HTTP 400" not in str(exc):
            raise AssertionError(f"{label} failed unexpectedly: {exc}") from exc
        return
    raise AssertionError(f"{label} was unexpectedly accepted")


def provider_block_from_output(output: str, provider_name: str) -> str:
    marker = f"  {provider_name}:\n"
    start = output.find(marker)
    if start < 0:
        raise AssertionError(f"provider block is missing: {provider_name}")
    following = output[start + len(marker) :]
    next_provider = re.search(r"(?m)^  [^ ].*:\s*$", following)
    end = len(following) if next_provider is None else next_provider.start()
    return marker + following[:end]


def provider_interval_from_output(output: str, provider_name: str) -> int:
    block = provider_block_from_output(output, provider_name)
    interval = re.search(r"(?m)^    interval: ([0-9]+)\s*$", block)
    if interval is None:
        raise AssertionError(
            f"provider interval is missing or non-numeric: {provider_name}\n{block}"
        )
    return int(interval.group(1))


def provider_proxy_direct_from_output(output: str, provider_name: str) -> bool:
    block = provider_block_from_output(output, provider_name)
    return re.search(r"(?m)^    proxy: DIRECT\s*$", block) is not None


def proxy_group_block_from_output(output: str, group_name: str) -> str:
    marker = f"  - name: {group_name}\n"
    start = output.find(marker)
    if start < 0:
        raise AssertionError(f"proxy group block is missing: {group_name}")
    following = output[start + len(marker) :]
    next_group = re.search(r"(?m)^  - name: ", following)
    end = len(following) if next_group is None else next_group.start()
    return marker + following[:end]


def proxy_group_use_from_output(output: str, group_name: str) -> list[str]:
    block = proxy_group_block_from_output(output, group_name)
    use = re.search(r"(?m)^    use:\s*$", block)
    if use is None:
        return []
    following = block[use.end() :]
    return re.findall(r"(?m)^      - (.+?)\s*$", following)


def proxy_group_filter_from_output(output: str, group_name: str) -> str | None:
    block = proxy_group_block_from_output(output, group_name)
    match = re.search(r'(?m)^    filter: (?:"([^"]*)"|([^\r\n]+))\s*$', block)
    if match is None:
        return None
    return match.group(1) if match.group(1) is not None else match.group(2)


def assert_local_group_matcher_matrix(base_url: str, timeout: int) -> None:
    output = fetch(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": "|".join(
                (
                    "tag:public," + SAMPLE_SS_LINK,
                    "tag:secondary," + SECONDARY_SS_LINK,
                )
            ),
            "config": LOCAL_GROUP_MATCHER_CONFIG,
        },
        timeout,
    )
    expected_groups = {
        "Plain": ["Smoke"],
        "ByGroup": ["Smoke"],
        "ByGroupCapture": ["Smoke"],
        "BySecondaryGroup": ["Second"],
        "ByPrimaryGroupId": ["Smoke"],
        "ByGroupId": ["Second"],
        "ByInsert": ["Second"],
        "ByType": ["Smoke", "Second"],
        "ByPortExact": ["Smoke"],
        "ByPortRange": ["Smoke", "Second"],
        "ByPortLess": ["Smoke", "Second"],
        "ByPortMore": ["Smoke", "Second"],
        "ByPortNot": ["Smoke"],
        "LegacyNotRange": ["Smoke", "Second"],
        "LegacyNegationOrder": ["Smoke", "Second"],
        "ByServer": ["Smoke"],
        "MalformedGroup": ["Smoke", "Second"],
    }
    for group_name, expected_members in expected_groups.items():
        block = proxy_group_block_from_output(output, group_name)
        members = re.findall(r"(?m)^      - (.+?)\s*$", block)
        if members != expected_members:
            raise AssertionError(
                f"local matcher group {group_name} changed members: {members!r}; "
                f"expected {expected_members!r}\n{block}"
            )
    for group_name in (
        "NoGroup",
        "NoPort",
        "LegacyNotRangeExcluded",
        "NoInsertPositive",
        "NoTypePartial",
        "InvalidPlain",
        "InvalidGroup",
    ):
        block = proxy_group_block_from_output(output, group_name)
        members = re.findall(r"(?m)^      - (.+?)\s*$", block)
        if members != ["DIRECT"]:
            raise AssertionError(
                f"local matcher negative group {group_name} changed members: "
                f"{members!r}\n{block}"
            )


def assert_select_health_check(
    base_url: str, timeout: int, remote_subscription_url: str | None
) -> None:
    cases = [("direct", SAMPLE_SS_LINK, False)]
    if remote_subscription_url:
        cases.extend(
            (
                (
                    "provider",
                    f"provider:HealthOne,{remote_subscription_url}",
                    True,
                ),
                (
                    "providers",
                    "|".join(
                        (
                            f"provider:HealthOne,{remote_subscription_url}",
                            f"provider:HealthTwo,{remote_subscription_url}",
                        )
                    ),
                    True,
                ),
                (
                    "mixed",
                    "|".join(
                        (
                            SAMPLE_SS_LINK,
                            f"provider:HealthOne,{remote_subscription_url}",
                        )
                    ),
                    True,
                ),
            )
        )

    for label, source, expects_provider in cases:
        output = fetch(
            base_url,
            "/sub",
            {"target": "clash", "url": source, "config": SELECT_HEALTH_CONFIG},
            timeout,
        )
        block = proxy_group_block_from_output(output, "DIRECT-HEALTH")
        members = re.findall(r"(?m)^      - (.+?)\s*$", block)
        if members != ["DIRECT"]:
            raise AssertionError(
                f"select health {label} changed members: {members!r}\n{block}"
            )
        if (
            re.search(
                r'(?m)^    url: ["\']?'
                + re.escape(SELECT_HEALTH_URL)
                + r'["\']?\s*$',
                block,
            )
            is None
        ):
            raise AssertionError(
                f"select health {label} lost its health-check URL\n{block}"
            )
        if proxy_group_use_from_output(output, "DIRECT-HEALTH") or (
            proxy_group_filter_from_output(output, "DIRECT-HEALTH") is not None
        ):
            raise AssertionError(
                f"select health {label} added provider selection\n{block}"
            )
        if ("proxy-providers:" in output) is not expects_provider:
            raise AssertionError(
                f"select health {label} did not exercise the intended provider mode"
            )


def assert_snapshot(name: str, content: str, snapshot_dir: Path | None, update: bool) -> None:
    if snapshot_dir is None:
        return

    snapshot_dir.mkdir(parents=True, exist_ok=True)
    path = snapshot_dir / name
    normalized = content.replace("\r\n", "\n")
    if update or not path.exists():
        path.write_text(normalized, encoding="utf-8")
        return

    expected = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    if expected != normalized:
        diff = "\n".join(
            difflib.unified_diff(
                expected.splitlines(),
                normalized.splitlines(),
                fromfile=str(path),
                tofile=f"current:{name}",
                lineterm="",
            )
        )
        raise AssertionError(f"Snapshot mismatch for {name}\n{diff}")


def assert_parser_route_isolation(base_url: str, timeout: int) -> None:
    common = {
        "url": MIHOMO_ONLY_ROUTE_URI,
        "config": DISABLE_RULEGEN_CONFIG,
    }
    for target in ("clash", "clashr"):
        output = fetch(
            base_url,
            "/sub",
            {"target": target, "list": "true", **common},
            timeout,
        )
        if "RouteProbe" not in output:
            raise AssertionError(
                f"explicit {target} did not use the Mihomo-only parser"
            )

    auto_cases = tuple(
        (user_agent, "clash") for user_agent in CLASH_AUTO_USER_AGENTS
    )
    auto_cases += tuple(
        (user_agent, "clashr") for user_agent in CLASHR_AUTO_USER_AGENTS
    )
    for user_agent, resolved_target in auto_cases:
        report = json.loads(
            fetch(
                base_url,
                "/sub",
                {"target": "auto", "explain": "true", **common},
                timeout,
                {"User-Agent": user_agent},
            )
        )
        if (
            report.get("target") != resolved_target
            or report.get("nodes", {}).get("total", 0) < 1
        ):
            raise AssertionError(
                f"auto UA {user_agent!r} did not resolve to the Mihomo-only "
                f"{resolved_target} route"
            )

    assert_rejected(
        base_url,
        "/sub",
        {"target": "auto", **common},
        timeout,
        "browser UA must not be classified as Clash",
        {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
    )

    assert_rejected(
        base_url,
        "/sub",
        {"target": "surge", **common},
        timeout,
        "explicit Surge legacy-only parser route",
    )
    assert_rejected(
        base_url,
        "/sub",
        {"target": "auto", **common},
        timeout,
        "auto Loon legacy-only parser route",
        {"User-Agent": "Loon/3.2.1"},
    )

    legacy_output = json.loads(
        fetch(
            base_url,
            "/sub",
            {
                "target": "singbox",
                "url": LEGACY_ONLY_ROUTE_URI,
                "config": DISABLE_RULEGEN_CONFIG,
            },
            timeout,
        )
    )
    if not any(
        outbound.get("tag") == "LegacyRouteProbe"
        for outbound in legacy_output.get("outbounds", [])
    ):
        raise AssertionError("legacy-only direct URI was not expanded by sing-box")

    auto_legacy_output = json.loads(
        fetch(
            base_url,
            "/sub",
            {
                "target": "auto",
                "url": LEGACY_ONLY_ROUTE_URI,
                "config": DISABLE_RULEGEN_CONFIG,
                "explain": "true",
            },
            timeout,
            {"User-Agent": "Loon/3.2.1"},
        )
    )
    if (
        auto_legacy_output.get("target") != "loon"
        or auto_legacy_output.get("nodes", {}).get("total", 0) < 1
    ):
        raise AssertionError("auto Loon did not resolve to the legacy-only route")

    assert_rejected(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": LEGACY_ONLY_ROUTE_URI,
            "config": DISABLE_RULEGEN_CONFIG,
            "list": "true",
        },
        timeout,
        "Clash Mihomo-only route with a legacy-only URI",
    )


def assert_mieru_standard_mihomo_bridge(base_url: str, timeout: int) -> None:
    for target, headers in (
        ("clash", None),
        ("clashr", None),
        ("auto", {"User-Agent": "clash.meta/1.19.29"}),
        ("auto", {"User-Agent": "ClashForAndroid/1.3.3R2"}),
    ):
        converted = fetch(
            base_url,
            "/sub",
            {
                "target": target,
                "url": MIERU_STANDARD_PROTOBUF_URI,
                "list": "true",
            },
            timeout,
            headers,
        )
        if (
            converted.count("type: mieru") != 4
            or "server: localhost" not in converted
            or "port: 6666" not in converted
            or "port-range: 9999-9999" not in converted
            or "transport: TCP" not in converted
            or "transport: UDP" not in converted
            or "multiplexing: MULTIPLEXING_HIGH" not in converted
        ):
            raise AssertionError(
                "official standard Mieru URI did not stay on the Mihomo-only "
                f"route for target={target}: {converted!r}"
            )

    assert_rejected(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": "mieru://AQIDBA==",
            "list": "true",
        },
        timeout,
        "invalid standard Mieru protobuf",
    )
    assert_rejected(
        base_url,
        "/sub",
        {
            "target": "surge",
            "ver": "4",
            "url": MIERU_STANDARD_PROTOBUF_URI,
            "list": "true",
        },
        timeout,
        "standard Mieru URI on the Legacy-only Surge route",
    )

    legacy_report = json.loads(
        fetch(
            base_url,
            "/sub",
            {
                "target": "surge",
                "ver": "4",
                "url": MIERU_STANDARD_PROTOBUF_URI + "|" + SAMPLE_SS_LINK,
                "list": "true",
                "explain": "true",
            },
            timeout,
        )
    )
    if (
        legacy_report.get("nodes", {}).get("total") != 1
        or legacy_report.get("nodes", {}).get("generated") != 1
        or legacy_report.get("nodes", {}).get("unsupported") != 0
    ):
        raise AssertionError(
            "standard Mieru input leaked into the Legacy parser or affected an "
            f"independent SS node: {legacy_report!r}"
        )

    assert_rejected(
        base_url,
        "/sub",
        {
            "target": "loon",
            "url": MIERU_OFFICIAL_SIMPLE_URI,
            "list": "true",
        },
        timeout,
        "unified target-generation all-unsupported fail-close",
    )


def assert_netch_legacy_parser(base_url: str, timeout: int) -> None:
    def netch_link(node: dict[str, object]) -> str:
        payload = json.dumps(node, separators=(",", ":")).encode("utf-8")
        encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
        return "Netch://" + encoded

    def data_url(value: dict[str, object]) -> str:
        payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
        encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
        return "data:application/json;base64," + encoded

    socks = {
        "Type": "SOCKS",
        "Remark": "Netch Smoke SOCKS",
        "Hostname": "socks-netch-smoke.example.test",
        "Port": 1080,
        "Username": "smoke-user",
        "Password": "smoke-password",
        "Version": 5,
    }
    vless = {
        "Type": "VLESS",
        "Remark": "Netch Smoke VLESS",
        "Hostname": "vless-netch-smoke.example.test",
        "Port": 443,
        "UserID": "22222222-2222-2222-2222-222222222222",
        "EncryptMethod": "none",
        "TransferProtocol": "grpc",
        "PacketEncoding": "xudp",
        "FakeType": "multi",
        "Path": "smoke-service",
        "TLSSecureType": "tls",
        "ServerName": "vless-sni-smoke.example.test",
    }
    ssh = {
        "Type": "SSH",
        "Remark": "Netch Unsupported SSH",
        "Hostname": "ssh-netch-smoke.example.test",
        "Port": 22,
        "User": "root",
        "Password": "not-a-proxy-protocol",
    }

    direct = json.loads(
        fetch(
            base_url,
            "/sub",
            {
                "target": "singbox",
                "url": netch_link(socks),
                "config": DISABLE_RULEGEN_CONFIG,
                "list": "true",
            },
            timeout,
        )
    ).get("outbounds", [])
    if (
        len(direct) != 1
        or direct[0].get("type") != "socks"
        or direct[0].get("tag") != "Netch Smoke SOCKS"
        or direct[0].get("version") != "5"
    ):
        raise AssertionError(f"modern Netch share link drifted: {direct!r}")

    settings = json.loads(
        fetch(
            base_url,
            "/sub",
            {
                "target": "singbox",
                "url": data_url({"Server": [socks, vless, ssh]}),
                "config": DISABLE_RULEGEN_CONFIG,
                "list": "true",
            },
            timeout,
        )
    ).get("outbounds", [])
    by_tag = {outbound.get("tag"): outbound for outbound in settings}
    if set(by_tag) != {"Netch Smoke SOCKS", "Netch Smoke VLESS"}:
        raise AssertionError(f"modern Netch settings.json drifted: {settings!r}")
    vless_outbound = by_tag["Netch Smoke VLESS"]
    if (
        vless_outbound.get("packet_encoding") != "xudp"
        or vless_outbound.get("transport")
        != {"type": "grpc", "service_name": "smoke-service"}
        or vless_outbound.get("tls", {}).get("server_name")
        != "vless-sni-smoke.example.test"
    ):
        raise AssertionError(f"modern Netch VLESS fields drifted: {vless_outbound!r}")

    assert_rejected(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": netch_link(socks),
            "config": DISABLE_RULEGEN_CONFIG,
            "list": "true",
        },
        timeout,
        "Clash Mihomo-only route with a Netch share link",
    )


def run_checks(
    base_url: str,
    timeout: int,
    snapshot_dir: Path | None,
    update: bool,
    remote_subscription_url: str | None,
    mihomo_raw_subscription_url: str | None,
    mihomo_yaml_subscription_url: str | None,
    legacy_subscription_url: str | None,
    verify_non_clash: bool,
) -> None:
    health = fetch(base_url, "/healthz", None, timeout)
    if health.strip() != "ok":
        raise AssertionError(f"/healthz returned unexpected body: {health!r}")

    version_page, version_headers = fetch_response(
        base_url, "/version", None, timeout
    )
    if (
        "<!DOCTYPE html>" not in version_page
        or "SubConverter-Extended" not in version_page
    ):
        raise AssertionError("/version did not return the HTML version page")
    if not version_headers.get("content-type", "").lower().startswith("text/html"):
        raise AssertionError("/version HTML response has an unexpected content type")

    navigation_page, navigation_headers = fetch_response(
        base_url,
        "/version",
        None,
        timeout,
        {
            "Origin": "https://edgetunnel.example",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
        },
    )
    if "<!DOCTYPE html>" not in navigation_page:
        raise AssertionError("/version navigation request did not return HTML")
    if not navigation_headers.get("content-type", "").lower().startswith(
        "text/html"
    ):
        raise AssertionError("/version navigation response has an unexpected content type")

    probe_headers = {
        "Origin": "https://edgetunnel.example",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
    }
    version_probe, version_probe_headers = fetch_response(
        base_url, "/version", None, timeout, probe_headers
    )
    version_probe_line = version_probe.strip()
    if not re.fullmatch(
        r"SubConverter-Extended \S+ backend", version_probe_line
    ):
        raise AssertionError(
            f"/version probe returned an unexpected body: {version_probe!r}"
        )
    if "subconverter" not in version_probe_line.lower() or "<" in version_probe_line:
        raise AssertionError("/version probe is not compatible with backend detection")
    if not version_probe_headers.get("content-type", "").lower().startswith(
        "text/plain"
    ):
        raise AssertionError("/version probe response has an unexpected content type")
    if version_probe_headers.get("access-control-allow-origin") != "*":
        raise AssertionError("/version probe response is missing the CORS header")
    if "no-store" not in version_probe_headers.get("cache-control", "").lower():
        raise AssertionError("/version probe response is missing no-store caching")
    vary = version_probe_headers.get("vary", "").lower()
    for header in ("sec-fetch-mode", "sec-fetch-dest", "origin"):
        if header not in vary:
            raise AssertionError(f"/version probe Vary header is missing {header}")

    legacy_probe, _ = fetch_response(
        base_url,
        "/version",
        None,
        timeout,
        {"Origin": "https://edgetunnel.example"},
    )
    if legacy_probe != version_probe:
        raise AssertionError("/version legacy browser probe response is inconsistent")

    inspect_page = fetch(base_url, "/inspect", None, timeout)
    if (
        "Request Inspector" not in inspect_page
        or "request-input" not in inspect_page
        or "request-preview" not in inspect_page
        or "parameter-section" not in inspect_page
    ):
        raise AssertionError("/inspect did not return the inspector page")

    common_params = {
        "target": "clash",
        "url": SAMPLE_SS_LINK,
        "config": DISABLE_RULEGEN_CONFIG,
    }

    assert_local_group_matcher_matrix(base_url, timeout)
    assert_select_health_check(base_url, timeout, remote_subscription_url)

    if verify_non_clash:
        assert_parser_route_isolation(base_url, timeout)
        assert_mieru_standard_mihomo_bridge(base_url, timeout)
        assert_netch_legacy_parser(base_url, timeout)

        desktop_profiles = decode_v2ray_internal_subscription(
            fetch(
                base_url,
                "/sub",
                {
                    "target": "v2rayn",
                    "url": "|".join(
                        (
                            V2RAY_CLIENT_VMESS_LINK,
                            V2RAYN_ANYTLS_LINK,
                            V2RAYN_NAIVE_LINK,
                            V2RAYN_REALM_LINK,
                        )
                    ),
                    "config": DISABLE_RULEGEN_CONFIG,
                    "list": "true",
                },
                timeout,
            )
        )
        if [item[1].get("ConfigType") for item in desktop_profiles] != [
            1,
            11,
            12,
            7,
        ]:
            raise AssertionError(
                f"v2rayN deployed protocol matrix drifted: {desktop_profiles!r}"
            )
        if any(
            item[1].get("CoreType") != 24 for item in desktop_profiles[1:3]
        ):
            raise AssertionError(
                f"v2rayN sing-box-only core mapping drifted: {desktop_profiles!r}"
            )
        realm_extra = desktop_profiles[3][1].get("ProtoExtraObj", {})
        if (
            desktop_profiles[3][1].get("CoreType") != 24
            or not realm_extra.get("Hy2RealmUrl", "").startswith("realm://")
            or realm_extra.get("GeckoMinPacketSize") != "512"
            or realm_extra.get("GeckoMaxPacketSize") != "1200"
        ):
            raise AssertionError(
                f"v2rayN deployed Realm/Gecko mapping drifted: {desktop_profiles!r}"
            )

        android_profiles = decode_v2ray_internal_subscription(
            fetch(
                base_url,
                "/sub",
                {
                    "target": "v2rayng",
                    "url": f"{V2RAY_CLIENT_VMESS_LINK}|{V2RAY_CLIENT_HY2_LINK}",
                    "config": DISABLE_RULEGEN_CONFIG,
                    "list": "true",
                },
                timeout,
            )
        )
        if [item[1].get("ConfigType") for item in android_profiles] != [1, 7]:
            raise AssertionError(
                f"v2rayNG deployed protocol matrix drifted: {android_profiles!r}"
            )
        auto_android = decode_v2ray_internal_subscription(
            fetch(
                base_url,
                "/sub",
                {
                    "target": "auto",
                    "url": V2RAY_CLIENT_VMESS_LINK,
                    "config": DISABLE_RULEGEN_CONFIG,
                    "list": "true",
                },
                timeout,
                {"User-Agent": "v2rayNG/1.10.29"},
            )
        )
        if len(auto_android) != 1 or auto_android[0][1].get("ConfigType") != 1:
            raise AssertionError(
                f"v2rayNG deployed auto-target drifted: {auto_android!r}"
            )
        assert_rejected(
            base_url,
            "/sub",
            {
                "target": "v2rayng",
                "url": V2RAYN_ANYTLS_LINK,
                "config": DISABLE_RULEGEN_CONFIG,
                "list": "true",
            },
            timeout,
            "v2rayNG desktop-only AnyTLS profile",
        )

        legacy_v2ray = fetch(
            base_url,
            "/sub",
            {
                "target": "v2ray",
                "url": V2RAY_CLIENT_VMESS_LINK,
                "config": DISABLE_RULEGEN_CONFIG,
                "list": "true",
            },
            timeout,
        )
        if not legacy_v2ray.startswith("vmess://") or "v2rayn://" in legacy_v2ray:
            raise AssertionError("historical target=v2ray output contract changed")

        shadowrocket_params = {
            "target": "shadowrocket",
            "url": "|".join(
                (
                    SAMPLE_SS_LINK,
                    V2RAY_CLIENT_VMESS_LINK,
                    V2RAY_CLIENT_HY2_LINK,
                    SHADOWROCKET_HYSTERIA_LINK,
                    SHADOWROCKET_ANYTLS_LINK,
                    MIERU_OFFICIAL_SIMPLE_URI,
                )
            ),
            "config": DISABLE_RULEGEN_CONFIG,
            "list": "true",
        }
        shadowrocket = fetch(
            base_url,
            "/sub",
            shadowrocket_params,
            timeout,
        )
        if [line.split("://", 1)[0] for line in shadowrocket.splitlines()] != [
            "ss",
            "vmess",
            "hysteria2",
            "hysteria",
            "anytls",
            "mierus",
        ]:
            raise AssertionError(
                f"Shadowrocket deployed protocol matrix drifted: {shadowrocket!r}"
            )
        encoded_shadowrocket = fetch(
            base_url,
            "/sub",
            {**shadowrocket_params, "list": "false"},
            timeout,
        )
        try:
            decoded_shadowrocket = base64.b64decode(
                encoded_shadowrocket, validate=True
            ).decode()
        except (ValueError, UnicodeDecodeError) as error:
            raise AssertionError(
                "Shadowrocket deployed default output is not strict Base64"
            ) from error
        if decoded_shadowrocket != shadowrocket:
            raise AssertionError(
                "Shadowrocket deployed raw and Base64 subscriptions diverged"
            )
        shadowrocket_report = json.loads(
            fetch(
                base_url,
                "/sub",
                {**shadowrocket_params, "explain": "true"},
                timeout,
            )
        )
        shadowrocket_nodes = shadowrocket_report.get("nodes", {})
        if (
            shadowrocket_report.get("target") != "shadowrocket"
            or shadowrocket_nodes.get("total") != 9
            or shadowrocket_nodes.get("generated") != 9
            or shadowrocket_nodes.get("unsupported") != 0
        ):
            raise AssertionError(
                "Shadowrocket deployed generation diagnostics drifted: "
                f"{shadowrocket_report!r}"
            )
        mixed = fetch(
            base_url,
            "/sub",
            {**shadowrocket_params, "target": "mixed"},
            timeout,
        )
        expected_mixed = "\n".join(shadowrocket.splitlines()[:3]) + "\n"
        if (
            mixed != expected_mixed
            or hashlib.sha256(mixed.encode()).hexdigest()
            != SHADOWROCKET_STAGE_ONE_SMOKE_SHA256
        ):
            raise AssertionError(
                "target=shadowrocket changed the historical mixed output contract: "
                f"{mixed!r} != {expected_mixed!r}"
            )
        for isolated_target in ("mixed", "v2ray"):
            assert_rejected(
                base_url,
                "/sub",
                {
                    "target": isolated_target,
                    "url": "|".join(
                        (
                            SHADOWROCKET_HYSTERIA_LINK,
                            SHADOWROCKET_ANYTLS_LINK,
                            MIERU_OFFICIAL_SIMPLE_URI,
                        )
                    ),
                    "config": DISABLE_RULEGEN_CONFIG,
                    "list": "true",
                },
                timeout,
                f"Shadowrocket-only protocols on target={isolated_target}",
            )
        auto_shadowrocket, auto_shadowrocket_headers = fetch_response(
            base_url,
            "/sub",
            {**shadowrocket_params, "target": "auto"},
            timeout,
            {"User-Agent": "Shadowrocket/2.2.60"},
        )
        if auto_shadowrocket != shadowrocket:
            raise AssertionError(
                "Shadowrocket deployed auto-target did not select its dedicated path"
            )
        if "user-agent" not in {
            value.strip().lower()
            for value in auto_shadowrocket_headers.get("vary", "").split(",")
            if value.strip()
        }:
            raise AssertionError(
                "Shadowrocket deployed auto-target is missing Vary: User-Agent"
            )
        mieru_lines = [
            line for line in shadowrocket.splitlines() if line.startswith("mierus://")
        ]
        if len(mieru_lines) != 1:
            raise AssertionError(
                f"Shadowrocket did not aggregate Mieru bindings: {shadowrocket!r}"
            )
        mieru_parts = urllib.parse.urlsplit(mieru_lines[0])
        mieru_query = urllib.parse.parse_qs(
            mieru_parts.query, keep_blank_values=True
        )
        if (
            mieru_query.get("profile") != ["default"]
            or mieru_query.get("port")
            != ["6666", "9998-9999", "6489", "4896"]
            or mieru_query.get("protocol") != ["TCP", "TCP", "UDP", "UDP"]
            or mieru_query.get("traffic-pattern")
            != ["CCoQARoECAEQCiIYCAMQASoIMDAwMTAyMDMqCDA0MDUwNjA3"]
        ):
            raise AssertionError(
                f"Shadowrocket deployed Mieru link drifted: {mieru_lines[0]!r}"
            )
        assert_rejected(
            base_url,
            "/sub",
            {
                "target": "shadowrocket",
                "url": MIERU_STANDARD_PROTOBUF_URI,
                "config": DISABLE_RULEGEN_CONFIG,
                "list": "true",
            },
            timeout,
            "Shadowrocket protobuf Mieru link on Legacy route",
        )
        assert_rejected(
            base_url,
            "/sub",
            {
                "target": "shadowrocket",
                "url": SHADOWROCKET_LOSSY_ANYTLS_LINK,
                "config": DISABLE_RULEGEN_CONFIG,
                "list": "true",
            },
            timeout,
            "Shadowrocket non-portable AnyTLS link",
        )

    direct_config = fetch(base_url, "/sub", common_params, timeout)
    if "Smoke" not in direct_config or "proxies:" not in direct_config:
        raise AssertionError("direct Clash conversion did not include expected node output")
    assert_snapshot("direct-clash.yaml", direct_config, snapshot_dir, update)

    auto_config, auto_headers = fetch_response(
        base_url,
        "/sub",
        {**common_params, "target": "auto"},
        timeout,
        {"User-Agent": "clash.meta/1.19.29"},
    )
    if "Smoke" not in auto_config or "proxies:" not in auto_config:
        raise AssertionError("auto Clash conversion did not select Mihomo output")
    auto_vary = {
        value.strip().lower()
        for value in auto_headers.get("vary", "").split(",")
        if value.strip()
    }
    if "user-agent" not in auto_vary:
        raise AssertionError("auto Clash response is missing Vary: User-Agent")

    _, plaintext_headers = fetch_response(
        base_url, "/sub", common_params, timeout
    )
    plaintext_vary = {
        value.strip().lower()
        for value in plaintext_headers.get("vary", "").split(",")
        if value.strip()
    }
    for expected in ("x-age-public-key", "user-agent"):
        if expected not in plaintext_vary:
            raise AssertionError(
                f"plaintext /sub response is missing Vary: {expected}"
            )

    age_config, age_headers = fetch_response(
        base_url,
        "/sub",
        common_params,
        timeout,
        {"X-Age-Public-Key": AGE_PUBLIC_KEY},
    )
    if not age_config.startswith("-----BEGIN AGE ENCRYPTED FILE-----"):
        raise AssertionError("Age response is not official ASCII armor")
    if age_headers.get("x-sce-age") != "encrypted":
        raise AssertionError("Age response is missing its encrypted diagnostic header")
    if len(age_headers.get("x-sce-age-recipient", "")) != 64:
        raise AssertionError("Age response is missing its recipient fingerprint")
    if "no-store" not in age_headers.get("cache-control", "").lower():
        raise AssertionError("Age response is not marked no-store")
    age_vary = {
        value.strip().lower()
        for value in age_headers.get("vary", "").split(",")
        if value.strip()
    }
    for expected in ("x-age-public-key", "user-agent"):
        if expected not in age_vary:
            raise AssertionError(f"Age response is missing Vary: {expected}")

    plaintext_after_age = fetch(base_url, "/sub", common_params, timeout)
    if plaintext_after_age.startswith("-----BEGIN AGE ENCRYPTED FILE-----"):
        raise AssertionError("Age response leaked into the plaintext cache variant")
    if plaintext_after_age != direct_config:
        raise AssertionError("plaintext response changed after an Age request")

    assert_rejected(
        base_url,
        "/sub",
        common_params,
        timeout,
        "invalid Age key",
        {"X-Age-Public-Key": "not-an-age-key"},
    )
    assert_rejected(
        base_url,
        "/sub",
        {**common_params, "target": "clashr"},
        timeout,
        "Age encryption for non-Clash target",
        {"X-Age-Public-Key": AGE_PUBLIC_KEY},
    )

    direct_explain = fetch(
        base_url,
        "/sub",
        {**common_params, "explain": "true"},
        timeout,
    )
    direct_report = json.loads(direct_explain)
    if direct_report.get("target") != "clash":
        raise AssertionError(f"unexpected explain target: {direct_report.get('target')!r}")
    if direct_report.get("nodes", {}).get("total", 0) < 1:
        raise AssertionError("direct explain report did not count the parsed node")
    direct_params = direct_report.get("parameters", {})
    direct_recognized = {
        item.get("name"): item for item in direct_params.get("recognized", [])
    }
    if "target" not in direct_recognized or "url" not in direct_recognized:
        raise AssertionError("direct explain report did not include recognized request parameters")
    if "effective_config" not in direct_report:
        raise AssertionError("direct explain report did not include effective config diagnostics")
    assert_snapshot("direct-explain.json", direct_explain, snapshot_dir, update)

    age_explain, age_explain_headers = fetch_response(
        base_url,
        "/sub",
        {**common_params, "explain": "true"},
        timeout,
        {"X-Age-Public-Key": AGE_PUBLIC_KEY},
    )
    json.loads(age_explain)
    if age_explain_headers.get("x-sce-age") != "diagnostic-not-encrypted":
        raise AssertionError("Age explain response did not remain diagnostic JSON")

    provider_explain = fetch(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": "https://example.com/sub",
            "config": PROVIDER_FILTER_CONFIG,
            "explain": "true",
        },
        timeout,
    )
    provider_report = json.loads(provider_explain)
    if not provider_report.get("mode", {}).get("proxy_provider"):
        raise AssertionError("provider explain report did not enter proxy-provider mode")
    if provider_report.get("output", {}).get("provider_count") != 1:
        raise AssertionError("provider explain report did not count one provider")
    provider = provider_report.get("providers", [{}])[0]
    if (
        provider.get("filter") != ""
        or provider.get("exclude_filter") != ""
        or provider.get("filter_present") is not True
        or provider.get("exclude_filter_present") is not True
    ):
        raise AssertionError(
            "provider explain did not report configured filters without exposing them"
        )
    provider_params = provider_report.get("parameters", {})
    provider_recognized = {
        item.get("name"): item for item in provider_params.get("recognized", [])
    }
    if provider_recognized.get("config", {}).get("status") not in {"applied", "ignored"}:
        raise AssertionError("provider explain report did not diagnose the config parameter")
    assert_snapshot("provider-explain.json", provider_explain, snapshot_dir, update)

    if remote_subscription_url:
        dead_quanx_source = (
            "https://127.0.0.1:1/quanx-must-not-fetch"
            "?token=quanx-smoke-source-secret"
        )
        quanx_output, quanx_headers = fetch_response(
            base_url,
            "/sub",
            {
                "target": "quanx",
                "url": f"provider:QXSmoke,interval:0,{dead_quanx_source}",
                "config": QUANX_REMOTE_CONFIG,
            },
            timeout,
        )
        for expected in (
            "[server_remote]",
            dead_quanx_source,
            "tag=QXSmoke",
            "update-interval=-1",
            "enabled=true",
            "resource-tag-regex=^QXSmoke$",
            "server-tag-regex=.*",
        ):
            if expected not in quanx_output:
                raise AssertionError(
                    f"Quantumult X server_remote output is missing {expected!r}\n"
                    f"{quanx_output}"
                )
        if "opt-parser=" in quanx_output:
            raise AssertionError("Quantumult X smoke output enabled opt-parser implicitly")
        if "user-agent" not in quanx_headers.get("vary", "").lower():
            raise AssertionError(
                "Quantumult X server_remote response did not emit Vary: User-Agent"
            )

        quanx_explain = json.loads(
            fetch(
                base_url,
                "/sub",
                {
                    "target": "quanx",
                    "url": f"provider:QXExplain,{dead_quanx_source}",
                    "config": QUANX_REMOTE_CONFIG,
                    "explain": "true",
                },
                timeout,
            )
        )
        if (
            quanx_explain.get("mode", {}).get("remote_subscription_backend")
            != "quanx-server-remote"
            or quanx_explain.get("mode", {}).get("remote_subscription_reason")
            != "native-capable"
            or quanx_explain.get("output", {}).get("remote_subscription_count") != 1
        ):
            raise AssertionError(
                f"Quantumult X explain route mismatch: {quanx_explain!r}"
            )
        if "quanx-smoke-source-secret" in json.dumps(quanx_explain):
            raise AssertionError("Quantumult X explain leaked its source credential")

        auto_quanx = fetch(
            base_url,
            "/sub",
            {
                "target": "auto",
                "url": f"provider:QXAuto,{dead_quanx_source}",
                "config": QUANX_REMOTE_CONFIG,
            },
            timeout,
            {"User-Agent": "Quantumult%20X/1.4"},
        )
        if "tag=QXAuto" not in auto_quanx or dead_quanx_source not in auto_quanx:
            raise AssertionError("auto Quantumult X did not select server_remote")

        mixed_quanx = fetch(
            base_url,
            "/sub",
            {
                "target": "quanx",
                "url": f"provider:QXMixed,{dead_quanx_source}|{DIRECT_SS_LINK}",
                "config": QUANX_REMOTE_CONFIG,
            },
            timeout,
        )
        for expected in ("tag=QXMixed", "DirectSmoke", "[server_local]"):
            if expected not in mixed_quanx:
                raise AssertionError(
                    f"mixed Quantumult X output is missing {expected!r}\n{mixed_quanx}"
                )

        dead_loon_source = (
            "https://127.0.0.1:1/loon-must-not-fetch"
            "?token=loon-smoke-source-secret"
        )
        loon_output = fetch(
            base_url,
            "/sub",
            {
                "target": "loon",
                "url": f"provider:LoonSmoke,{dead_loon_source}",
                "config": QUANX_REMOTE_CONFIG,
            },
            timeout,
        )
        for expected in (
            "[Remote Proxy]",
            f"LoonSmoke={dead_loon_source}",
            "[Proxy Group]",
            "Remote = select,LoonSmoke",
        ):
            if expected not in loon_output:
                raise AssertionError(
                    f"Loon remote-proxy output is missing {expected!r}\n{loon_output}"
                )

        dead_stash_source = (
            "https://127.0.0.1:1/stash-must-not-fetch.yaml"
            "?token=stash-smoke-source-secret"
        )
        stash_output = fetch(
            base_url,
            "/sub",
            {
                "target": "stash",
                "url": f"provider:StashSmoke,interval:7200,{dead_stash_source}",
                "config": QUANX_REMOTE_CONFIG,
            },
            timeout,
        )
        for expected in (
            "default-nameserver:",
            "- 223.5.5.5",
            "- 1.12.12.12",
            "- doh3://223.5.5.5/dns-query",
            "- https://1.12.12.12/dns-query",
            "skip-cert-verify: false",
            "follow-rule: false",
            "proxy-providers:",
            "StashSmoke:",
            f"url: {dead_stash_source}",
            "path: ./providers/StashSmoke.yaml",
            "interval: 7200",
            "use:",
            "- StashSmoke",
            "name: Proxy",
            "- Remote",
        ):
            if expected not in stash_output:
                raise AssertionError(
                    f"Stash provider output is missing {expected!r}\n{stash_output}"
                )
        stash_provider_block = stash_output.split("StashSmoke:", 1)[1].split(
            "proxy-groups:", 1
        )[0]
        if any(
            field in stash_provider_block
            for field in (
                "type:",
                "proxy:",
                "header:",
                "health-check:",
                "override:",
                "exclude-filter:",
            )
        ):
            raise AssertionError(
                f"Stash provider leaked Mihomo fields: {stash_provider_block!r}"
            )
        stash_explain = json.loads(
            fetch(
                base_url,
                "/sub",
                {
                    "target": "stash",
                    "url": f"provider:StashSmoke,{dead_stash_source}",
                    "config": QUANX_REMOTE_CONFIG,
                    "explain": "true",
                },
                timeout,
            )
        )
        if (
            stash_explain.get("mode", {}).get("remote_subscription_backend")
            != "stash-proxy-provider"
            or stash_explain.get("resources", {}).get(
                "remote_subscription_count"
            )
            != 1
        ):
            raise AssertionError(f"Stash explain route mismatch: {stash_explain!r}")
        if "stash-smoke-source-secret" in json.dumps(stash_explain):
            raise AssertionError("Stash explain leaked its source token")

        stash_rules = fetch(
            base_url,
            "/sub",
            {
                "target": "stash",
                "url": f"provider:RuleNodes,{dead_stash_source}",
                "config": STASH_RULE_PROVIDER_CONFIG,
            },
            timeout,
        )
        for expected in (
            "rule-providers:",
            "stash-smoke-domain:",
            "behavior: domain",
            "format: mrs",
            "path: ./rules/stash-smoke-domain.mrs",
            "RULE-SET,stash-smoke-domain,RuleGroup",
            "GEOSITE,telegram,RuleGroup",
        ):
            if expected not in stash_rules:
                raise AssertionError(
                    f"Stash native rule-provider output is missing {expected!r}\n"
                    f"{stash_rules}"
                )
        stash_rule_provider_block = provider_block_from_output(
            stash_rules, "stash-smoke-domain"
        )
        expected_rule_provider_fields = (
            "    behavior: domain",
            "    format: mrs",
            "    url: https://127.0.0.1:1/stash-smoke-domain.mrs?"
            "token=stash-rule-smoke-secret",
            "    path: ./rules/stash-smoke-domain.mrs",
            "    interval: 3600",
        )
        stash_rule_provider_lines = set(stash_rule_provider_block.splitlines())
        if any(
            field not in stash_rule_provider_lines
            for field in expected_rule_provider_fields
        ):
            raise AssertionError(
                "Stash rule-provider fields are not associated with the "
                f"expected provider:\n{stash_rule_provider_block}"
            )
        if "type:" in stash_rule_provider_block:
            raise AssertionError(
                "Stash rule-provider leaked the Mihomo type field"
            )
        stash_rules_explain = json.loads(
            fetch(
                base_url,
                "/sub",
                {
                    "target": "stash",
                    "url": f"provider:RuleNodes,{dead_stash_source}",
                    "config": STASH_RULE_PROVIDER_CONFIG,
                    "explain": "true",
                },
                timeout,
            )
        )
        stash_rule_resources = stash_rules_explain.get("resources", {})
        if (
            stash_rules_explain.get("target") != "stash"
            or stash_rules_explain.get("ok") is not True
            or stash_rules_explain.get("status_code") != 200
            or stash_rule_resources.get("ruleset_count") != 2
            or stash_rule_resources.get("rule_provider_count") != 1
            or stash_rule_resources.get("inline_rule_source_count") != 1
            or stash_rule_resources.get("expanded_rule_source_count") != 0
            or stash_rule_resources.get("unsupported_ruleset_count") != 0
        ):
            raise AssertionError(
                f"Stash native rule-provider Explain mismatch: "
                f"{stash_rules_explain!r}"
            )
        stash_rules_explain_text = json.dumps(stash_rules_explain)
        if any(
            secret in stash_rules_explain_text
            for secret in (
                "stash-rule-smoke-secret",
                "stash-smoke-source-secret",
            )
        ):
            raise AssertionError("Stash rule-provider Explain leaked a token")

        stash_direct = fetch(
            base_url,
            "/sub",
            {
                "target": "stash",
                "url": STASH_MIERU_LINK + "|" + STASH_HYSTERIA2_LINK,
                "list": "true",
            },
            timeout,
        )
        for expected in (
            "type: mieru",
            "port-range: 9998-9999",
            "transport: tcp",
            "type: hysteria2",
        ):
            if expected not in stash_direct:
                raise AssertionError(
                    f"Stash direct protocol output is missing {expected!r}\n"
                    f"{stash_direct}"
                )

        quanx_list = fetch(
            base_url,
            "/sub",
            {
                "target": "quanx",
                "url": remote_subscription_url,
                "config": QUANX_REMOTE_CONFIG,
                "list": "true",
            },
            timeout,
        )
        if "Smoke" not in quanx_list or remote_subscription_url in quanx_list:
            raise AssertionError(
                "Quantumult X list=true did not retain Legacy expansion"
            )

        quanx_fallback = fetch(
            base_url,
            "/sub",
            {
                "target": "quanx",
                "url": f"provider:QXLegacy,{remote_subscription_url}",
                "config": QUANX_REMOTE_CONFIG,
                "tfo": "true",
            },
            timeout,
        )
        if "Smoke" not in quanx_fallback or remote_subscription_url in quanx_fallback:
            raise AssertionError(
                "Quantumult X explicit node override did not select Legacy"
            )

        mixed_url = f"{remote_subscription_url}|{DIRECT_SS_LINK}"
        clash_cases = (
            (
                "remote/list=false",
                remote_subscription_url,
                False,
                ("proxy-providers:", remote_subscription_url),
                ("name: Smoke", "DirectSmoke"),
            ),
            (
                "uri/list=false",
                DIRECT_SS_LINK,
                False,
                ("DirectSmoke", "direct.example.com"),
                ("proxy-providers:", "name: Smoke"),
            ),
            (
                "mixed/list=false",
                mixed_url,
                False,
                ("proxy-providers:", remote_subscription_url, "DirectSmoke"),
                ("name: Smoke",),
            ),
            (
                "remote/list=true",
                remote_subscription_url,
                True,
                ("Smoke", "example.com"),
                ("proxy-providers:", "DirectSmoke"),
            ),
            (
                "uri/list=true",
                DIRECT_SS_LINK,
                True,
                ("DirectSmoke", "direct.example.com"),
                ("proxy-providers:", "name: Smoke"),
            ),
            (
                "mixed/list=true",
                mixed_url,
                True,
                ("Smoke", "DirectSmoke", "example.com", "direct.example.com"),
                ("proxy-providers:",),
            ),
        )
        for case_name, source_url, list_mode, expected, forbidden in clash_cases:
            params = {
                "target": "clash",
                "url": source_url,
                "config": DISABLE_RULEGEN_CONFIG,
            }
            if list_mode:
                params["list"] = "true"
            output = fetch(base_url, "/sub", params, timeout)
            missing = [value for value in expected if value not in output]
            unexpected = [value for value in forbidden if value in output]
            if missing or unexpected:
                raise AssertionError(
                    f"{case_name} failed: missing={missing}, unexpected={unexpected}\n"
                    f"{output}"
                )

        provider_group_output = fetch(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": "|".join(
                    (
                        f"tag:myvps,provider:MyVPS,{remote_subscription_url}",
                        f"tag:home,provider:Home,{remote_subscription_url}",
                        f"tag:public,provider:Public,{remote_subscription_url}",
                    )
                ),
                "config": PROVIDER_GROUP_TAG_CONFIG,
            },
            timeout,
        )
        expected_provider_groups = {
            "Plain": (["MyVPS", "Home", "Public"], "Smoke"),
            "OnlyPublic": (["Public"], "Smoke"),
            "ExcludePrivate": (["Public"], "Smoke"),
            "PublicAll": (["Public"], None),
            "ByGroupId": (["Public"], "Smoke"),
            "ExplicitProvider": (["Public"], None),
        }
        for group_name, (
            expected_use,
            expected_filter,
        ) in expected_provider_groups.items():
            actual_use = proxy_group_use_from_output(
                provider_group_output, group_name
            )
            actual_filter = proxy_group_filter_from_output(
                provider_group_output, group_name
            )
            if actual_use != expected_use or actual_filter != expected_filter:
                raise AssertionError(
                    f"provider group {group_name} mismatch: "
                    f"use={actual_use!r}, filter={actual_filter!r}; "
                    f"expected use={expected_use!r}, filter={expected_filter!r}\n"
                    f"{proxy_group_block_from_output(provider_group_output, group_name)}"
                )
        if (
            "filter: !!GROUP=" in provider_group_output
            or 'filter: "!!GROUP=' in provider_group_output
        ):
            raise AssertionError(
                "provider GROUP selector leaked into the Mihomo node filter"
            )

        def assert_provider_ua_present(label: str, output: str, user_agent: str) -> None:
            required = ("proxy-providers:", "header:", "User-Agent:", user_agent)
            missing = [value for value in required if value not in output]
            if missing:
                raise AssertionError(
                    f"{label} did not include provider User-Agent: missing={missing}\n"
                    f"{output}"
                )

        def assert_provider_ua_absent(label: str, output: str) -> None:
            if "User-Agent:" in output:
                raise AssertionError(
                    f"{label} unexpectedly included provider User-Agent\n{output}"
                )

        provider_params = {
            "target": "clash",
            "url": remote_subscription_url,
            "config": DISABLE_RULEGEN_CONFIG,
        }
        interval_output = fetch(
            base_url,
            "/sub",
            {
                **provider_params,
                "url": "|".join(
                    (
                        f"provider:Zero,interval:0,proxy_direct:false,{remote_subscription_url}",
                        f"proxy_direct:true,interval:21600,provider:Slow,{remote_subscription_url}",
                        f"provider:Default,{remote_subscription_url}",
                    )
                ),
            },
            timeout,
        )
        for provider_name, expected in {
            "Zero": 0,
            "Slow": 21600,
            "Default": 3600,
        }.items():
            actual = provider_interval_from_output(interval_output, provider_name)
            if actual != expected:
                raise AssertionError(
                    f"{provider_name} interval mismatch: {actual} != {expected}"
                )
        if interval_output.count("      interval: 300") != 3:
            raise AssertionError("provider health-check intervals changed")
        for provider_name, expected in {
            "Zero": False,
            "Slow": True,
            "Default": True,
        }.items():
            actual = provider_proxy_direct_from_output(interval_output, provider_name)
            if actual is not expected:
                raise AssertionError(
                    f"{provider_name} proxy_direct mismatch: {actual} != {expected}"
                )

        managed_interval_output = fetch(
            base_url,
            "/sub",
            {
                **provider_params,
                "url": f"provider:Managed,{remote_subscription_url}",
                "interval": "17",
            },
            timeout,
        )
        if provider_interval_from_output(managed_interval_output, "Managed") != 3600:
            raise AssertionError(
                "request-level interval parameter changed provider interval"
            )

        request_false_output = fetch(
            base_url,
            "/sub",
            {
                **provider_params,
                "url": "|".join(
                    (
                        f"provider:RequestFalse,{remote_subscription_url}",
                        f"provider:LinkTrue,proxy_direct:true,{remote_subscription_url}",
                    )
                ),
                "provider_proxy_direct": "false",
            },
            timeout,
        )
        if provider_proxy_direct_from_output(request_false_output, "RequestFalse"):
            raise AssertionError(
                "provider_proxy_direct=false no longer omits proxy: DIRECT"
            )
        if not provider_proxy_direct_from_output(request_false_output, "LinkTrue"):
            raise AssertionError(
                "per-link proxy_direct=true did not override the request default"
            )

        direct_explain = fetch(
            base_url,
            "/sub",
            {
                **provider_params,
                "url": f"provider:ExplainDirect,proxy_direct:false,{remote_subscription_url}",
                "explain": "true",
            },
            timeout,
        )
        direct_report = json.loads(direct_explain)
        direct_providers = direct_report.get("providers", [])
        if (
            len(direct_providers) != 1
            or direct_providers[0].get("proxy_direct") is not False
            or direct_providers[0].get("proxy_field_emitted") is not False
        ):
            raise AssertionError(
                f"proxy_direct explain output is incorrect: {direct_providers!r}"
            )

        for label, source_value in (
            ("none provider interval", "interval:none,https://example.invalid/sub"),
            (
                "duplicate provider interval",
                "interval:0,interval:1,https://example.invalid/sub",
            ),
            ("provider interval on direct node", f"interval:0,{DIRECT_SS_LINK}"),
        ):
            assert_rejected(
                base_url,
                "/sub",
                {
                    "target": "clash",
                    "url": source_value,
                    "config": DISABLE_RULEGEN_CONFIG,
                },
                timeout,
                label,
            )

        for label, source_value in (
            (
                "none provider proxy_direct",
                "proxy_direct:none,https://example.invalid/sub",
            ),
            (
                "duplicate provider proxy_direct",
                "proxy_direct:true,proxy_direct:false,https://example.invalid/sub",
            ),
            (
                "provider proxy_direct on direct node",
                f"proxy_direct:false,{DIRECT_SS_LINK}",
            ),
        ):
            assert_rejected(
                base_url,
                "/sub",
                {
                    "target": "clash",
                    "url": source_value,
                    "config": DISABLE_RULEGEN_CONFIG,
                },
                timeout,
                label,
            )

        assert_rejected(
            base_url,
            "/sub",
            {**provider_params, "url": f"interval:0,{remote_subscription_url}", "list": "true"},
            timeout,
            "provider interval with list=true",
        )
        assert_rejected(
            base_url,
            "/sub",
            {
                **provider_params,
                "url": f"proxy_direct:false,{remote_subscription_url}",
                "list": "true",
            },
            timeout,
            "provider proxy_direct with list=true",
        )
        client_ua = "clash.meta/1.19.20"
        client_output, client_headers = fetch_response(
            base_url,
            "/sub",
            provider_params,
            timeout,
            {"User-Agent": client_ua},
        )
        assert_provider_ua_present("client UA provider", client_output, client_ua)
        vary_values = {
            value.strip().lower()
            for value in client_headers.get("vary", "").split(",")
            if value.strip()
        }
        if "user-agent" not in vary_values:
            raise AssertionError(
                "client UA provider response did not emit Vary: User-Agent"
            )

        custom_ua = "AirportRequired-UA/2026.07"
        custom_output = fetch(
            base_url,
            "/sub",
            provider_params,
            timeout,
            {"User-Agent": custom_ua},
        )
        assert_provider_ua_present("custom UA provider", custom_output, custom_ua)
        if client_ua in custom_output:
            raise AssertionError("custom UA provider output reused the sample UA")

        selected_header_output, selected_header_response_headers = fetch_response(
            base_url,
            "/sub",
            {**provider_params, "provider_headers": "x-hwid,Authorization"},
            timeout,
            {
                "User-Agent": client_ua,
                "x-hwid": "smoke-device-2026",
                "Authorization": "Bearer provider-smoke-token",
                "X-Unselected-Smoke": "must-not-leak",
            },
        )
        selected_header_output_lower = selected_header_output.lower()
        for expected in ("x-hwid:", "authorization:"):
            if expected not in selected_header_output_lower:
                raise AssertionError(
                    f"selected provider header output is missing {expected!r}"
                )
        for expected in ("smoke-device-2026", "Bearer provider-smoke-token"):
            if expected not in selected_header_output:
                raise AssertionError(
                    f"selected provider header output is missing {expected!r}"
                )
        if "must-not-leak" in selected_header_output:
            raise AssertionError("unselected request header leaked into proxy-provider")
        selected_vary = {
            value.strip().lower()
            for value in selected_header_response_headers.get("vary", "").split(",")
            if value.strip()
        }
        for expected in (
            "x-hwid",
            "authorization",
            "x-age-public-key",
            "user-agent",
        ):
            if expected not in selected_vary:
                raise AssertionError(
                    f"selected provider response Vary is missing {expected}"
                )

        expanded_with_headers = fetch(
            base_url,
            "/sub",
            {
                **provider_params,
                "list": "true",
                "provider_headers": "x-hwid",
            },
            timeout,
            {
                "User-Agent": client_ua,
                "x-hwid": "smoke-device-2026",
            },
        )
        if (
            "Smoke" not in expanded_with_headers
            or "proxy-providers:" in expanded_with_headers
        ):
            raise AssertionError("list=true provider header fetch did not expand nodes")

        assert_rejected(
            base_url,
            "/sub",
            {**provider_params, "provider_headers": "x-missing-smoke"},
            timeout,
            "missing selected provider header",
        )
        assert_rejected(
            base_url,
            "/sub",
            {**provider_params, "provider_headers": "X-Age-Public-Key"},
            timeout,
            "reserved selected provider header",
            {"X-Age-Public-Key": AGE_PUBLIC_KEY},
        )
        assert_rejected(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": DIRECT_SS_LINK,
                "config": DISABLE_RULEGEN_CONFIG,
                "provider_headers": "x-hwid",
            },
            timeout,
            "selected provider header without a generated provider",
            {"x-hwid": "smoke-device-2026"},
        )

        browser_output, browser_headers = fetch_response(
            base_url,
            "/sub",
            provider_params,
            timeout,
            {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/126.0.0.0 Safari/537.36"
                )
            },
        )
        if "proxy-providers:" not in browser_output:
            raise AssertionError("browser UA provider request did not stay in provider mode")
        assert_provider_ua_absent("browser UA provider", browser_output)
        browser_vary_values = {
            value.strip().lower()
            for value in browser_headers.get("vary", "").split(",")
            if value.strip()
        }
        if "user-agent" not in browser_vary_values:
            raise AssertionError(
                "browser UA provider response did not emit Vary: User-Agent"
            )

        tool_output = fetch(
            base_url,
            "/sub",
            provider_params,
            timeout,
            {"User-Agent": "curl/8.5.0"},
        )
        assert_provider_ua_absent("inspection-tool UA provider", tool_output)

        uri_with_client_ua = fetch(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": DIRECT_SS_LINK,
                "config": DISABLE_RULEGEN_CONFIG,
            },
            timeout,
            {"User-Agent": client_ua},
        )
        if "proxy-providers:" in uri_with_client_ua:
            raise AssertionError("URI-only request unexpectedly entered provider mode")
        assert_provider_ua_absent("URI-only client UA", uri_with_client_ua)

        list_true_with_client_ua = fetch(
            base_url,
            "/sub",
            {**provider_params, "list": "true"},
            timeout,
            {"User-Agent": client_ua},
        )
        if "proxy-providers:" in list_true_with_client_ua:
            raise AssertionError("list=true request unexpectedly emitted proxy-providers")
        assert_provider_ua_absent("list=true client UA", list_true_with_client_ua)

        mixed_with_client_ua = fetch(
            base_url,
            "/sub",
            {**provider_params, "url": mixed_url},
            timeout,
            {"User-Agent": client_ua},
        )
        assert_provider_ua_present("mixed client UA provider", mixed_with_client_ua, client_ua)
        if "DirectSmoke" not in mixed_with_client_ua:
            raise AssertionError("mixed client UA provider lost direct URI nodes")

        clashr_with_client_ua = fetch(
            base_url,
            "/sub",
            {**provider_params, "target": "clashr"},
            timeout,
            {"User-Agent": client_ua},
        )
        assert_provider_ua_absent("clashr client UA provider", clashr_with_client_ua)

        duplicate_uri_nodes = fetch(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": f"{DIRECT_SS_LINK}|{DIRECT_SS_LINK}",
                "config": DISABLE_RULEGEN_CONFIG,
                "list": "true",
            },
            timeout,
        )
        if "DirectSmoke 2" not in duplicate_uri_nodes:
            raise AssertionError("duplicate URI node names were not made unique")

        duplicate_remote_nodes = fetch(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": f"{remote_subscription_url}|{remote_subscription_url}",
                "config": DISABLE_RULEGEN_CONFIG,
                "list": "true",
            },
            timeout,
        )
        if "Smoke 2" not in duplicate_remote_nodes:
            raise AssertionError("duplicate subscription node names were not made unique")

        if verify_non_clash:
            singbox_config = fetch(
                base_url,
                "/sub",
                {
                    "target": "singbox",
                    "url": remote_subscription_url,
                    "config": DISABLE_RULEGEN_CONFIG,
                },
                timeout,
            )
            singbox_json = json.loads(singbox_config)
            outbounds = singbox_json.get("outbounds", [])
            if not any(outbound.get("tag") == "Smoke" for outbound in outbounds):
                raise AssertionError(
                    "remote sing-box conversion did not expand the subscription"
                )
            dns = singbox_json.get("dns", {})
            dns_servers = dns.get("servers", [])
            if [server.get("type") for server in dns_servers] != [
                "tls",
                "h3",
                "fakeip",
                "udp",
            ]:
                raise AssertionError(
                    "deployed sing-box profile did not use modern DNS servers"
                )
            if (
                "fakeip" in dns
                or "independent_cache" in dns
                or any(
                    "address" in server or "address_resolver" in server
                    for server in dns_servers
                )
            ):
                raise AssertionError(
                    "deployed sing-box profile retained legacy DNS fields"
                )
            tun = next(
                (
                    inbound
                    for inbound in singbox_json.get("inbounds", [])
                    if inbound.get("type") == "tun"
                ),
                None,
            )
            if (
                tun is None
                or tun.get("address") != ["172.19.0.1/30"]
                or any(
                    field in tun
                    for field in ("inet4_address", "inet6_address", "sniff")
                )
            ):
                raise AssertionError(
                    "deployed sing-box profile retained legacy TUN fields"
                )
            route_rules = singbox_json.get("route", {}).get("rules", [])
            if (
                not any(rule.get("action") == "sniff" for rule in route_rules)
                or not any(
                    rule.get("action") == "hijack-dns" for rule in route_rules
                )
                or any("action" not in rule for rule in route_rules)
            ):
                raise AssertionError(
                    "deployed sing-box profile did not use modern route actions"
                )

            surge_config = fetch(
                base_url,
                "/sub",
                {
                    "target": "surge",
                    "url": remote_subscription_url,
                    "config": QUANX_REMOTE_CONFIG,
                },
                timeout,
            )
            if (
                f"policy-path={remote_subscription_url}" not in surge_config
                or "policy-regex-filter=" not in surge_config
            ):
                raise AssertionError(
                    "remote Surge conversion did not emit policy-path"
                )
            if surge_contains_fixture_proxy(surge_config, "Smoke", "example.com"):
                raise AssertionError(
                    "remote Surge conversion unexpectedly expanded the subscription"
                )

    if mihomo_yaml_subscription_url:
        mihomo_yaml_nodes = fetch(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": mihomo_yaml_subscription_url,
                "config": DISABLE_RULEGEN_CONFIG,
                "list": "true",
            },
            timeout,
        )
        if (
            "NativeYAML" not in mihomo_yaml_nodes
            or "yaml.example.com" not in mihomo_yaml_nodes
            or "udp: true" not in mihomo_yaml_nodes
            or "smux:" not in mihomo_yaml_nodes
            or "enabled: true" not in mihomo_yaml_nodes
            or "NativeVLESS" not in mihomo_yaml_nodes
            or "alpn:" not in mihomo_yaml_nodes
            or "h2" not in mihomo_yaml_nodes
            or "ws-opts:" not in mihomo_yaml_nodes
            or "path: /ws" not in mihomo_yaml_nodes
            or "proxy-providers:" in mihomo_yaml_nodes
        ):
            raise AssertionError(
                "Mihomo native YAML was not expanded with scalar types preserved"
            )

    if mihomo_raw_subscription_url:
        mihomo_raw_nodes = fetch(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": mihomo_raw_subscription_url,
                "config": DISABLE_RULEGEN_CONFIG,
                "list": "true",
            },
            timeout,
        )
        if "Smoke" not in mihomo_raw_nodes or "proxy-providers:" in mihomo_raw_nodes:
            raise AssertionError(
                "Mihomo did not expand the fetched raw URI subscription"
            )

    if legacy_subscription_url:
        legacy_common = {
            "url": legacy_subscription_url,
            "config": DISABLE_RULEGEN_CONFIG,
            "list": "true",
        }
        for label, target, headers in (
            ("explicit Clash", "clash", None),
            ("explicit ClashR", "clashr", None),
            ("auto Clash", "auto", {"User-Agent": "Clash/1.0"}),
            (
                "auto ClashR",
                "auto",
                {"User-Agent": "ClashForAndroid/1.9R"},
            ),
        ):
            assert_rejected(
                base_url,
                "/sub",
                {"target": target, **legacy_common},
                timeout,
                f"{label} Mihomo-only parser route",
                headers,
            )

    if legacy_subscription_url and verify_non_clash:
        legacy_singbox = fetch(
            base_url,
            "/sub",
            {
                "target": "singbox",
                "url": legacy_subscription_url,
                "config": DISABLE_RULEGEN_CONFIG,
            },
            timeout,
        )
        legacy_json = json.loads(legacy_singbox)
        legacy_outbounds = legacy_json.get("outbounds", [])
        if not any(
            outbound.get("tag") == "LegacyFallback" for outbound in legacy_outbounds
        ):
            raise AssertionError(
                "legacy-only parser did not expand the Surge subscription"
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:25500")
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--snapshot-dir", type=Path)
    parser.add_argument("--update-snapshots", action="store_true")
    parser.add_argument(
        "--remote-subscription-url",
        help="Optional HTTP(S) subscription used to verify provider vs expanded output.",
    )
    parser.add_argument(
        "--mihomo-raw-subscription-url",
        help="Optional raw URI subscription used to verify Mihomo fetch expansion.",
    )
    parser.add_argument(
        "--mihomo-yaml-subscription-url",
        help="Optional native Mihomo YAML subscription used to verify list expansion.",
    )
    parser.add_argument(
        "--legacy-subscription-url",
        help="Optional legacy subscription used to verify legacy-only parsing.",
    )
    parser.add_argument(
        "--verify-non-clash",
        action="store_true",
        help="Also verify sing-box, Surge, and legacy-parser compatibility.",
    )
    args = parser.parse_args()

    try:
        run_checks(
            args.base_url,
            args.timeout,
            args.snapshot_dir,
            args.update_snapshots,
            args.remote_subscription_url,
            args.mihomo_raw_subscription_url,
            args.mihomo_yaml_subscription_url,
            args.legacy_subscription_url,
            args.verify_non_clash,
        )
    except Exception as exc:
        print(f"smoke checks failed: {exc}", file=sys.stderr)
        return 1

    print("smoke checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
