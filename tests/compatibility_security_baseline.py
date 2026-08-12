#!/usr/bin/env python3
"""Offline compatibility and security baselines for the built service."""

from __future__ import annotations

import argparse
import base64
import contextlib
import difflib
import hashlib
import http.client
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
FIXTURES = REPOSITORY / "tests" / "fixtures"
COMPAT_FIXTURES = FIXTURES / "compat"
GOLDEN_ROOT = REPOSITORY / "tests" / "snapshots" / "compatibility"


def _urlsafe_b64(value: str | bytes) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


SUBSCRIPTION = (
    "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:8388#Smoke\n"
)
ENCODED_SUBSCRIPTION = base64.urlsafe_b64encode(SUBSCRIPTION.encode()).decode()
VLESS_URI = (
    "vless://11111111-1111-1111-1111-111111111111@vless.example.test:443"
    "?security=tls&type=ws&host=vless.example.test&path=%2Fws#VLESSFixture"
)
VMESS_STANDARD_URI = (
    "vmess://22222222-2222-2222-2222-222222222222@vmess.example.test:443"
    "?encryption=none&security=tls&sni=tls.example.test"
    "&alpn=h2%2Chttp%2F1.1&fp=chrome&insecure=1#VMessStandard"
)
VMESS_QR_URI = "vmess://" + base64.urlsafe_b64encode(
    json.dumps(
        {
            "v": "2",
            "ps": "VMessQR",
            "add": "vmess-qr.example.test",
            "port": "443",
            "id": "33333333-3333-3333-3333-333333333333",
            "aid": "0",
            "scy": "chacha20-poly1305",
            "net": "grpc",
            "type": "multi",
            "path": "grpc-service",
            "host": "",
            "tls": "tls",
            "sni": "grpc.example.test",
            "alpn": "h2,http/1.1",
            "fp": "firefox",
        },
        separators=(",", ":"),
    ).encode()
).decode().rstrip("=")
VMESS_QR_QUIC_URI = "vmess://" + base64.urlsafe_b64encode(
    json.dumps(
        {
            "v": "2",
            "ps": "VMessQUIC",
            "add": "vmess-quic.example.test",
            "port": "443",
            "id": "99999999-9999-9999-9999-999999999999",
            "aid": "0",
            "scy": "auto",
            "net": "quic",
            "type": "srtp",
            "host": "aes-128-gcm",
            "path": "quic-secret",
            "tls": "tls",
        },
        separators=(",", ":"),
    ).encode()
).decode().rstrip("=")
VLESS_DEFAULT_TCP_URI = (
    "vless://44444444-4444-4444-4444-444444444444@[2001:db8::1]:443"
    "?encryption=none&security=tls&sni=vless-tls.example.test"
    "&alpn=h2%2Chttp%2F1.1&insecure=1#VLESSDefaultTCP"
)
VLESS_XHTTP_URI = (
    "vless://55555555-5555-5555-5555-555555555555@vless-xhttp.example.test:443"
    "?encryption=none&security=reality&type=xhttp&host=xhttp.example.test"
    "&path=%2Fsplit%3Ftoken%3D1&mode=stream-one"
    "&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D"
    "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=00112233"
    "&fp=chrome#VLESSXHTTP"
)
VLESS_HTTPUPGRADE_URI = (
    "vless://66666666-6666-6666-6666-666666666666@upgrade.example.test:443"
    "?encryption=none&security=tls&type=httpupgrade&host=upgrade-host.example.test"
    "&path=%2Fupgrade#VLESSHTTPUpgrade"
)
VLESS_GRPC_URI = (
    "vless://77777777-7777-7777-7777-777777777777@grpc-vless.example.test:443"
    "?encryption=none&security=tls&type=grpc&serviceName=service%2Fname"
    "&mode=multi&authority=authority.example.test#VLESSGRPC"
)
VLESS_TCP_HTTP_URI = (
    "vless://88888888-8888-8888-8888-888888888888@http-vless.example.test:443"
    "?encryption=none&security=tls&type=tcp&headerType=http"
    "&host=header.example.test&path=%2Fheader#VLESSTCPHTTP"
)
VLESS_QUIC_URI = (
    "vless://aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa@vless-quic.example.test:443"
    "?encryption=none&security=tls&type=quic&headerType=utp"
    "&quicSecurity=chacha20-poly1305&key=vless-quic-secret#VLESSQUIC"
)
TROJAN_WS_URI = (
    "trojan://p%40ss+word%2Ftoken@[2001:db8::2]:443"
    "?security=tls&type=ws&host=ws.example.test&path=%2Fsocket"
    "&sni=trojan-tls.example.test&alpn=h2%2Chttp%2F1.1&fp=chrome"
    "&insecure=1#TrojanWS"
)
TROJAN_KCP_URI = (
    "trojan://kcp-password@trojan-kcp.example.test:443"
    "?security=tls&type=kcp&headerType=wechat-video"
    "&seed=trojan-kcp-seed#TrojanKCP"
)
XRAY_PROTOCOL_SUBSCRIPTION = (
    VMESS_STANDARD_URI + "\n" + VLESS_HTTPUPGRADE_URI + "\n" + TROJAN_WS_URI + "\n"
)
ENCODED_XRAY_PROTOCOL_SUBSCRIPTION = base64.urlsafe_b64encode(
    XRAY_PROTOCOL_SUBSCRIPTION.encode()
).decode()
HYSTERIA2_URI = (
    "hysteria2://hy-password@hy2.example.test:8443/?insecure=1"
    "&obfs=salamander&obfs-password=real-obfs-password"
    "&sni=hy2.example.test#Hy2Fixture"
)
HYSTERIA2_MODERN_URI = (
    "hy2://user%3Apass+token@[2001:db8::10]:8443,12000-12002/"
    "?insecure=1&obfs=salamander&obfs-password=obfs%2Bsecret"
    "&sni=hy2-tls.example.test&pinSHA256=AA%3ABB%3ACC"
    "&ech=AE%2Bconfig%2Fvalue#Hy2%20Modern+Literal"
)
HYSTERIA2_SURGE_GECKO_URI = HYSTERIA2_MODERN_URI.replace(
    "obfs=salamander", "obfs=gecko"
)
TUIC_MODERN_URI = (
    "tuic://99999999-9999-4999-8999-999999999999:p%40ss+word"
    "@[2001:db8::11]:10443?allow_insecure=1&sni=tuic-tls.example.test"
    "&congestion_control=bbr&udp_relay_mode=quic&zero_rtt_handshake=1"
    "&disable_sni=0&request_timeout=9000#TUIC%20Modern"
)
TUIC_SURGE_URI = (
    "tuic://surge%2Btoken@[2001:db8::13]:11443?allow_insecure=1"
    "&sni=tuic-surge.example.test&alpn=h3#TUIC%20Surge"
)
ANYTLS_MODERN_URI = (
    "anytls://p%40ss+word@[2001:db8::12]/?sni=anytls-tls.example.test"
    "&insecure=1&alpn=h2%2Chttp%2F1.1&fp=chrome"
    "&idle_session_check_interval=45s&idle_session_timeout=60s"
    "&min_idle_session=3#AnyTLS%20Modern"
)
SS_SIP002_URI = (
    "ss://"
    + _urlsafe_b64("aes-256-gcm:p@ss+word")
    + "@[2001:db8::21]:8388/?plugin="
    + urllib.parse.quote(
        "v2ray-plugin;mode=websocket;host=plugin.example.test;path=/ws;tls",
        safe="",
    )
    + "#SS%20SIP002"
)
SS_2022_PASSWORD = base64.b64encode(
    bytes([0xFB]) * 32
).decode("ascii")
SS_2022_URI = (
    "ss://2022-blake3-aes-256-gcm:"
    + urllib.parse.quote(SS_2022_PASSWORD, safe="")
    + "@[2001:db8::22]:8389#SS%202022"
)
SSR_IPV6_URI = "ssr://" + _urlsafe_b64(
    "[2001:db8::23]:8390:auth_sha1_v4:aes-256-cfb:tls1.2_ticket_auth:"
    + _urlsafe_b64("legacy:p@ss")
    + "/?group="
    + _urlsafe_b64("SSR Fixture")
    + "&remarks="
    + _urlsafe_b64("SSR IPv6")
    + "&obfsparam="
    + _urlsafe_b64("cdn.example.test")
    + "&protoparam="
    + _urlsafe_b64("64:fixture")
)
SOCKS_CURRENT_URI = (
    "socks://"
    + _urlsafe_b64("current-user:p@ss+word:tail")
    + "@[2001:db8::24]:1080#SOCKS%20Current"
)
SOCKS_LEGACY_URI = (
    "socks://"
    + _urlsafe_b64("legacy-user:legacy-pass@[2001:db8::25]:1081")
    + "#SOCKS%20Legacy"
)
SOCKS_PLAIN_URI = (
    "socks://plain-user:p%40ss%2Bword@[2001:db8::26]:1082"
    "#SOCKS%20Plain"
)
SOCKS_NO_AUTH_URI = (
    "socks://" + _urlsafe_b64("[2001:db8::27]:1083") + "#SOCKS%20NoAuth"
)
HTTP_LEGACY_URI = (
    "http://"
    + _urlsafe_b64("http-user:http-pass@[2001:db8::28]:8080")
    + "?remarks=HTTP%20Legacy&group=HTTP%20Fixture"
)
HTTPS_LEGACY_URI = (
    "https://"
    + _urlsafe_b64("https-user:https-pass@[2001:db8::29]:8443")
    + "?remarks=HTTPS%20Legacy&group=HTTP%20Fixture"
)
TELEGRAM_SOCKS_URI = (
    "tg://socks?server=telegram-socks.example.test&port=1084"
    "&user=tg-user&pass=tg%2Bpass&remarks=Telegram%20SOCKS"
)
TELEGRAM_HTTP_URI = (
    "tg://http?server=telegram-http.example.test&port=8081"
    "&user=tg-http&pass=tg%2Bhttp&remarks=Telegram%20HTTP"
)
SIP008_OBJECT = json.dumps(
    {
        "version": 1,
        "remarks": "SIP008 Fixture",
        "servers": [
            {
                "id": "sip008-plugin",
                "remarks": "SIP008 Plugin",
                "server": "2001:db8::30",
                "server_port": 8388,
                "password": "sip008-password",
                "method": "aes-256-gcm",
                "plugin": "v2ray-plugin",
                "plugin_opts": "mode=websocket;host=sip008.example.test;tls",
            }
        ],
    },
    separators=(",", ":"),
)
SIP008_ARRAY = json.dumps(
    [
        {
            "id": "sip008-array",
            "remarks": "SIP008 Array",
            "server": "2001:db8::31",
            "server_port": 8391,
            "password": SS_2022_PASSWORD,
            "method": "2022-blake3-aes-256-gcm",
        }
    ],
    separators=(",", ":"),
)
SSR_LIBEV_CONFIG = json.dumps(
    {
        "server": "2001:db8::32",
        "server_port": 8392,
        "local_address": "127.0.0.1",
        "local_port": 1080,
        "password": "ssr-json-password",
        "method": "aes-256-cfb",
        "protocol": "auth_sha1_v4",
        "protocol_param": "32:json",
        "obfs": "tls1.2_ticket_auth",
        "obfs_param": "json.example.test",
    },
    separators=(",", ":"),
)
MIXED_PROTOCOL_SUBSCRIPTION = SUBSCRIPTION + VLESS_URI + "\n" + HYSTERIA2_URI + "\n"
ENCODED_MIXED_PROTOCOL_SUBSCRIPTION = base64.urlsafe_b64encode(
    MIXED_PROTOCOL_SUBSCRIPTION.encode()
).decode()
RULESET = (
    "DOMAIN-SUFFIX,example.com,Proxy\n"
    "IP-CIDR,198.51.100.0/24,Proxy\n"
)
ISSUE_98_RULESET = "DOMAIN-SUFFIX,issue-98.example\n"
RULESET_WITH_INVALID_LINE = (
    "DOMAIN-SUFFIX,valid-before.example,SourcePolicy\n"
    "NOT-A-SUPPORTED-RULE,this-entry-must-be-skipped\n"
    "IP-CIDR,203.0.113.0/24,SourcePolicy\n"
)
GENERATION_RULESET = (
    "DOMAIN-SUFFIX,first.snapshot.test,Proxy\n"
    "DOMAIN-SUFFIX,second.snapshot.test,Proxy\n"
    "DOMAIN-SUFFIX,third.snapshot.test,Proxy\n"
)
DISABLE_RULEGEN_CONFIG = "data:,enable_rule_generator=false"
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
LEGACY_ONLY_TARGETS = (
    "surge",
    "quan",
    "quanx",
    "loon",
    "surfboard",
    "mellow",
    "singbox",
    "ss",
    "ssd",
    "ssr",
    "sssub",
    "v2ray",
    "trojan",
    "vless",
    "hysteria2",
    "mixed",
)
GIST_FIXTURE_TOKEN = "fixture-token"
GIST_FIXTURE_CONFIG = (
    "[common]\n"
    f"token={GIST_FIXTURE_TOKEN}\n"
    "username=fixture-user\n"
)
VLESS_REALITY_WITHOUT_SID_URI = (
    "vless://22222222-2222-4222-8222-222222222222@reality.example.test:443"
    "?encryption=none&security=reality&flow=xtls-rprx-vision&type=tcp"
    "&sni=www.amazon.nl"
    "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "&fp=chrome#RealityWithoutSid"
)
VLESS_REALITY_WITH_NUMERIC_SID_URI = (
    "vless://33333333-3333-4333-8333-333333333333@reality.example.test:443"
    "?encryption=none&security=reality&flow=xtls-rprx-vision&type=tcp"
    "&sni=www.amazon.nl"
    "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "&sid=00112233"
    "&fp=chrome#RealityNumericSid"
)
GIST_REMOTE_FAILURE_SECRET = "remote-response-user-body-secret"
GIST_REMOTE_FAILURE_BODY = (
    '{"error":"' + GIST_REMOTE_FAILURE_SECRET + '",'
    '"authorization":"token ' + GIST_FIXTURE_TOKEN + '"}'
).encode()


class FixtureHandler(BaseHTTPRequestHandler):
    gist_request_count = 0
    provider_never_fetch_count = 0
    quanx_remote_fetch_count = 0
    external_valid_count = 0
    get_request_count = 0
    counter_lock = threading.Lock()
    slow_subscription_started = threading.Event()
    slow_subscription_release = threading.Event()
    slow_ruleset_started = threading.Event()
    slow_ruleset_release = threading.Event()

    def do_GET(self) -> None:  # noqa: N802
        with type(self).counter_lock:
            type(self).get_request_count += 1
        request_path = urllib.parse.urlsplit(self.path).path
        if request_path == "/subscription.txt":
            body = ENCODED_SUBSCRIPTION.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/provider-must-not-fetch.txt":
            type(self).provider_never_fetch_count += 1
            body = ENCODED_SUBSCRIPTION.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/quanx-remote.txt":
            type(self).quanx_remote_fetch_count += 1
            body = ENCODED_SUBSCRIPTION.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/mihomo-raw-subscription.txt":
            body = SUBSCRIPTION.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/slow-subscription.txt":
            type(self).slow_subscription_started.set()
            if not type(self).slow_subscription_release.wait(timeout=15):
                self.send_error(504)
                return
            body = ENCODED_SUBSCRIPTION.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/mixed-protocol-subscription.txt":
            body = ENCODED_MIXED_PROTOCOL_SUBSCRIPTION.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/xray-protocol-subscription.txt":
            body = ENCODED_XRAY_PROTOCOL_SUBSCRIPTION.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/sip008.json":
            body = SIP008_OBJECT.encode()
            content_type = "application/json; charset=utf-8"
        elif request_path == "/sip008-array.json":
            body = SIP008_ARRAY.encode()
            content_type = "application/json; charset=utf-8"
        elif request_path == "/ssr-libev.json":
            body = SSR_LIBEV_CONFIG.encode()
            content_type = "application/json; charset=utf-8"
        elif request_path == "/rules.list":
            body = RULESET.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/issue-98-rules.list":
            body = ISSUE_98_RULESET.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/rules-with-invalid.list":
            body = RULESET_WITH_INVALID_LINE.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/generation-rules.list":
            body = GENERATION_RULESET.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/slow-generation-rules.list":
            type(self).slow_ruleset_started.set()
            if not type(self).slow_ruleset_release.wait(timeout=15):
                self.send_error(504)
                return
            body = GENERATION_RULESET.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/redirect-loopback-to-remote.ini":
            self.send_response(302)
            self.send_header(
                "Location",
                f"http://target.test:{self.server.server_port}"
                "/external-valid.ini?route=loopback-to-remote",
            )
            self.end_headers()
            return
        elif request_path == "/redirect-loopback-to-suffix.ini":
            self.send_response(302)
            self.send_header(
                "Location",
                f"http://foo.127.0.0.1:{self.server.server_port}"
                "/external-valid.ini?route=loopback-to-suffix",
            )
            self.end_headers()
            return
        elif request_path == "/redirect-remote-to-loopback.ini":
            self.send_response(302)
            self.send_header(
                "Location",
                f"http://127.0.0.1:{self.server.server_port}"
                "/external-valid.ini?route=remote-to-loopback",
            )
            self.end_headers()
            return
        elif request_path == "/external-valid.ini":
            with type(self).counter_lock:
                type(self).external_valid_count += 1
            body = b"[custom]\nenable_rule_generator=false\n"
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/external-clash-generation.ini":
            host = self.headers.get("Host", "127.0.0.1")
            body = (
                "[custom]\n"
                "enable_rule_generator=true\n"
                "custom_proxy_group=Proxy`select`.*\n"
                f"ruleset=Proxy,http://{host}/issue-98-rules.list\n"
            ).encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/external-empty.ini":
            body = b""
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/external-template-failure.ini":
            body = b"[custom]\nenable_rule_generator={{ invalid\n"
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/external-template-fetch-failure.ini":
            host = self.headers.get("Host", "127.0.0.1")
            body = (
                "[custom]\n"
                "enable_rule_generator=false\n"
                f"unused={{{{ fetch(\"http://{host}/missing-template-input\") }}}}\n"
            ).encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/external-malicious-base.ini":
            host = self.headers.get("Host", "127.0.0.1")
            body = (
                "[custom]\n"
                "enable_rule_generator=false\n"
                f"clash_rule_base=http://{host}/malicious-base.yaml\n"
            ).encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/malicious-base.yaml":
            body = b'{% include "template-exception-cookie-secret.tpl" %}\n'
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/external-no-effective.ini":
            body = b"[custom]\n"
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/external-import-failure.ini":
            host = self.headers.get("Host", "127.0.0.1")
            body = (
                "[custom]\n"
                "enable_rule_generator=false\n"
                f"ruleset=!!import:http://{host}/missing-import.list\n"
            ).encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path in (
            "/external-generation.ini",
            "/external-generation-slow.ini",
        ):
            host = self.headers.get("Host", "127.0.0.1")
            rules_path = (
                "/slow-generation-rules.list"
                if request_path.endswith("-slow.ini")
                else "/generation-rules.list"
            )
            body = (
                "[custom]\n"
                "enable_rule_generator=true\n"
                f"singbox_rule_base=http://{host}/snapshot-singbox.json\n"
                f"ruleset=Proxy,http://{host}{rules_path}\n"
            ).encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/snapshot-singbox.json":
            host = self.headers.get("Host", "127.0.0.1")
            body = (
                "{\n"
                '  "snapshot_link": "{{ getLink("/snapshot") }}",\n'
                f'  "template_fetch": "{{{{ fetch("http://{host}/template-marker") }}}}",\n'
                '  "outbounds": [],\n'
                '  "route": {"rules": []}\n'
                "}\n"
            ).encode()
            content_type = "application/json; charset=utf-8"
        elif request_path == "/template-marker":
            body = b"template-ok"
            content_type = "text/plain; charset=utf-8"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _write_gist_response(self) -> None:
        type(self).gist_request_count += 1
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length:
            self.rfile.read(content_length)
        request_path = urllib.parse.urlsplit(self.path).path
        remote_failure = request_path.startswith("/failure/")
        body = (
            GIST_REMOTE_FAILURE_BODY
            if remote_failure
            else b'{"id":"fixture-gist","owner":{"login":"fixture-user"}}'
        )
        self.send_response(
            502 if remote_failure else (201 if self.command == "POST" else 200)
        )
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        request_path = urllib.parse.urlsplit(self.path).path
        if request_path not in ("/gists", "/failure/gists"):
            self.send_error(404)
            return
        self._write_gist_response()

    def do_PATCH(self) -> None:  # noqa: N802
        request_path = urllib.parse.urlsplit(self.path).path
        if not (
            request_path.startswith("/gists/")
            or request_path.startswith("/failure/gists/")
        ):
            self.send_error(404)
            return
        self._write_gist_response()

    def log_message(self, _format: str, *_args: object) -> None:
        return


class AuthenticatedProxyHandler(BaseHTTPRequestHandler):
    expected_authorization = ""
    request_hosts: list[str] = []
    request_lock = threading.Lock()

    def do_GET(self) -> None:  # noqa: N802
        if self.headers.get("Proxy-Authorization", "") != type(
            self
        ).expected_authorization:
            self.send_response(407)
            self.send_header("Proxy-Authenticate", 'Basic realm="fixture"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        target = urllib.parse.urlsplit(self.path)
        if target.scheme != "http" or target.hostname is None or target.port is None:
            self.send_error(400)
            return
        with type(self).request_lock:
            type(self).request_hosts.append(target.hostname)

        forwarded_path = urllib.parse.urlunsplit(
            ("", "", target.path or "/", target.query, "")
        )
        try:
            connection = http.client.HTTPConnection(
                "127.0.0.1", target.port, timeout=10
            )
            connection.request(
                "GET", forwarded_path, headers={"Host": target.netloc}
            )
            response = connection.getresponse()
            body = response.read()
        except OSError:
            self.send_error(502)
            return
        finally:
            if "connection" in locals():
                connection.close()

        self.send_response(response.status)
        for name, value in response.getheaders():
            if name.lower() not in {
                "connection",
                "content-length",
                "proxy-authenticate",
                "transfer-encoding",
            }:
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


@contextlib.contextmanager
def authenticated_proxy_server(username: str, password: str):
    authorization = base64.b64encode(
        f"{username}:{password}".encode("utf-8")
    ).decode("ascii")
    AuthenticatedProxyHandler.expected_authorization = "Basic " + authorization
    AuthenticatedProxyHandler.request_hosts = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), AuthenticatedProxyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield (
            f"http://{username}:{password}@127.0.0.1:{server.server_port}",
            AuthenticatedProxyHandler,
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


@contextlib.contextmanager
def fixture_server():
    FixtureHandler.gist_request_count = 0
    FixtureHandler.provider_never_fetch_count = 0
    FixtureHandler.quanx_remote_fetch_count = 0
    FixtureHandler.external_valid_count = 0
    FixtureHandler.get_request_count = 0
    FixtureHandler.slow_subscription_started.clear()
    FixtureHandler.slow_subscription_release.set()
    FixtureHandler.slow_ruleset_started.clear()
    FixtureHandler.slow_ruleset_release.set()
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        FixtureHandler.slow_subscription_release.set()
        FixtureHandler.slow_ruleset_release.set()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def unused_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def direct_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(
    base_url: str,
    path: str,
    params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    method: str = "GET",
) -> tuple[int, bytes, dict[str, str]]:
    query = urllib.parse.urlencode(params or {})
    url = base_url + path + (f"?{query}" if query else "")
    req = urllib.request.Request(url, headers=headers or {}, method=method)
    try:
        with direct_opener().open(req, timeout=20) as response:
            return (
                response.status,
                response.read(),
                {key.lower(): value for key, value in response.headers.items()},
            )
    except urllib.error.HTTPError as error:
        return (
            error.code,
            error.read(),
            {key.lower(): value for key, value in error.headers.items()},
        )


def assert_vary_header(
    headers: dict[str, str], field: str, context: str
) -> None:
    vary = {
        value.strip().lower()
        for value in headers.get("vary", "").split(",")
        if value.strip()
    }
    if field.lower() not in vary:
        raise AssertionError(f"{context} is missing Vary: {field}")


def assert_request_id(headers: dict[str, str], context: str) -> str:
    request_id = headers.get("x-request-id", "")
    if re.fullmatch(r"[0-9a-f]{32}", request_id) is None:
        raise AssertionError(f"{context} has an invalid X-Request-ID: {request_id!r}")
    exposed = {
        value.strip().lower()
        for value in headers.get("access-control-expose-headers", "").split(",")
        if value.strip()
    }
    if "x-request-id" not in exposed:
        raise AssertionError(f"{context} does not expose X-Request-ID")
    return request_id


def assert_coalesced_request_link(
    diagnostics: str, response_ids: list[str], context: str
) -> None:
    ids = set(response_ids)
    links = re.findall(
        r"request_id=([0-9a-f]{32}) SUB_REQUEST_COALESCED "
        r"owner_request_id=([0-9a-f]{32})",
        diagnostics,
    )
    if not any(waiter in ids and owner in ids and waiter != owner for waiter, owner in links):
        raise AssertionError(
            f"{context} did not link a waiter request ID to its owner: {links!r}"
        )


def has_exact_log_event(diagnostics: str, event: str) -> bool:
    return any(line.rstrip().endswith(event) for line in diagnostics.splitlines())


def request_with_raw_headers(
    base_url: str, path: str, headers: list[tuple[str, str]]
) -> int:
    parsed = urllib.parse.urlsplit(base_url)
    with socket.create_connection((parsed.hostname, parsed.port), timeout=20) as sock:
        request_lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {parsed.hostname}:{parsed.port}",
            "Connection: close",
        ]
        request_lines.extend(f"{name}: {value}" for name, value in headers)
        sock.sendall(("\r\n".join(request_lines) + "\r\n\r\n").encode("ascii"))
        response = b""
        while b"\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
    status_line = response.split(b"\r\n", 1)[0].decode("ascii", "replace")
    try:
        return int(status_line.split(" ", 2)[1])
    except (IndexError, ValueError) as error:
        raise AssertionError(f"invalid raw HTTP response: {status_line!r}") from error


def wait_ready(base_url: str, process: subprocess.Popen[bytes]) -> None:
    for _ in range(100):
        if process.poll() is not None:
            raise AssertionError(
                f"service exited before readiness with {process.returncode}"
            )
        try:
            status, body, _ = request(base_url, "/healthz")
            if status == 200 and body.strip() == b"ok":
                return
        except OSError:
            pass
        time.sleep(0.1)
    raise AssertionError("service did not become ready")


def describe_process_returncode(returncode: int | None) -> str:
    if returncode is None:
        return "running"
    if returncode < 0:
        try:
            return f"{returncode} ({signal.Signals(-returncode).name})"
        except ValueError:
            pass
    if returncode >= 128:
        try:
            return f"{returncode} (128+{signal.Signals(returncode - 128).name})"
        except ValueError:
            pass
    return str(returncode)


@contextlib.contextmanager
def running_service(
    binary: Path,
    *,
    statistics: bool = False,
    security_profile: str = "lan",
    allow_public_upload: bool = False,
    listen_address: str = "127.0.0.1",
    extra_args: tuple[str, ...] = (),
    runtime_details: bool = False,
    legacy_statistics: bool = False,
    invalid_statistics_path: bool = False,
    fallback_to_default_external_config: bool = False,
    default_external_config: str | None = None,
    legacy_publish_enabled: bool = False,
    proxy_provider_interval: int | None = None,
    proxy_provider_direct: bool | None = None,
    dashboard_client_ip_header: str | None = None,
    dashboard_trusted_proxy_cidrs: tuple[str, ...] = (),
    gist_api_base: str | None = None,
    gist_config_text: str | None = GIST_FIXTURE_CONFIG,
    gist_config_hardlink_failure: bool = False,
    log_capture: list[str] | None = None,
    log_level: str = "info",
    config_replacements: tuple[tuple[str, str], ...] = (),
    pref_path_capture: list[Path] | None = None,
):
    port = unused_port()
    baseline = (COMPAT_FIXTURES / "legacy-pref.toml").read_text(
        encoding="utf-8"
    )
    base_path = (REPOSITORY / "base" / "base").as_posix()
    baseline = baseline.replace('base_path = "base"', f'base_path = "{base_path}"')
    baseline = baseline.replace(
        '"base/all_base.tpl"', f'"{base_path}/all_base.tpl"'
    )
    baseline = baseline.replace(
        'template_path = "template"', f'template_path = "{base_path}/templates"'
    )
    baseline = baseline.replace(
        'proxy_config = "socks5h://fixture-user:fixture-secret@proxy.example.test:1080"',
        'proxy_config = "NONE"',
    )
    if legacy_publish_enabled:
        baseline = baseline.replace(
            "publish_enabled = false", "publish_enabled = true"
        )
    if proxy_provider_interval is not None or proxy_provider_direct is not None:
        provider_settings = ["[proxy_provider]"]
        if proxy_provider_interval is not None:
            provider_settings.append(f"interval = {proxy_provider_interval}")
        if proxy_provider_direct is not None:
            provider_settings.append(
                f"proxy_direct = {str(proxy_provider_direct).lower()}"
            )
        baseline = baseline.replace(
            "[custom_openclash_rules]",
            "\n".join(provider_settings)
            + "\n\n"
            "[custom_openclash_rules]",
            1,
        )
    if default_external_config is not None:
        baseline = baseline.replace(
            'default_external_config = "data:,enable_rule_generator=false"',
            "default_external_config = "
            + json.dumps(default_external_config),
        )
    if fallback_to_default_external_config:
        baseline = baseline.replace(
            "append_proxy_type = false",
            "fallback_to_default_external_config = true\n"
            "append_proxy_type = false",
            1,
        )
    if dashboard_client_ip_header is not None or dashboard_trusted_proxy_cidrs:
        header = dashboard_client_ip_header or "none"
        client_ip_section = (
            "lock_seconds = 60\n\n"
            "[statistics.dashboard_auth.client_ip]\n"
            f"header = {json.dumps(header)}\n"
            "trusted_proxy_cidrs = "
            f"{json.dumps(list(dashboard_trusted_proxy_cidrs))}"
        )
        baseline = baseline.replace("lock_seconds = 60", client_ip_section, 1)
    baseline = baseline.replace('proxy_subscription = "SYSTEM"', 'proxy_subscription = "NONE"')
    baseline = baseline.replace('log_level = "info"', f'log_level = "{log_level}"')
    baseline = baseline.replace('enabled = true\n', f"enabled = {str(statistics).lower()}\n", 1)
    baseline = baseline.replace('profile = "lan"', f'profile = "{security_profile}"')
    baseline = baseline.replace(
        "allow_public_upload = false",
        f"allow_public_upload = {str(allow_public_upload).lower()}",
    )
    baseline = baseline.replace(
        'listen = "127.0.0.1"', f'listen = "{listen_address}"'
    )
    for original, replacement in config_replacements:
        if original not in baseline:
            raise AssertionError(
                f"runtime configuration replacement source is missing: {original!r}"
            )
        baseline = baseline.replace(original, replacement, 1)
    runtime_dir = REPOSITORY / "build" / "test-baseline-runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=runtime_dir) as temporary:
        temporary_path = Path(temporary)
        statistics_path = temporary_path / "stats"
        stats_path = statistics_path.as_posix()
        baseline = baseline.replace('data_dir = "stats"', f'data_dir = "{stats_path}"')
        if legacy_statistics:
            statistics_path.mkdir(parents=True, exist_ok=True)
            (statistics_path / "statistics.json").write_text(
                '{"schema":4,"legacy":true}',
                encoding="utf-8",
            )
        elif invalid_statistics_path:
            statistics_path.write_text("not a directory", encoding="utf-8")
        pref = temporary_path / "pref.toml"
        pref.write_text(baseline, encoding="utf-8", newline="\n")
        if pref_path_capture is not None:
            pref_path_capture.append(pref)
        stdout_path = temporary_path / "stdout.log"
        stderr_path = temporary_path / "stderr.log"
        stdout = stdout_path.open("wb")
        stderr = stderr_path.open("wb")
        if gist_api_base is not None and gist_config_text is not None:
            gist_config = temporary_path / "gistconf.ini"
            gist_config.write_text(gist_config_text, encoding="utf-8", newline="\n")
            if gist_config_hardlink_failure:
                os.link(gist_config, temporary_path / "gistconf-hardlink.ini")
        env = os.environ.copy()
        env.pop("SUBCONVERTER_DASHBOARD_CLIENT_IP_HEADER", None)
        env.pop("SUBCONVERTER_DASHBOARD_TRUSTED_PROXY_CIDRS", None)
        env.pop("SUBCONVERTER_SECURITY_PROFILE", None)
        env.pop("SUBCONVERTER_ALLOW_PUBLIC_UPLOAD", None)
        env.pop("SUBCONVERTER_GIST_API_BASE", None)
        if gist_api_base is not None:
            env["SUBCONVERTER_GIST_API_BASE"] = gist_api_base
        env["PORT"] = str(port)
        env["NO_PROXY"] = "127.0.0.1,localhost"
        env["no_proxy"] = "127.0.0.1,localhost"
        process = subprocess.Popen(
            [str(binary), *extra_args, "-f", str(pref)],
            cwd=temporary_path if gist_api_base is not None else REPOSITORY,
            env=env,
            stdout=stdout,
            stderr=stderr,
        )
        base_url = f"http://127.0.0.1:{port}"
        body_error: BaseException | None = None
        try:
            try:
                wait_ready(base_url, process)
            except Exception as error:
                stderr.flush()
                diagnostics = stderr_path.read_text(
                    encoding="utf-8", errors="replace"
                )
                raise AssertionError(
                    f"{error}; service stderr tail: {diagnostics[-8000:]!r}"
                ) from error
            yield (
                (base_url, statistics_path)
                if runtime_details
                else base_url
            )
        except BaseException as error:
            body_error = error
            raise
        finally:
            shutdown_error: AssertionError | None = None
            terminate_sent = False
            if process.poll() is None:
                try:
                    process.terminate()
                    terminate_sent = True
                except ProcessLookupError:
                    # The child exited between poll() and terminate(). wait()
                    # below records its real exit status and reports it with
                    # the accurate pre-cleanup phase.
                    pass
            try:
                returncode = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                try:
                    cleanup_returncode = process.wait(timeout=5)
                    cleanup_result = describe_process_returncode(cleanup_returncode)
                except subprocess.TimeoutExpired:
                    cleanup_result = "still running after cleanup SIGKILL"
                shutdown_error = AssertionError(
                    "service did not exit within 10 seconds after normal "
                    "termination; SIGKILL was cleanup only and returned "
                    f"{cleanup_result}"
                )
            else:
                # POSIX Popen.terminate() is SIGTERM and exercises the service's
                # graceful path. Windows TerminateProcess has no corresponding
                # graceful-exit contract, so the dedicated signal matrix is
                # registered only on UNIX.
                if os.name == "posix" and returncode != 0:
                    exit_phase = (
                        "after SIGTERM"
                        if terminate_sent
                        else "before normal cleanup could send SIGTERM"
                    )
                    shutdown_error = AssertionError(
                        "service returned "
                        f"{describe_process_returncode(returncode)} {exit_phase}; "
                        "expected exit 0"
                    )
            stdout.close()
            stderr.close()
            diagnostics = stderr_path.read_text(
                encoding="utf-8", errors="replace"
            )
            if log_capture is not None:
                log_capture.append(diagnostics)
            if shutdown_error is not None:
                detail = (
                    f"{shutdown_error}; service stderr tail: "
                    f"{diagnostics[-8000:]!r}"
                )
                if body_error is None:
                    raise AssertionError(detail) from shutdown_error
                if hasattr(body_error, "add_note"):
                    body_error.add_note("service shutdown also failed: " + detail)
                else:
                    print("service shutdown also failed: " + detail, file=sys.stderr)


def run_settings_snapshot(
    helper: Path,
    fixture: Path,
    environment: dict[str, str] | None = None,
) -> tuple[dict[str, object], str]:
    env = os.environ.copy() if environment is None else environment.copy()
    for name in (
        "SUBCONVERTER_DASHBOARD_CLIENT_IP_HEADER",
        "SUBCONVERTER_DASHBOARD_TRUSTED_PROXY_CIDRS",
        "SUBCONVERTER_SECURITY_PROFILE",
        "SUBCONVERTER_ALLOW_PUBLIC_UPLOAD",
    ):
        if environment is None:
            env.pop(name, None)
    completed = subprocess.run(
        [str(helper), str(fixture)],
        cwd=REPOSITORY,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    if completed.returncode != 0:
        raise AssertionError(
            "settings snapshot helper failed with "
            f"exit {completed.returncode}; stderr tail: "
            f"{completed.stderr[-8000:]!r}"
        )
    if "fixture-secret" in completed.stdout or "fixture-dashboard-secret" in completed.stdout:
        raise AssertionError("SettingsSnapshot leaked a fixture secret")
    return json.loads(completed.stdout), completed.stderr


def load_settings_snapshot(
    helper: Path,
    fixture: Path,
    environment: dict[str, str] | None = None,
) -> dict[str, object]:
    snapshot, _ = run_settings_snapshot(helper, fixture, environment)
    return snapshot


def early_log_level_parsing_baseline(helper: Path) -> None:
    replacements = {
        ".ini": (("log_level=info", "log_level=error"),
                 ("print_debug_info=false", "print_debug_info=true")),
        ".yml": (("  log_level: info", "  log_level: error"),
                 ("  print_debug_info: false", "  print_debug_info: true")),
        ".toml": (('log_level = "info"', 'log_level = "error"'),
                  ("print_debug_info = false", "print_debug_info = true")),
    }
    with tempfile.TemporaryDirectory(
        dir=REPOSITORY / "build", prefix="log-level-baseline-"
    ) as temporary:
        temporary_path = Path(temporary)
        text_import = temporary_path / "early-emoji.txt"
        text_import.write_text(
            "EarlyImport,\U0001f50e\n", encoding="utf-8", newline="\n"
        )
        toml_import = temporary_path / "early-emoji.toml"
        toml_import.write_text(
            '[[emoji]]\nmatch = "EarlyImport"\nemoji = "\U0001f50e"\n',
            encoding="utf-8",
            newline="\n",
        )

        def with_real_import(content: str, suffix: str) -> str:
            if suffix == ".ini":
                return (
                    content
                    + "\n[emojis]\nadd_emoji=false\nremove_old_emoji=false\n"
                    + f"rule=!!import:{text_import.as_posix()}\n"
                )
            if suffix == ".yml":
                return (
                    content
                    + "\nemojis:\n  add_emoji: false\n"
                    + "  remove_old_emoji: false\n  rules:\n"
                    + f"    - {{import: {json.dumps(text_import.as_posix())}}}\n"
                )
            if suffix == ".toml":
                marker = "remove_old_emoji = false"
                if marker not in content:
                    raise AssertionError("TOML emoji insertion marker is missing")
                return content.replace(
                    marker,
                    marker
                    + "\nemoji = [{ import = "
                    + json.dumps(toml_import.as_posix())
                    + " }]",
                    1,
                )
            raise AssertionError(f"unsupported config suffix: {suffix}")

        for fixture_name in (
            "legacy-pref.ini",
            "legacy-pref.yml",
            "legacy-pref.toml",
        ):
            fixture = COMPAT_FIXTURES / fixture_name
            content = fixture.read_text(encoding="utf-8")
            log_replacement, debug_replacement = replacements[fixture.suffix]
            if log_replacement[0] not in content or debug_replacement[0] not in content:
                raise AssertionError(
                    f"log-level fixture fields are missing from {fixture_name}"
                )

            imported_content = with_real_import(content, fixture.suffix)
            error_fixture = temporary_path / ("error-" + fixture_name)
            error_fixture.write_text(
                imported_content.replace(*log_replacement, 1),
                encoding="utf-8",
                newline="\n",
            )
            error_snapshot, error_logs = run_settings_snapshot(helper, error_fixture)
            if error_snapshot["node_pref"]["emoji_rule_count"] != 1:
                raise AssertionError(
                    f"{fixture.suffix} did not execute the real pre-advanced import"
                )
            if "[VERB]" in error_logs or "正在导入项目：" in error_logs:
                raise AssertionError(
                    f"{fixture.suffix} applied log_level after import diagnostics"
                )
            if "已加载 " in error_logs:
                raise AssertionError(
                    f"{fixture.suffix} did not apply log_level=error"
                )

            debug_fixture = temporary_path / ("debug-" + fixture_name)
            debug_fixture.write_text(
                imported_content.replace(*log_replacement, 1).replace(
                    *debug_replacement, 1
                ),
                encoding="utf-8",
                newline="\n",
            )
            debug_snapshot, debug_logs = run_settings_snapshot(helper, debug_fixture)
            if debug_snapshot["node_pref"]["emoji_rule_count"] != 1:
                raise AssertionError(
                    f"{fixture.suffix} debug load skipped the real import"
                )
            if (
                "LOG_LEVEL_CONFIGURED level=verbose "
                "print_debug_info=true phase=pre-import"
                not in debug_logs
                or "正在导入项目：" not in debug_logs
                or "已导入 1 个项目。" not in debug_logs
            ):
                raise AssertionError(
                    f"{fixture.suffix} print_debug_info did not enable early verbose logs"
                )

            invalid_value = '"none"' if fixture.suffix == ".toml" else "none"
            invalid_fixture = temporary_path / ("invalid-reload-" + fixture_name)
            invalid_fixture.write_text(
                add_proxy_provider_direct(
                    imported_content.replace(*log_replacement, 1),
                    fixture.suffix,
                    invalid_value,
                ),
                encoding="utf-8",
                newline="\n",
            )
            _, reload_logs = run_reload_settings_snapshot(
                helper, debug_fixture, invalid_fixture, expect_failure=True
            )
            if "SETTINGS_RELOAD_LEVEL_PROBE" not in reload_logs:
                raise AssertionError(
                    f"{fixture.suffix} failed reload did not restore verbose logging"
                )


def run_reload_settings_snapshot(
    helper: Path,
    first: Path,
    second: Path,
    *,
    expect_failure: bool = False,
) -> tuple[dict[str, object], str]:
    command = [str(helper), str(first), str(second)]
    if expect_failure:
        command.append("--expect-reload-failure")
    env = os.environ.copy()
    for name in (
        "SUBCONVERTER_DASHBOARD_CLIENT_IP_HEADER",
        "SUBCONVERTER_DASHBOARD_TRUSTED_PROXY_CIDRS",
        "SUBCONVERTER_SECURITY_PROFILE",
        "SUBCONVERTER_ALLOW_PUBLIC_UPLOAD",
    ):
        env.pop(name, None)
    completed = subprocess.run(
        command,
        cwd=REPOSITORY,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    if completed.returncode != 0:
        raise AssertionError(
            "settings reload helper failed with "
            f"exit {completed.returncode}; stderr tail: "
            f"{completed.stderr[-8000:]!r}"
        )
    return json.loads(completed.stdout), completed.stderr


def reload_settings_snapshot(
    helper: Path,
    first: Path,
    second: Path,
    *,
    expect_failure: bool = False,
) -> dict[str, object]:
    snapshot, _ = run_reload_settings_snapshot(
        helper, first, second, expect_failure=expect_failure
    )
    return snapshot


def security_environment() -> dict[str, str]:
    env = os.environ.copy()
    for name in (
        "SUBCONVERTER_DASHBOARD_CLIENT_IP_HEADER",
        "SUBCONVERTER_DASHBOARD_TRUSTED_PROXY_CIDRS",
        "SUBCONVERTER_SECURITY_PROFILE",
        "SUBCONVERTER_ALLOW_PUBLIC_UPLOAD",
    ):
        env.pop(name, None)
    return env


def replace_security_profile(
    content: str, suffix: str, value: str | None
) -> str:
    patterns = {
        ".ini": r"(?m)^profile=.*\n?",
        ".yml": r"(?m)^  profile:.*\n?",
        ".toml": r'(?m)^profile\s*=.*\n?',
    }
    replacements = {
        ".ini": "" if value is None else f"profile={value}\n",
        ".yml": "" if value is None else f"  profile: {value}\n",
        ".toml": "" if value is None else f'profile = "{value}"\n',
    }
    pattern = patterns.get(suffix)
    if pattern is None:
        raise AssertionError(f"unsupported config suffix: {suffix}")
    updated, count = re.subn(pattern, replacements[suffix], content, count=1)
    if count != 1:
        raise AssertionError(f"security profile line missing: {suffix}")
    return updated


def security_configuration_matrix_baseline(helper: Path) -> None:
    runtime_dir = REPOSITORY / "build" / "test-baseline-runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=runtime_dir) as temporary:
        temporary_path = Path(temporary)
        fixtures = (
            COMPAT_FIXTURES / "legacy-pref.ini",
            COMPAT_FIXTURES / "legacy-pref.yml",
            COMPAT_FIXTURES / "legacy-pref.toml",
        )
        for original in fixtures:
            original_content = original.read_text(encoding="utf-8")
            source = "file:yaml" if original.suffix == ".yml" else (
                "file:" + original.suffix.removeprefix(".")
            )
            for configured, expected in (
                (None, "lan"),
                ("lan", "lan"),
                ("public", "public"),
                ("strict", "strict"),
                ("publci", "lan"),
            ):
                label = "missing" if configured is None else configured
                candidate = temporary_path / f"{original.stem}-{label}{original.suffix}"
                candidate.write_text(
                    replace_security_profile(
                        original_content, original.suffix, configured
                    ),
                    encoding="utf-8",
                    newline="\n",
                )
                snapshot, logs = run_settings_snapshot(helper, candidate)
                actual = snapshot["security"]["profile"]
                if actual != expected:
                    raise AssertionError(
                        f"{original.suffix} profile={label} became {actual}, "
                        f"expected {expected}"
                    )
                expected_source = "builtin-default" if configured is None else source
                event = (
                    f"SECURITY_PROFILE_EFFECTIVE profile={expected} "
                    f"source={expected_source}"
                )
                if event not in logs:
                    raise AssertionError(
                        f"{original.suffix} profile={label} source log missing: "
                        f"{logs!r}"
                    )
                invalid_event = "SECURITY_PROFILE_INVALID_FALLBACK"
                if configured == "publci":
                    if (
                        f"{invalid_event} source={source}" not in logs
                        or "effective=lan compatibility_fallback=true" not in logs
                    ):
                        raise AssertionError(
                            f"{original.suffix} invalid profile fallback was not "
                            f"observable: {logs!r}"
                        )
                elif invalid_event in logs:
                    raise AssertionError(
                        f"{original.suffix} valid profile emitted invalid warning"
                    )

            public_file = temporary_path / f"{original.stem}-env{original.suffix}"
            public_file.write_text(
                replace_security_profile(
                    original_content, original.suffix, "public"
                ),
                encoding="utf-8",
                newline="\n",
            )
            env = security_environment()
            env["SUBCONVERTER_SECURITY_PROFILE"] = "strict"
            snapshot, logs = run_settings_snapshot(helper, public_file, env)
            if snapshot["security"]["profile"] != "strict" or (
                "SECURITY_PROFILE_EFFECTIVE profile=strict source=environment "
                f"file_candidate={source}"
            ) not in logs:
                raise AssertionError(
                    f"{original.suffix} environment profile did not override file"
                )

            env["SUBCONVERTER_SECURITY_PROFILE"] = "publci'\nforged-event\\tail"
            snapshot, logs = run_settings_snapshot(helper, public_file, env)
            if snapshot["security"]["profile"] != "lan" or (
                "SECURITY_PROFILE_INVALID_FALLBACK source=environment "
                "input='publci\\x27\\x0Aforged-event\\x5Ctail'"
            ) not in logs:
                raise AssertionError(
                    f"{original.suffix} invalid environment profile fallback or "
                    "log escaping changed"
                )

            env = security_environment()
            env["SUBCONVERTER_SECURITY_PROFILE"] = "public"
            env["SUBCONVERTER_ALLOW_PUBLIC_UPLOAD"] = "true"
            snapshot, _ = run_settings_snapshot(helper, public_file, env)
            if not snapshot["security"]["allow_public_upload"]:
                raise AssertionError(
                    f"{original.suffix} upload environment override was ignored"
                )

            env["SUBCONVERTER_ALLOW_PUBLIC_UPLOAD"] = "truthy"
            snapshot, logs = run_settings_snapshot(helper, public_file, env)
            if snapshot["security"]["allow_public_upload"] or (
                "SECURITY_UPLOAD_VALUE_INVALID source=environment "
                "input='truthy' effective=false"
            ) not in logs:
                raise AssertionError(
                    f"{original.suffix} invalid upload environment behavior changed"
                )

            missing_file = temporary_path / f"{original.stem}-reload{original.suffix}"
            missing_file.write_text(
                replace_security_profile(original_content, original.suffix, None),
                encoding="utf-8",
                newline="\n",
            )
            reloaded = reload_settings_snapshot(helper, public_file, missing_file)
            if reloaded["security"]["profile"] != "public":
                raise AssertionError(
                    f"{original.suffix} reload no longer retains a removed profile"
                )


def deployment_security_defaults_baseline() -> None:
    expected_profile_lines = {
        REPOSITORY / "base" / "pref.example.ini": "profile=lan",
        REPOSITORY / "base" / "pref.example.yml": "  profile: lan",
        REPOSITORY / "base" / "pref.example.toml": 'profile = "lan"',
    }
    expected_upload_lines = {
        ".ini": "allow_public_upload=false",
        ".yml": "  allow_public_upload: false",
        ".toml": "allow_public_upload = false",
    }
    for path, profile_line in expected_profile_lines.items():
        lines = path.read_text(encoding="utf-8").splitlines()
        if profile_line not in lines or expected_upload_lines[path.suffix] not in lines:
            raise AssertionError(
                f"deployment example defaults changed in {path.name}"
            )

    dockerfile = (REPOSITORY / "Dockerfile").read_text(encoding="utf-8")
    if (
        "COPY --from=builder /src/base /base/" not in dockerfile
        or "cp /base/pref.example.toml \"$CONF\"" not in dockerfile
    ):
        raise AssertionError(
            "Docker image no longer bootstraps pref.toml from the TOML example"
        )

    compose = (REPOSITORY / "docker-compose.yml").read_text(encoding="utf-8")
    active_compose = "\n".join(
        line for line in compose.splitlines() if not line.lstrip().startswith("#")
    )
    if '- "25500:25500/tcp"' not in active_compose:
        raise AssertionError("Compose default port publication changed")
    if re.search(
        r"(?m)^\s*SUBCONVERTER_SECURITY_PROFILE\s*:", active_compose
    ):
        raise AssertionError("Compose started forcing a security profile")


def add_proxy_provider_interval(
    content: str, suffix: str, value: str
) -> str:
    if suffix == ".ini":
        marker = "\n[custom_openclash_rules]"
        section = f"\n[proxy_provider]\ninterval={value}\n"
    elif suffix == ".yml":
        marker = "\ncustom_openclash_rules:"
        section = f"\nproxy_provider:\n  interval: {value}\n"
    elif suffix == ".toml":
        marker = "\n[custom_openclash_rules]"
        section = f"\n[proxy_provider]\ninterval = {value}\n"
    else:
        raise AssertionError(f"unsupported config suffix: {suffix}")
    if marker not in content:
        raise AssertionError(f"provider interval insertion marker missing: {suffix}")
    return content.replace(marker, section + marker, 1)


def add_dashboard_client_ip(
    content: str, suffix: str, header: str, cidrs: list[str]
) -> str:
    if suffix == ".ini":
        marker = "\n[security]"
        section = (
            f"dashboard_auth_client_ip_header={header}\n"
            "dashboard_auth_trusted_proxy_cidrs=" + ",".join(cidrs) + "\n\n"
        )
    elif suffix == ".yml":
        marker = "\nsecurity:"
        cidr_lines = "\n".join(f"        - {json.dumps(cidr)}" for cidr in cidrs)
        section = (
            "    client_ip:\n"
            f"      header: {json.dumps(header)}\n"
            "      trusted_proxy_cidrs:\n"
            f"{cidr_lines}\n"
        )
    elif suffix == ".toml":
        marker = "\n[security]"
        section = (
            "[statistics.dashboard_auth.client_ip]\n"
            f"header = {json.dumps(header)}\n"
            f"trusted_proxy_cidrs = {json.dumps(cidrs)}\n\n"
        )
    else:
        raise AssertionError(f"unsupported config suffix: {suffix}")
    if marker not in content:
        raise AssertionError(f"dashboard client IP insertion marker missing: {suffix}")
    return content.replace(marker, "\n" + section + marker.lstrip("\n"), 1)


def settings_dashboard_client_ip_baseline(helper: Path) -> None:
    runtime_dir = REPOSITORY / "build" / "test-baseline-runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    configured_snapshots: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(dir=runtime_dir) as temporary:
        temporary_path = Path(temporary)
        for fixture_name in (
            "legacy-pref.ini",
            "legacy-pref.yml",
            "legacy-pref.toml",
        ):
            original = COMPAT_FIXTURES / fixture_name
            content = original.read_text(encoding="utf-8")
            configured = temporary_path / ("client-ip-" + fixture_name)
            configured.write_text(
                add_dashboard_client_ip(
                    content,
                    original.suffix,
                    "X-FoRwArDeD-FoR",
                    ["127.0.0.1/32", "2001:db8::/32"],
                ),
                encoding="utf-8",
                newline="\n",
            )
            snapshot = load_settings_snapshot(helper, configured)
            configured_snapshots.append(snapshot)
            statistics = snapshot["statistics"]
            if (
                statistics["dashboard_client_ip_header"] != "x-forwarded-for"
                or statistics["dashboard_trusted_proxy_count"] != 2
            ):
                raise AssertionError(
                    f"{original.suffix} did not load dashboard client-IP policy"
                )

            reloaded = reload_settings_snapshot(helper, configured, original)
            if (
                reloaded["statistics"]["dashboard_client_ip_header"] != "none"
                or reloaded["statistics"]["dashboard_trusted_proxy_count"] != 0
            ):
                raise AssertionError(
                    f"{original.suffix} reload retained removed client-IP settings"
                )

            for label, invalid_header, invalid_cidrs in (
                ("header", "x-client-ip", ["127.0.0.1/32"]),
                ("cidr", "x-forwarded-for", ["0.0.0.0/0"]),
            ):
                invalid = temporary_path / (f"invalid-{label}-" + fixture_name)
                invalid.write_text(
                    add_dashboard_client_ip(
                        content, original.suffix, invalid_header, invalid_cidrs
                    ),
                    encoding="utf-8",
                    newline="\n",
                )
                startup = subprocess.run(
                    [str(helper), str(invalid)],
                    cwd=REPOSITORY,
                    check=False,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    env={
                        key: value
                        for key, value in os.environ.items()
                        if key
                        not in {
                            "SUBCONVERTER_DASHBOARD_CLIENT_IP_HEADER",
                            "SUBCONVERTER_DASHBOARD_TRUSTED_PROXY_CIDRS",
                        }
                    },
                )
                if startup.returncode == 0:
                    raise AssertionError(
                        f"{original.suffix} accepted invalid client-IP {label}"
                    )
                retained = reload_settings_snapshot(
                    helper, configured, invalid, expect_failure=True
                )
                if (
                    retained["statistics"]["dashboard_client_ip_header"]
                    != "x-forwarded-for"
                    or retained["statistics"]["dashboard_trusted_proxy_count"] != 2
                ):
                    raise AssertionError(
                        f"{original.suffix} invalid reload replaced valid policy"
                    )

        if configured_snapshots[1:] != configured_snapshots[:1] * 2:
            raise AssertionError("INI/YAML/TOML dashboard client-IP snapshots differ")

        env = os.environ.copy()
        env["SUBCONVERTER_DASHBOARD_CLIENT_IP_HEADER"] = "cf-connecting-ip"
        env["SUBCONVERTER_DASHBOARD_TRUSTED_PROXY_CIDRS"] = (
            "127.0.0.1/32, 2001:db8::/32"
        )
        snapshot = load_settings_snapshot(
            helper, COMPAT_FIXTURES / "legacy-pref.toml", env
        )
        if (
            snapshot["statistics"]["dashboard_client_ip_header"]
            != "cf-connecting-ip"
            or snapshot["statistics"]["dashboard_trusted_proxy_count"] != 2
        ):
            raise AssertionError("dashboard client-IP environment overrides failed")


def settings_provider_interval_compatibility_baseline(helper: Path) -> None:
    runtime_dir = REPOSITORY / "build" / "test-baseline-runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    configured_snapshots: dict[int, list[dict[str, object]]] = {
        0: [],
        7200: [],
    }
    with tempfile.TemporaryDirectory(dir=runtime_dir) as temporary:
        temporary_path = Path(temporary)
        for fixture_name in (
            "legacy-pref.ini",
            "legacy-pref.yml",
            "legacy-pref.toml",
        ):
            original = COMPAT_FIXTURES / fixture_name
            content = original.read_text(encoding="utf-8")
            for expected in configured_snapshots:
                configured = temporary_path / (
                    f"configured-{expected}-" + fixture_name
                )
                configured.write_text(
                    add_proxy_provider_interval(
                        content, original.suffix, str(expected)
                    ),
                    encoding="utf-8",
                    newline="\n",
                )
                configured_snapshot = load_settings_snapshot(helper, configured)
                configured_snapshots[expected].append(configured_snapshot)
                if configured_snapshot["proxy_provider"]["interval"] != expected:
                    raise AssertionError(
                        f"{original.suffix} did not load "
                        f"proxy_provider.interval={expected}"
                    )

                reloaded = reload_settings_snapshot(helper, configured, original)
                if reloaded["proxy_provider"]["interval"] != 3600:
                    raise AssertionError(
                        f"{original.suffix} hot reload retained a removed "
                        "provider interval"
                    )

            invalid = temporary_path / ("invalid-" + fixture_name)
            invalid_value = '"none"' if original.suffix == ".toml" else "none"
            invalid.write_text(
                add_proxy_provider_interval(
                    content, original.suffix, invalid_value
                ),
                encoding="utf-8",
                newline="\n",
            )
            startup = subprocess.run(
                [str(helper), str(invalid)],
                cwd=REPOSITORY,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=security_environment(),
            )
            if startup.returncode == 0:
                raise AssertionError(
                    f"{original.suffix} accepted an invalid provider interval"
                )
            retained = reload_settings_snapshot(
                helper, original, invalid, expect_failure=True
            )
            if retained["proxy_provider"]["interval"] != 3600:
                raise AssertionError(
                    f"{original.suffix} invalid reload replaced valid settings"
                )

    for expected, snapshots in configured_snapshots.items():
        if snapshots[1:] != snapshots[:1] * 2:
            raise AssertionError(
                "INI/YAML/TOML provider interval snapshots differ for "
                f"interval={expected}"
            )


def add_proxy_provider_direct(content: str, suffix: str, value: str) -> str:
    if suffix == ".ini":
        marker = "\n[custom_openclash_rules]"
        section = f"\n[proxy_provider]\nproxy_direct={value}\n"
    elif suffix == ".yml":
        marker = "\ncustom_openclash_rules:"
        section = f"\nproxy_provider:\n  proxy_direct: {value}\n"
    elif suffix == ".toml":
        marker = "\n[custom_openclash_rules]"
        section = f"\n[proxy_provider]\nproxy_direct = {value}\n"
    else:
        raise AssertionError(f"unsupported config suffix: {suffix}")
    if marker not in content:
        raise AssertionError(f"provider direct insertion marker missing: {suffix}")
    return content.replace(marker, section + marker, 1)


def settings_provider_direct_compatibility_baseline(helper: Path) -> None:
    runtime_dir = REPOSITORY / "build" / "test-baseline-runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    configured_snapshots: dict[bool, list[dict[str, object]]] = {
        True: [],
        False: [],
    }
    with tempfile.TemporaryDirectory(dir=runtime_dir) as temporary:
        temporary_path = Path(temporary)
        for fixture_name in (
            "legacy-pref.ini",
            "legacy-pref.yml",
            "legacy-pref.toml",
        ):
            original = COMPAT_FIXTURES / fixture_name
            content = original.read_text(encoding="utf-8")
            configured_paths: dict[bool, Path] = {}
            for expected in configured_snapshots:
                configured = temporary_path / (
                    f"configured-direct-{str(expected).lower()}-" + fixture_name
                )
                configured_paths[expected] = configured
                configured.write_text(
                    add_proxy_provider_direct(
                        content, original.suffix, str(expected).lower()
                    ),
                    encoding="utf-8",
                    newline="\n",
                )
                configured_snapshot = load_settings_snapshot(helper, configured)
                configured_snapshots[expected].append(configured_snapshot)
                if (
                    configured_snapshot["proxy_provider"]["proxy_direct"]
                    is not expected
                ):
                    raise AssertionError(
                        f"{original.suffix} did not load "
                        f"proxy_provider.proxy_direct={expected}"
                    )

                reloaded = reload_settings_snapshot(helper, configured, original)
                if reloaded["proxy_provider"]["proxy_direct"] is not True:
                    raise AssertionError(
                        f"{original.suffix} hot reload retained a removed "
                        "provider proxy_direct value"
                    )

            invalid = temporary_path / ("invalid-direct-" + fixture_name)
            invalid_value = '"none"' if original.suffix == ".toml" else "none"
            invalid.write_text(
                add_proxy_provider_direct(content, original.suffix, invalid_value),
                encoding="utf-8",
                newline="\n",
            )
            startup = subprocess.run(
                [str(helper), str(invalid)],
                cwd=REPOSITORY,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if startup.returncode == 0:
                raise AssertionError(
                    f"{original.suffix} accepted an invalid provider proxy_direct"
                )
            retained = reload_settings_snapshot(
                helper, configured_paths[False], invalid, expect_failure=True
            )
            if retained["proxy_provider"]["proxy_direct"] is not False:
                raise AssertionError(
                    f"{original.suffix} invalid reload did not retain false"
                )

    for expected, snapshots in configured_snapshots.items():
        if snapshots[1:] != snapshots[:1] * 2:
            raise AssertionError(
                "INI/YAML/TOML provider direct snapshots differ for "
                f"proxy_direct={expected}"
            )


def runtime_cli_isolation_baseline(binary: Path) -> None:
    binary_content = binary.read_bytes()
    for marker in (
        b"--settings-snapshot",
        b"--inject-invariant-failure",
    ):
        if marker in binary_content:
            raise AssertionError(
                "formal subconverter binary contains test-only marker "
                f"{marker.decode()}"
            )
        with running_service(binary, extra_args=(marker.decode(),)) as base_url:
            status, body, _ = request(base_url, "/healthz")
            if status != 200 or body.strip() != b"ok":
                raise AssertionError(
                    "formal subconverter binary handles test-only marker "
                    f"{marker.decode()} instead of preserving legacy "
                    "unknown-argument behavior"
                )


def log_redirection_baseline(binary: Path) -> None:
    with tempfile.TemporaryDirectory(
        dir=REPOSITORY / "build", prefix="log-redirection-"
    ) as temporary:
        temporary_path = Path(temporary)
        redirected_log = temporary_path / "service.log"
        redirected_log.write_text("preexisting-log-line\n", encoding="utf-8")
        with running_service(
            binary,
            extra_args=("-l", str(redirected_log)),
        ) as base_url:
            status, body, headers = request(base_url, "/healthz")
            if status != 200 or body.strip() != b"ok":
                raise AssertionError("service failed after log redirection")
            assert_request_id(headers, "redirected log health response")
        redirected = redirected_log.read_text(encoding="utf-8", errors="replace")
        if not redirected.startswith("preexisting-log-line\n"):
            raise AssertionError("-l did not preserve existing log content")
        if "LOG_REDIRECT_ACTIVE mode=append rotation=external" not in redirected:
            raise AssertionError("successful -l redirection lacks its stable event")
        if "HTTP_RESPONSE_PREPARED" not in redirected:
            raise AssertionError("redirected log lost HTTP diagnostics")

        failed_logs: list[str] = []
        secret_directory = temporary_path / "redirect-path-secret"
        secret_directory.mkdir()
        with running_service(
            binary,
            extra_args=("-l", str(secret_directory)),
            log_capture=failed_logs,
        ) as base_url:
            status, body, _ = request(base_url, "/healthz")
            if status != 200 or body.strip() != b"ok":
                raise AssertionError("failed -l redirection broke stderr or startup")
        diagnostics = "".join(failed_logs)
        if "LOG_REDIRECT_FAILED" not in diagnostics:
            raise AssertionError("failed -l redirection lacks its stable event")
        if "redirect-path-secret" in diagnostics:
            raise AssertionError("failed -l redirection leaked the configured path")


def normalize_output(content: bytes, fixture_base: str) -> str:
    normalized = (
        content.decode("utf-8")
        .replace("\r\n", "\n")
        .replace(fixture_base, "http://fixture.test")
    )
    normalized = re.sub(r"Provider_[0-9A-F]{6}", "Provider_FIXTURE", normalized)
    return normalized.strip() + "\n"


def canonical_golden(name: str, content: str) -> str:
    """Keep generated semantics while excluding platform base-template boilerplate."""
    lines = content.splitlines()
    if name == "clash-provider.yaml":
        start = lines.index("proxy-providers:")
        end = next(
            (
                index
                for index in range(start + 1, len(lines))
                if lines[index] in {"proxy-groups: ~", "rules: ~"}
            ),
            len(lines),
        )
        return "\n".join(lines[start:end]) + "\n"
    if name == "surge.conf":
        return next(line for line in lines if line.startswith("Smoke = ")) + "\n"
    if name == "quanx.conf":
        return next(
            line
            for line in lines
            if line.startswith("shadowsocks = ") and "tag=Smoke" in line
        ) + "\n"
    if name == "singbox.json":
        document = json.loads(content)
        smoke = next(
            item
            for item in document.get("outbounds", [])
            if item.get("tag") == "Smoke"
        )
        return (
            json.dumps(
                {"outbounds": [smoke]},
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )
    return content


def assert_golden(name: str, content: str, update: bool) -> None:
    path = GOLDEN_ROOT / name
    if update:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
        return
    expected = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    if content != expected:
        diff = "".join(
            difflib.unified_diff(
                expected.splitlines(keepends=True),
                content.splitlines(keepends=True),
                fromfile=f"{name}.expected",
                tofile=f"{name}.actual",
            )
        )
        raise AssertionError(f"golden output changed: {path}\n{diff}")


def validate_mihomo_config(binary: Path, content: bytes) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        runtime_dir = Path(temporary)
        config_path = runtime_dir / "issue-98.yaml"
        config_path.write_bytes(content)
        completed = subprocess.run(
            [
                str(binary),
                "-t",
                "-d",
                str(runtime_dir),
                "-f",
                str(config_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        if completed.returncode != 0:
            diagnostics = completed.stdout.decode("utf-8", errors="replace")
            raise AssertionError(
                "pinned Mihomo rejected the Issue #98 output: "
                f"exit={completed.returncode}, output={diagnostics[-8000:]!r}"
            )


def issue_98_reality_baseline(
    base_url: str, fixture_base: str, mihomo_binary: Path | None
) -> None:
    def assert_numeric_sid_output(
        description: str, status: int, body: bytes
    ) -> None:
        output = body.decode("utf-8", errors="replace")
        if status != 200:
            raise AssertionError(
                f"VLESS Reality {description} conversion failed: "
                f"HTTP {status}: {output!r}"
            )
        if 'short-id: "00112233"' not in output:
            raise AssertionError(
                f"VLESS Reality {description} lost its numeric string short-id"
            )
        if "canonical-string" in output:
            raise AssertionError(
                f"VLESS Reality {description} leaked an internal string tag"
            )
        if mihomo_binary is not None:
            validate_mihomo_config(mihomo_binary, body)

    cases = (
        (
            "without sid",
            VLESS_REALITY_WITHOUT_SID_URI,
            'short-id: ""',
        ),
        (
            "with a leading-zero numeric sid",
            VLESS_REALITY_WITH_NUMERIC_SID_URI,
            'short-id: "00112233"',
        ),
    )
    for description, uri, expected_short_id in cases:
        status, body, _ = request(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": uri,
                "config": fixture_base + "/external-clash-generation.ini",
            },
        )
        reality_output = body.decode("utf-8", errors="replace")
        if status != 200:
            raise AssertionError(
                f"VLESS Reality {description} conversion failed: "
                f"HTTP {status}: {reality_output!r}"
            )
        if expected_short_id not in reality_output:
            raise AssertionError(
                f"VLESS Reality {description} lost its string short-id: "
                f"expected {expected_short_id!r}"
            )
        if 'short-id: """"' in reality_output:
            raise AssertionError(
                "VLESS Reality short-id regained the invalid doubled quoting"
            )
        if "canonical-string" in reality_output:
            raise AssertionError(
                "VLESS Reality output leaked an internal canonical string tag"
            )
        if "DOMAIN-SUFFIX,issue-98.example,Proxy,Proxy" in reality_output:
            raise AssertionError(
                "Issue #98 fixture generated a duplicate rule policy"
            )
        if "DOMAIN-SUFFIX,issue-98.example,Proxy" not in reality_output:
            raise AssertionError(
                "Issue #98 fixture did not generate its expected Clash rule"
            )
        if mihomo_binary is not None:
            validate_mihomo_config(mihomo_binary, body)

    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": VLESS_REALITY_WITH_NUMERIC_SID_URI,
            "config": DISABLE_RULEGEN_CONFIG,
            "list": "true",
        },
    )
    assert_numeric_sid_output("list output", status, body)

def conversion_baselines(
    base_url: str, fixture_base: str, update_golden: bool
) -> None:
    subscription_url = fixture_base + "/subscription.txt"
    common = {
        "url": subscription_url,
        "config": DISABLE_RULEGEN_CONFIG,
    }
    cases = {
        "clash-provider.yaml": {"target": "clash", **common},
        "clash-list.yaml": {"target": "clash", "list": "true", **common},
        "surge.conf": {"target": "surge", "list": "true", **common},
        "singbox.json": {"target": "singbox", "list": "true", **common},
        "quanx.conf": {"target": "quanx", "list": "true", **common},
        "simple-subscription.txt": {
            "target": "mixed",
            "list": "true",
            **common,
        },
    }
    outputs: dict[str, str] = {}
    for name, params in cases.items():
        status, body, _ = request(base_url, "/sub", params)
        if status != 200:
            raise AssertionError(f"{name} conversion returned HTTP {status}: {body!r}")
        outputs[name] = normalize_output(body, fixture_base)
        assert_golden(
            name, canonical_golden(name, outputs[name]), update_golden
        )

    if "proxy-providers:" not in outputs["clash-provider.yaml"]:
        raise AssertionError("Clash provider baseline lost provider mode")
    if "Smoke" not in outputs["clash-list.yaml"] or "proxy-providers:" in outputs[
        "clash-list.yaml"
    ]:
        raise AssertionError("Clash list baseline lost expanded node mode")
    if "Smoke = ss, " not in outputs["surge.conf"]:
        raise AssertionError("Surge semantic baseline failed")
    singbox = json.loads(outputs["singbox.json"])
    if not any(item.get("tag") == "Smoke" for item in singbox.get("outbounds", [])):
        raise AssertionError("sing-box semantic baseline lost the fixture outbound")
    if "Smoke" not in outputs["quanx.conf"]:
        raise AssertionError("Quantumult X semantic baseline failed")
    if not outputs["simple-subscription.txt"].startswith("ss://"):
        raise AssertionError("simple subscription baseline is not an ss:// URI")

    encoded_ruleset = base64.urlsafe_b64encode(
        (fixture_base + "/rules.list").encode()
    ).decode()
    encoded_group = base64.urlsafe_b64encode(b"Converted").decode()
    expected_ruleset_outputs = {
        "1": RULESET,
        "2": (
            "DOMAIN-SUFFIX,example.com,Converted\n"
            "IP-CIDR,198.51.100.0/24,Converted\n"
        ),
        "3": "payload:\n  - '+.example.com'\n",
        "4": "payload:\n  - '198.51.100.0/24'\n",
        "5": ".example.com\n",
        "6": (
            "payload:\n"
            "  - DOMAIN-SUFFIX,example.com,Proxy\n"
            "  - IP-CIDR,198.51.100.0/24,Proxy\n"
        ),
    }
    for ruleset_type, expected in expected_ruleset_outputs.items():
        params = {"url": encoded_ruleset, "type": ruleset_type}
        if ruleset_type == "2":
            params["group"] = encoded_group
        status, body, _ = request(base_url, "/getruleset", params)
        if status != 200:
            raise AssertionError(
                f"/getruleset type={ruleset_type} returned "
                f"HTTP {status}: {body!r}"
            )
        ruleset_output = normalize_output(body, fixture_base)
        if ruleset_output != expected:
            diff = "".join(
                difflib.unified_diff(
                    expected.splitlines(keepends=True),
                    ruleset_output.splitlines(keepends=True),
                    fromfile=f"getruleset-type-{ruleset_type}.expected",
                    tofile=f"getruleset-type-{ruleset_type}.actual",
                )
            )
            raise AssertionError(
                f"/getruleset type={ruleset_type} output changed:\n{diff}"
            )
        if ruleset_type == "6":
            assert_golden("getruleset.yaml", ruleset_output, update_golden)

    encoded_mixed_ruleset = base64.urlsafe_b64encode(
        (fixture_base + "/rules-with-invalid.list").encode()
    ).decode()
    for ruleset_type, expected_rule in (
        ("3", "valid-before.example"),
        ("4", "203.0.113.0/24"),
    ):
        status, body, _ = request(
            base_url,
            "/getruleset",
            {"url": encoded_mixed_ruleset, "type": ruleset_type},
        )
        converted = body.decode("utf-8", errors="replace")
        if (
            status != 200
            or expected_rule not in converted
            or "NOT-A-SUPPORTED-RULE" in converted
        ):
            raise AssertionError(
                "a single unsupported ruleset line was not skipped "
                f"independently for type={ruleset_type}: {converted!r}"
            )


def parser_route_isolation_baseline(base_url: str, fixture_base: str) -> None:
    common = {
        "url": MIHOMO_ONLY_ROUTE_URI,
        "config": DISABLE_RULEGEN_CONFIG,
    }
    for target in ("clash", "clashr"):
        status, body, headers = request(
            base_url,
            "/sub",
            {"target": target, "list": "true", **common},
        )
        output = body.decode("utf-8", errors="replace")
        if status != 200 or "RouteProbe" not in output:
            raise AssertionError(
                f"explicit {target} did not use the Mihomo-only parser: "
                f"HTTP {status}: {output!r}"
            )
        assert_vary_header(headers, "User-Agent", f"explicit {target}")

    auto_cases = tuple(
        (user_agent, "clash") for user_agent in CLASH_AUTO_USER_AGENTS
    )
    auto_cases += tuple(
        (user_agent, "clashr") for user_agent in CLASHR_AUTO_USER_AGENTS
    )
    for user_agent, resolved_target in auto_cases:
        status, body, headers = request(
            base_url,
            "/sub",
            {"target": "auto", "explain": "true", **common},
            {"User-Agent": user_agent},
        )
        if status != 200:
            raise AssertionError(
                f"auto {resolved_target} parser route returned HTTP {status}: {body!r}"
            )
        assert_vary_header(
            headers, "User-Agent", f"auto {resolved_target} parser route"
        )
        report = json.loads(body)
        if (
            report.get("target") != resolved_target
            or report.get("nodes", {}).get("total", 0) < 1
        ):
            raise AssertionError(
                f"auto UA {user_agent!r} did not resolve to the Mihomo-only "
                f"{resolved_target} route: {report!r}"
            )

    non_clash_auto_user_agents = (
        "Kitsunebi/1.8.0",
        "Loon/3.2.1",
        "Pharos/1.0",
        "Potatso/2.0",
        "Quantumult%20X/1.4",
        "Quantumult/2.0",
        "Qv2ray/2.7",
        "Shadowrocket/2.2.60",
        "Surfboard/2.24",
        "SURGE/906 X86",
        "Trojan-Qt5/1.4",
        "V2rayU/3.8",
        "V2RayX/1.5",
    )
    for user_agent in non_clash_auto_user_agents:
        status, body, headers = request(
            base_url,
            "/sub",
            {"target": "auto", **common},
            {"User-Agent": user_agent},
        )
        if status != 400:
            raise AssertionError(
                f"legacy auto UA {user_agent!r} accepted a Mihomo-only URI: "
                f"HTTP {status}: {body!r}"
            )
        assert_vary_header(headers, "User-Agent", f"auto UA {user_agent!r}")

    status, body, headers = request(
        base_url,
        "/sub",
        {"target": "auto", **common},
        {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
    )
    if status != 400:
        raise AssertionError(
            "browser UA was incorrectly classified as Clash: "
            f"HTTP {status}: {body!r}"
        )
    assert_vary_header(headers, "User-Agent", "unrecognized auto target")

    for target in LEGACY_ONLY_TARGETS:
        status, body, headers = request(
            base_url,
            "/sub",
            {"target": target, **common},
        )
        if status != 400:
            raise AssertionError(
                f"legacy-only target {target} accepted a Mihomo-only URI: "
                f"HTTP {status}: {body!r}"
            )
        assert_vary_header(headers, "User-Agent", f"legacy target {target}")

    status, body, headers = request(
        base_url,
        "/sub",
        {"target": "auto", **common},
        {"User-Agent": "Loon/3.2.1"},
    )
    if status != 400:
        raise AssertionError(
            "auto Loon route accepted a Mihomo-only URI: "
            f"HTTP {status}: {body!r}"
        )
    assert_vary_header(headers, "User-Agent", "auto Loon parser error")

    status, body, headers = request(
        base_url,
        "/sub",
        {
            "target": "singbox",
            "url": LEGACY_ONLY_ROUTE_URI,
            "config": DISABLE_RULEGEN_CONFIG,
        },
    )
    if status != 200:
        raise AssertionError(
            f"legacy-only parser rejected its direct URI: HTTP {status}: {body!r}"
        )
    assert_vary_header(headers, "User-Agent", "legacy direct response")
    report = json.loads(body)
    if not any(
        outbound.get("tag") == "LegacyRouteProbe"
        for outbound in report.get("outbounds", [])
    ):
        raise AssertionError("legacy-only direct URI was not expanded by sing-box")

    status, body, headers = request(
        base_url,
        "/sub",
        {
            "target": "auto",
            "url": LEGACY_ONLY_ROUTE_URI,
            "config": DISABLE_RULEGEN_CONFIG,
            "explain": "true",
        },
        {"User-Agent": "Loon/3.2.1"},
    )
    if status != 200:
        raise AssertionError(
            f"auto Loon legacy-only route returned HTTP {status}: {body!r}"
        )
    assert_vary_header(headers, "User-Agent", "auto Loon response")
    report = json.loads(body)
    if report.get("target") != "loon" or report.get("nodes", {}).get("total", 0) < 1:
        raise AssertionError(
            f"auto Loon did not resolve to the legacy-only route: {report!r}"
        )

    status, body, headers = request(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": LEGACY_ONLY_ROUTE_URI,
            "config": DISABLE_RULEGEN_CONFIG,
            "list": "true",
        },
    )
    if status != 400:
        raise AssertionError(
            "Mihomo-only Clash route accepted a legacy-only URI: "
            f"HTTP {status}: {body!r}"
        )
    assert_vary_header(headers, "User-Agent", "Clash parser error")

    status, body, headers = request(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": fixture_base + "/mihomo-raw-subscription.txt",
            "config": DISABLE_RULEGEN_CONFIG,
            "list": "true",
        },
    )
    output = body.decode("utf-8", errors="replace")
    if status != 200 or "Smoke" not in output:
        raise AssertionError(
            "Mihomo-only Clash route did not expand a fetched raw URI list: "
            f"HTTP {status}: {output!r}"
        )
    assert_vary_header(headers, "User-Agent", "Clash fetched list response")


def parser_invocation_log_baseline(binary: Path, fixture_base: str) -> None:
    cases = (
        (
            "mihomo",
            (
                (
                    {
                        "target": "clash",
                        "url": MIHOMO_ONLY_ROUTE_URI,
                        "config": DISABLE_RULEGEN_CONFIG,
                        "list": "true",
                    },
                    200,
                ),
                (
                    {
                        "target": "clash",
                        "url": LEGACY_ONLY_ROUTE_URI,
                        "config": DISABLE_RULEGEN_CONFIG,
                        "list": "true",
                    },
                    400,
                ),
            ),
        ),
        (
            "legacy",
            (
                (
                    {
                        "target": "singbox",
                        "url": LEGACY_ONLY_ROUTE_URI,
                        "config": DISABLE_RULEGEN_CONFIG,
                    },
                    200,
                ),
                (
                    {
                        "target": "singbox",
                        "url": fixture_base + "/subscription.txt",
                        "config": DISABLE_RULEGEN_CONFIG,
                    },
                    200,
                ),
            ),
        ),
    )
    for expected_parser, requests in cases:
        logs: list[str] = []
        with running_service(
            binary, log_capture=logs, log_level="verbose"
        ) as base_url:
            for params, expected_status in requests:
                status, body, _ = request(base_url, "/sub", params)
                if status != expected_status:
                    raise AssertionError(
                        f"{expected_parser} invocation probe returned HTTP {status}, "
                        f"expected {expected_status}: {body!r}"
                    )

        diagnostics = "".join(logs)
        for branch in ("sub", "direct"):
            event = (
                f"NODE_PARSER_INVOKE parser={expected_parser} branch={branch}"
            )
            if event not in diagnostics:
                raise AssertionError(f"parser invocation log missing {event!r}")
        forbidden_parser = "legacy" if expected_parser == "mihomo" else "mihomo"
        forbidden = f"NODE_PARSER_INVOKE parser={forbidden_parser}"
        if forbidden in diagnostics:
            raise AssertionError(
                f"{expected_parser}-only requests also invoked {forbidden_parser}"
            )


def provider_no_fetch_vary_and_route_log_baseline(
    binary: Path, fixture_base: str
) -> None:
    FixtureHandler.provider_never_fetch_count = 0
    with direct_opener().open(
        fixture_base + "/provider-must-not-fetch.txt?case=counter-control",
        timeout=20,
    ) as response:
        response.read()
    if FixtureHandler.provider_never_fetch_count != 1:
        raise AssertionError("provider fetch fixture counter control failed")
    FixtureHandler.provider_never_fetch_count = 0

    logs: list[str] = []
    clash_ua_secret = "clash-ua-secret-must-not-reach-logs"
    clashr_ua_secret = "clashr-ua-secret-must-not-reach-logs"
    unknown_ua_secret = "unknown-ua-secret-must-not-reach-logs"
    fixture_source = fixture_base + "/provider-must-not-fetch.txt"
    cases = (
        ("clash", {}, fixture_source + "?case=explicit-clash"),
        ("clashr", {}, fixture_source + "?case=explicit-clashr"),
        (
            "auto",
            {
                "User-Agent": (
                    "ClashMetaForAndroid/2.11.32.Meta " + clash_ua_secret
                )
            },
            fixture_source + "?case=auto-clash",
        ),
        (
            "auto",
            {
                "User-Agent": (
                    "ClashForAndroid/1.3.3R2 " + clashr_ua_secret
                )
            },
            fixture_source + "?case=auto-clashr",
        ),
        ("clash", {}, "https://127.0.0.1:1/provider-must-not-connect"),
    )
    with running_service(
        binary, log_capture=logs, log_level="verbose"
    ) as base_url:
        for target, headers, source in cases:
            status, body, response_headers = request(
                base_url,
                "/sub",
                {
                    "target": target,
                    "url": source,
                    "config": DISABLE_RULEGEN_CONFIG,
                },
                headers,
            )
            output = body.decode("utf-8", errors="replace")
            if status != 200 or "proxy-providers:" not in output:
                raise AssertionError(
                    f"{target} provider-only route returned HTTP {status}: "
                    f"{output!r}"
                )
            assert_vary_header(
                response_headers, "User-Agent", f"{target} provider response"
            )
        head_status, head_body, head_headers = request(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": fixture_base + "/provider-must-not-fetch.txt?case=head",
                "config": DISABLE_RULEGEN_CONFIG,
            },
            method="HEAD",
        )
        if head_status != 200 or head_body:
            raise AssertionError(
                f"provider HEAD route returned HTTP {head_status}: {head_body!r}"
            )
        assert_vary_header(head_headers, "User-Agent", "provider HEAD response")
        assert_request_id(head_headers, "provider HEAD response")

        bad_status, _, bad_headers = request(
            base_url,
            "/sub",
            {
                "target": "auto",
                "url": fixture_base + "/provider-must-not-fetch.txt?case=bad-auto",
                "config": DISABLE_RULEGEN_CONFIG,
            },
            {"User-Agent": "Mozilla/5.0 " + unknown_ua_secret},
        )
        if bad_status != 400:
            raise AssertionError(
                f"unrecognized auto target returned HTTP {bad_status}, expected 400"
            )
        assert_vary_header(bad_headers, "User-Agent", "auto-target error")

        dead_status, _, _ = request(base_url, "/surge2clash")
        if dead_status != 404:
            raise AssertionError(
                f"unregistered /surge2clash route changed to HTTP {dead_status}"
            )

    diagnostics = "".join(logs)
    if FixtureHandler.provider_never_fetch_count != 0:
        raise AssertionError(
            "provider-only /sub request downloaded its remote subscription: "
            f"count={FixtureHandler.provider_never_fetch_count}"
        )
    if "NODE_PARSER_INVOKE" in diagnostics:
        raise AssertionError("provider-only /sub request invoked a node parser")
    for target in ("clash", "clashr"):
        for source in ("explicit", "auto"):
            event = (
                f"SUB_ROUTE_RESULT target={target} source={source} "
                "route=proxy-provider parser_policy=mihomo parser=none "
                "provider_count=1 source_calls=0 source_failures=0 "
                "parser_calls=0 parser_failures=0"
            )
            if not has_exact_log_event(diagnostics, event):
                raise AssertionError(
                    f"provider-only route observability is missing {event!r}"
                )
    if (
        not has_exact_log_event(
            diagnostics,
            "AUTO_TARGET_RESOLVED target=clash parser=mihomo ua_family=clash",
        )
        or not has_exact_log_event(
            diagnostics,
            "AUTO_TARGET_RESOLVED target=clashr parser=mihomo "
            "ua_family=clash-for-android-r",
        )
    ):
        raise AssertionError("safe auto-target resolution events are incomplete")
    for secret in (clash_ua_secret, clashr_ua_secret, unknown_ua_secret):
        if secret in diagnostics:
            raise AssertionError("raw User-Agent data leaked into auto-target logs")
    if not has_exact_log_event(
        diagnostics, "AUTO_TARGET_UNRESOLVED ua_family=unknown"
    ):
        raise AssertionError("unrecognized auto-target event is missing")


def quanx_server_remote_baseline(binary: Path, fixture_base: str) -> None:
    def data_url(content: str) -> str:
        encoded = base64.urlsafe_b64encode(content.encode()).decode()
        return "data:text/plain;base64," + encoded

    def section_lines(output: str, name: str) -> list[str]:
        marker = f"[{name}]"
        lines = output.splitlines()
        try:
            start = lines.index(marker) + 1
        except ValueError as error:
            raise AssertionError(f"missing [{name}] section\n{output}") from error
        result: list[str] = []
        for line in lines[start:]:
            if line.startswith("[") and line.endswith("]"):
                break
            if line.strip():
                result.append(line.strip())
        return result

    group_config = data_url(
        "enable_rule_generator=false\n"
        "custom_proxy_group=Remote`select`.*\n"
    )
    native_config = (
        ("udp_flag = false", "# udp_flag intentionally left unset"),
        ("tcp_fast_open_flag = true", "# tcp_fast_open_flag intentionally left unset"),
        ("skip_cert_verify_flag = false", "# skip_cert_verify_flag intentionally left unset"),
        ("tls13_flag = true", "# tls13_flag intentionally left unset"),
    )
    source_secret = "quanx-source-secret-must-not-reach-logs"
    source_a = (
        fixture_base
        + "/quanx-remote.txt?case=native-a&token="
        + source_secret
        + "+literal-plus%252F"
    )
    source_b = fixture_base + "/quanx-remote.txt?case=native-b"
    FixtureHandler.quanx_remote_fetch_count = 0
    logs: list[str] = []

    with running_service(
        binary,
        log_capture=logs,
        log_level="verbose",
        config_replacements=native_config,
    ) as base_url:
        status, body, headers = request(
            base_url,
            "/sub",
            {
                "target": "quanx",
                "url": "|".join(
                    (
                        f"interval:0,provider:Airport/A,{source_a}",
                        f"provider:Airport/A,interval:21600,{source_b}",
                        SUBSCRIPTION.strip(),
                    )
                ),
                "config": group_config,
            },
        )
        output = body.decode("utf-8", errors="replace")
        if status != 200:
            raise AssertionError(
                f"Quantumult X native remote request returned HTTP {status}: {output!r}"
            )
        assert_vary_header(headers, "User-Agent", "Quantumult X native response")
        assert_request_id(headers, "Quantumult X native response")
        remote_lines = section_lines(output, "server_remote")
        expected_remote_fragments = (
            (source_a, "tag=Airport_A", "update-interval=-1", "enabled=true"),
            (source_b, "tag=Airport_A_1", "update-interval=21600", "enabled=true"),
        )
        if len(remote_lines) != 2:
            raise AssertionError(
                f"Quantumult X remote resources mismatch: {remote_lines!r}"
            )
        for line, fragments in zip(remote_lines, expected_remote_fragments):
            missing = [fragment for fragment in fragments if fragment not in line]
            if missing:
                raise AssertionError(
                    f"Quantumult X remote line is missing {missing!r}: {line!r}"
                )
        if "opt-parser=" in output:
            raise AssertionError("Quantumult X output enabled opt-parser implicitly")
        local_lines = section_lines(output, "server_local")
        if not any("tag=Smoke" in line for line in local_lines):
            raise AssertionError(
                f"mixed Quantumult X request lost its direct node: {local_lines!r}"
            )
        policy_lines = section_lines(output, "policy")
        if not any(
            "static=Remote" in line
            and "resource-tag-regex=^(?:Airport_A|Airport_A_1)$" in line
            and "server-tag-regex=.*" in line
            for line in policy_lines
        ):
            raise AssertionError(
                f"Quantumult X policy does not reference remote resources: {policy_lines!r}"
            )
        if FixtureHandler.quanx_remote_fetch_count != 0:
            raise AssertionError(
                "Quantumult X native route downloaded a client-managed resource: "
                f"count={FixtureHandler.quanx_remote_fetch_count}"
            )

        existing_base = data_url(
            "[general]\n"
            "[policy]\n"
            "[server_remote]\n"
            "https://existing.example.test/sub, tag=Airport_A, enabled=true\n"
            "[server_local]\n"
        )
        collision_config = data_url(
            "enable_rule_generator=false\n"
            f"quanx_rule_base={existing_base}\n"
            "custom_proxy_group=Remote`select`!!PROVIDER=Airport/A\n"
        )
        collision_status, collision_body, _ = request(
            base_url,
            "/sub",
            {
                "target": "quanx",
                "url": f"provider:Airport/A,{source_a}",
                "config": collision_config,
            },
        )
        collision_output = collision_body.decode("utf-8", errors="replace")
        collision_lines = section_lines(collision_output, "server_remote")
        if (
            collision_status != 200
            or not any("tag=Airport_A," in line for line in collision_lines)
            or not any("tag=Airport_A_1," in line for line in collision_lines)
            or "resource-tag-regex=^Airport_A_1$" not in collision_output
        ):
            raise AssertionError(
                "Quantumult X custom base resource preservation/collision failed: "
                f"HTTP {collision_status}: {collision_output!r}"
            )
        if FixtureHandler.quanx_remote_fetch_count != 0:
            raise AssertionError("custom Quantumult X base caused a remote source fetch")

        root_source = "https://root-subscription.example.test"
        root_status, root_body, _ = request(
            base_url,
            "/sub",
            {
                "target": "quanx",
                "url": f"provider:RootRemote,{root_source}",
                "config": group_config,
            },
        )
        root_output = root_body.decode("utf-8", errors="replace")
        if (
            root_status != 200
            or root_source not in root_output
            or "tag=RootRemote" not in root_output
        ):
            raise AssertionError(
                "explicit root Quantumult X subscription was not treated as remote: "
                f"HTTP {root_status}: {root_output!r}"
            )

        explain_status, explain_body, explain_headers = request(
            base_url,
            "/sub",
            {
                "target": "quanx",
                "url": f"provider:ExplainRemote,{source_a}",
                "config": group_config,
                "explain": "true",
            },
        )
        if explain_status != 200:
            raise AssertionError(
                "Quantumult X explain failed: "
                f"HTTP {explain_status}: {explain_body[-1000:]!r}"
            )
        if "no-store" not in explain_headers.get("cache-control", ""):
            raise AssertionError("Quantumult X explain is missing no-store")
        explain_text = explain_body.decode("utf-8", errors="replace")
        if source_secret in explain_text:
            raise AssertionError("Quantumult X explain leaked a source credential")
        report = json.loads(explain_body)
        if (
            report.get("mode", {}).get("remote_subscription_backend")
            != "quanx-server-remote"
            or report.get("mode", {}).get("remote_subscription_reason")
            != "native-capable"
            or report.get("resources", {}).get("remote_subscription_count") != 1
            or report.get("output", {}).get("remote_subscription_count") != 1
        ):
            raise AssertionError(
                f"Quantumult X explain route metadata mismatch: {report!r}"
            )

        direct_explain_status, direct_explain_body, _ = request(
            base_url,
            "/sub",
            {
                "target": "quanx",
                "url": SUBSCRIPTION.strip(),
                "config": group_config,
                "explain": "true",
            },
        )
        direct_report = json.loads(direct_explain_body)
        if (
            direct_explain_status != 200
            or direct_report.get("mode", {}).get("remote_subscription_backend")
            != "server-side-parse"
            or direct_report.get("mode", {}).get("remote_subscription_reason")
            != "no-remote-subscription"
            or direct_report.get("resources", {}).get("remote_subscription_count") != 0
        ):
            raise AssertionError(
                f"direct-only Quantumult X route metadata mismatch: {direct_report!r}"
            )

        imported_uri = "!!import:" + data_url(SUBSCRIPTION)
        imported_status, imported_body, _ = request(
            base_url,
            "/sub",
            {
                "target": "quanx",
                "url": imported_uri,
                "config": group_config,
                "explain": "true",
            },
        )
        imported_report = json.loads(imported_body)
        if (
            imported_status != 200
            or imported_report.get("mode", {}).get("remote_subscription_backend")
            != "server-side-parse"
            or imported_report.get("mode", {}).get("remote_subscription_reason")
            != "imported-source-list"
        ):
            raise AssertionError(
                f"imported Quantumult X source did not preserve Legacy: {imported_report!r}"
            )

        combined_group_config = data_url(
            "enable_rule_generator=false\n"
            "custom_proxy_group=Remote`select`!!PROVIDER=Only`.*\n"
        )
        combined_status, combined_body, _ = request(
            base_url,
            "/sub",
            {
                "target": "quanx",
                "url": f"provider:Only,{fixture_base}/subscription.txt",
                "config": combined_group_config,
                "explain": "true",
            },
        )
        combined_report = json.loads(combined_body)
        if (
            combined_status != 200
            or combined_report.get("mode", {}).get("remote_subscription_backend")
            != "server-side-parse"
            or combined_report.get("mode", {}).get("remote_subscription_reason")
            != "provider-and-rule-selectors"
        ):
            raise AssertionError(
                "combined provider/rule Quantumult X group did not preserve Legacy: "
                f"{combined_report!r}"
            )

        auto_status, auto_body, auto_headers = request(
            base_url,
            "/sub",
            {
                "target": "auto",
                "url": "https://127.0.0.1:1/quanx-dead-sub?case=auto",
                "config": group_config,
            },
            {"User-Agent": "Quantumult%20X/1.4"},
        )
        auto_output = auto_body.decode("utf-8", errors="replace")
        if auto_status != 200 or "quanx-dead-sub" not in auto_output:
            raise AssertionError(
                f"auto Quantumult X did not select server_remote: HTTP {auto_status}: "
                f"{auto_output!r}"
            )
        assert_vary_header(auto_headers, "User-Agent", "auto Quantumult X response")

        http_proxy_payload = (
            "cHJveHktdXNlcjpwcm94eS1wYXNzQHByb3h5LmV4YW1wbGUudGVzdDo4MDgw"
        )
        for proxy_uri in (
            f"http://{http_proxy_payload}",
            f"https://{http_proxy_payload}?remarks=NamedHTTP&group=NamedGroup",
            f"provider:Ignored,http://{http_proxy_payload}?remarks=NamedHTTP",
        ):
            proxy_status, proxy_body, _ = request(
                base_url,
                "/sub",
                {
                    "target": "quanx",
                    "url": proxy_uri,
                    "config": group_config,
                },
            )
            proxy_output = proxy_body.decode("utf-8", errors="replace")
            local_proxy_lines = section_lines(proxy_output, "server_local")
            remote_proxy_lines = section_lines(proxy_output, "server_remote")
            if (
                proxy_status != 200
                or not any("proxy.example.test" in line for line in local_proxy_lines)
                or any(http_proxy_payload in line for line in remote_proxy_lines)
            ):
                raise AssertionError(
                    "Legacy HTTP proxy URI was misclassified as a remote subscription: "
                    f"HTTP {proxy_status}: {proxy_output!r}"
                )

        interval_proxy_status, interval_proxy_body, _ = request(
            base_url,
            "/sub",
            {
                "target": "quanx",
                "url": f"interval:3600,http://{http_proxy_payload}",
                "config": group_config,
            },
        )
        if interval_proxy_status != 400 or b"interval:" not in interval_proxy_body:
            raise AssertionError(
                "Quantumult X accepted interval: for an HTTP proxy node: "
                f"HTTP {interval_proxy_status}: {interval_proxy_body!r}"
            )

        telegram_status, telegram_body, _ = request(
            base_url,
            "/sub",
            {
                "target": "quanx",
                "url": (
                    "https://t.me/http?server=telegram.example.test&port=8080"
                    "&user=telegram-user&pass=telegram-pass&remarks=TelegramHTTP"
                ),
                "config": group_config,
            },
        )
        telegram_output = telegram_body.decode("utf-8", errors="replace")
        if (
            telegram_status != 200
            or not any(
                "telegram.example.test" in line
                for line in section_lines(telegram_output, "server_local")
            )
            or any(
                "t.me/http" in line
                for line in section_lines(telegram_output, "server_remote")
            )
        ):
            raise AssertionError(
                "Telegram HTTP node was misclassified as Quantumult X remote: "
                f"HTTP {telegram_status}: {telegram_output!r}"
            )

        if FixtureHandler.quanx_remote_fetch_count != 0:
            raise AssertionError("a native Quantumult X request fetched the remote source")

        list_status, list_body, _ = request(
            base_url,
            "/sub",
            {
                "target": "quanx",
                "url": source_b,
                "config": group_config,
                "list": "true",
            },
        )
        if list_status != 200 or b"Smoke" not in list_body:
            raise AssertionError(
                f"Quantumult X list=true no longer uses Legacy: HTTP {list_status}: {list_body!r}"
            )
        if FixtureHandler.quanx_remote_fetch_count != 1:
            raise AssertionError("Quantumult X list=true did not fetch exactly once")

    diagnostics = "".join(logs)
    if source_secret in diagnostics:
        raise AssertionError("Quantumult X source credential leaked into logs")
    if "NODE_PARSER_INVOKE parser=mihomo" in diagnostics:
        raise AssertionError("Quantumult X route invoked Mihomo")
    if (
        "SUB_ROUTE_RESULT target=quanx source=explicit route=hybrid "
        "parser_policy=legacy parser=legacy provider_count=0 source_calls=1 "
        "source_failures=0 parser_calls=1 parser_failures=0 "
        "remote_backend=quanx-server-remote remote_reason=native-capable "
        "remote_count=2"
        not in diagnostics
    ):
        raise AssertionError("Quantumult X native route summary is missing")
    if (
        "AUTO_TARGET_RESOLVED target=quanx parser=legacy ua_family=quantumult-x"
        not in diagnostics
    ):
        raise AssertionError("Quantumult X auto-target event is missing")

    FixtureHandler.quanx_remote_fetch_count = 0
    fallback_logs: list[str] = []
    with running_service(
        binary, log_capture=fallback_logs, log_level="info"
    ) as base_url:
        fallback_status, fallback_body, _ = request(
            base_url,
            "/sub",
            {
                "target": "quanx",
                "url": f"provider:IgnoredOnFallback,{source_b}",
                "config": group_config,
            },
        )
        fallback_output = fallback_body.decode("utf-8", errors="replace")
        if fallback_status != 200 or "tag=Smoke" not in fallback_output:
            raise AssertionError(
                "legacy preferences no longer preserve Quantumult X Legacy behavior: "
                f"HTTP {fallback_status}: {fallback_output!r}"
            )
        if any(source_b in line for line in section_lines(fallback_output, "server_remote")):
            raise AssertionError("capability-gated Quantumult X request emitted server_remote")
        if FixtureHandler.quanx_remote_fetch_count != 1:
            raise AssertionError(
                "capability-gated Quantumult X request did not use Legacy exactly once"
            )

    fallback_diagnostics = "".join(fallback_logs)
    if (
        "remote_backend=server-side-parse remote_reason=node-option-override "
        "remote_count=0"
        not in fallback_diagnostics
    ):
        raise AssertionError("Quantumult X Legacy capability reason is missing")
def parser_failure_level_and_mixed_request_baseline(binary: Path) -> None:
    for log_level in ("info", "error"):
        failure_logs: list[str] = []
        with running_service(
            binary, log_capture=failure_logs, log_level=log_level
        ) as base_url:
            for target, invalid_uri in (
                ("clash", LEGACY_ONLY_ROUTE_URI),
                ("singbox", MIHOMO_ONLY_ROUTE_URI),
            ):
                status, _, headers = request(
                    base_url,
                    "/sub",
                    {
                        "target": target,
                        "url": invalid_uri,
                        "config": DISABLE_RULEGEN_CONFIG,
                        **({"list": "true"} if target == "clash" else {}),
                    },
                )
                if status != 400:
                    raise AssertionError(
                        f"{target} invalid parser probe returned HTTP {status} "
                        f"at log_level={log_level}"
                    )
                assert_vary_header(
                    headers,
                    "User-Agent",
                    f"{target} parser error at {log_level}",
                )

        failure_diagnostics = "".join(failure_logs)
        for parser in ("mihomo", "legacy"):
            if not any(
                "[ERRO]" in line
                and f"NODE_PARSER_FAILED parser={parser}" in line
                for line in failure_diagnostics.splitlines()
            ):
                raise AssertionError(
                    f"{parser} parser failure is not visible at {log_level}"
                )
            if any(
                "[VERB]" in line
                and f"NODE_PARSER_FAILED parser={parser}" in line
                for line in failure_diagnostics.splitlines()
            ):
                raise AssertionError(
                    f"{parser} parser failure is mislabeled verbose at {log_level}"
                )

    logs: list[str] = []
    legacy_ua_secret = "legacy-ua-secret-must-not-reach-logs"
    with running_service(binary, log_capture=logs, log_level="info") as base_url:
        status, body, _ = request(
            base_url,
            "/sub",
            {
                "target": "auto",
                "url": LEGACY_ONLY_ROUTE_URI,
                "config": DISABLE_RULEGEN_CONFIG,
            },
            {"User-Agent": "Loon/3.2.1 " + legacy_ua_secret},
        )
        if status != 200 or b"LegacyRouteProbe" not in body:
            raise AssertionError(
                f"safe legacy auto-target log probe failed: HTTP {status}: {body!r}"
            )

        mixed_cases = (
            (
                "clash",
                MIHOMO_ONLY_ROUTE_URI + "|" + LEGACY_ONLY_ROUTE_URI,
                "RouteProbe",
            ),
            (
                "clash",
                LEGACY_ONLY_ROUTE_URI + "|" + MIHOMO_ONLY_ROUTE_URI,
                "RouteProbe",
            ),
            (
                "singbox",
                LEGACY_ONLY_ROUTE_URI + "|" + MIHOMO_ONLY_ROUTE_URI,
                "LegacyRouteProbe",
            ),
            (
                "singbox",
                MIHOMO_ONLY_ROUTE_URI + "|" + LEGACY_ONLY_ROUTE_URI,
                "LegacyRouteProbe",
            ),
        )
        for target, url, marker in mixed_cases:
            params = {
                "target": target,
                "url": url,
                "config": DISABLE_RULEGEN_CONFIG,
            }
            if target == "clash":
                params["list"] = "true"
            status, body, headers = request(base_url, "/sub", params)
            output = body.decode("utf-8", errors="replace")
            if status != 200 or marker not in output:
                raise AssertionError(
                    f"{target} mixed valid/invalid request returned HTTP {status}: "
                    f"{output!r}"
                )
            if target == "clash" and "LegacyRouteProbe" in output:
                raise AssertionError("Clash mixed request fell back to legacy parser")
            if target == "singbox":
                report = json.loads(body)
                tags = {
                    outbound.get("tag")
                    for outbound in report.get("outbounds", [])
                    if isinstance(outbound, dict)
                }
                if "RouteProbe" in tags:
                    raise AssertionError(
                        "legacy mixed request fell back to Mihomo parser"
                    )
            assert_vary_header(headers, "User-Agent", f"{target} mixed response")

    diagnostics = "".join(logs)
    for parser in ("mihomo", "legacy"):
        route_event = (
            f"route=node-parser parser_policy={parser} parser={parser} "
            "provider_count=0 source_calls=2 source_failures=1 "
            "parser_calls=2 parser_failures=1"
        )
        if route_event not in diagnostics:
            raise AssertionError(
                f"mixed-request route summary is missing for {parser}"
            )
    if "NODE_PARSER_INVOKE" in diagnostics:
        raise AssertionError("verbose parser invocation leaked into info logging")
    if legacy_ua_secret in diagnostics:
        raise AssertionError("raw legacy User-Agent leaked into logs")
    if not has_exact_log_event(
        diagnostics,
        "AUTO_TARGET_RESOLVED target=loon parser=legacy ua_family=loon",
    ):
        raise AssertionError("safe legacy auto-target event is missing")


def insert_url_parser_route_baseline(binary: Path, fixture_base: str) -> None:
    logs: list[str] = []
    replacement = (
        'insert_url = ["' + MIHOMO_ONLY_ROUTE_URI.replace('"', '\\"') + '"]'
    )
    with running_service(
        binary,
        log_capture=logs,
        log_level="info",
        config_replacements=(("insert_url = []", replacement),),
    ) as base_url:
        status, body, headers = request(
            base_url,
            "/sub",
            {
                "target": "auto",
                "url": fixture_base + "/provider-must-not-fetch.txt?case=insert",
                "config": DISABLE_RULEGEN_CONFIG,
                "insert": "true",
            },
            {"User-Agent": "clash.meta/1.19.29"},
        )
        output = body.decode("utf-8", errors="replace")
        if (
            status != 200
            or "RouteProbe" not in output
            or "proxy-providers:" not in output
        ):
            raise AssertionError(
                f"auto Clash insert URL did not inherit Mihomo: HTTP {status}: "
                f"{output!r}"
            )
        assert_vary_header(headers, "User-Agent", "auto Clash insert response")

        status, body, headers = request(
            base_url,
            "/sub",
            {
                "target": "auto",
                "url": LEGACY_ONLY_ROUTE_URI,
                "config": DISABLE_RULEGEN_CONFIG,
                "insert": "true",
            },
            {"User-Agent": "Loon/3.2.1"},
        )
        if status != 400:
            raise AssertionError(
                f"auto Loon insert URL unexpectedly used Mihomo: HTTP {status}: "
                f"{body!r}"
            )
        assert_vary_header(headers, "User-Agent", "auto Loon insert error")
        if MIHOMO_ONLY_ROUTE_URI.encode() in body:
            raise AssertionError("configured insert URI leaked into an HTTP error")

    diagnostics = "".join(logs)
    if (
        "SUB_ROUTE_RESULT target=clash source=auto route=hybrid "
        "parser_policy=mihomo parser=mihomo provider_count=1 "
        "source_calls=1 source_failures=0 parser_calls=1 parser_failures=0"
        not in diagnostics
    ):
        raise AssertionError("auto Clash insert route summary is missing")
    if (
        "SUB_ROUTE_RESULT target=loon source=auto route=node-parser "
        "parser_policy=legacy parser=legacy provider_count=0 "
        "source_calls=1 source_failures=1 parser_calls=1 parser_failures=1"
        not in diagnostics
    ):
        raise AssertionError("auto Loon insert route summary is missing")
    if "user:pass" in diagnostics:
        raise AssertionError("configured insert credentials leaked into logs")


def vary_cache_and_coalesce_baseline(binary: Path, fixture_base: str) -> None:
    logs: list[str] = []
    with running_service(
        binary,
        log_capture=logs,
        log_level="debug",
        config_replacements=(("response_cache_ttl = 0", "response_cache_ttl = 5"),),
    ) as base_url:
        cached_params = {
            "target": "clash",
            "url": MIHOMO_ONLY_ROUTE_URI,
            "config": DISABLE_RULEGEN_CONFIG,
            "list": "true",
        }
        cached_request_ids: list[str] = []
        for label in ("cache owner", "microcache hit"):
            status, body, headers = request(base_url, "/sub", cached_params)
            if status != 200 or b"RouteProbe" not in body:
                raise AssertionError(
                    f"{label} response failed: HTTP {status}: {body!r}"
                )
            assert_vary_header(headers, "User-Agent", label)
            cached_request_ids.append(assert_request_id(headers, label))
        if len(set(cached_request_ids)) != len(cached_request_ids):
            raise AssertionError("microcache reused the owner request ID")

        FixtureHandler.slow_subscription_started.clear()
        FixtureHandler.slow_subscription_release.clear()
        results: list[tuple[int, bytes, dict[str, str]]] = []
        errors: list[BaseException] = []
        slow_params = {
            "target": "singbox",
            "url": fixture_base + "/slow-subscription.txt?case=coalesce-vary",
            "config": DISABLE_RULEGEN_CONFIG,
        }

        def run_request() -> None:
            try:
                results.append(request(base_url, "/sub", slow_params))
            except BaseException as error:
                errors.append(error)

        owner = threading.Thread(target=run_request)
        waiter = threading.Thread(target=run_request)
        owner.start()
        if not FixtureHandler.slow_subscription_started.wait(timeout=10):
            FixtureHandler.slow_subscription_release.set()
            owner.join(timeout=5)
            raise AssertionError("coalesce owner did not reach the slow fixture")
        waiter.start()
        time.sleep(0.2)
        FixtureHandler.slow_subscription_release.set()
        owner.join(timeout=20)
        waiter.join(timeout=20)
        if owner.is_alive() or waiter.is_alive():
            raise AssertionError("coalesced Vary probes did not finish")
        if errors:
            raise errors[0]
        if len(results) != 2:
            raise AssertionError("coalesced Vary probe did not return two responses")
        coalesced_request_ids: list[str] = []
        for status, body, headers in results:
            if status != 200 or b"Smoke" not in body:
                raise AssertionError(
                    f"coalesced response failed: HTTP {status}: {body!r}"
                )
            assert_vary_header(headers, "User-Agent", "coalesced waiter")
            coalesced_request_ids.append(
                assert_request_id(headers, "coalesced waiter")
            )
        if len(set(coalesced_request_ids)) != len(coalesced_request_ids):
            raise AssertionError("coalesced responses reused the owner request ID")

    diagnostics = "".join(logs)
    if "/sub 响应微缓存命中。" not in diagnostics:
        raise AssertionError("microcache Vary probe did not hit the response cache")
    assert_coalesced_request_link(
        diagnostics, coalesced_request_ids, "coalesced Vary probe"
    )


def explain_privacy_and_cache_baseline(binary: Path, fixture_base: str) -> None:
    logs: list[str] = []
    configured_device_secret = "configured-device-secret"
    request_secrets = (
        configured_device_secret,
        "upload-path-secret",
        "groups-secret",
        "ruleset-secret",
        "rename-secret",
        "profile-secret",
        "profile-query-secret",
        "token-secret",
        "unknown-secret",
        "unicode-unknown-secret",
        "provider-source-secret",
        "anonymous-provider-secret",
        "early-error-secret",
    )
    response_ids: list[str] = []
    with running_service(
        binary,
        log_capture=logs,
        log_level="debug",
        config_replacements=(
            (
                'quanx_device_id = ""',
                f'quanx_device_id = "{configured_device_secret}"',
            ),
            ("write_managed_config = false", "write_managed_config = true"),
            ("response_cache_ttl = 0", "response_cache_ttl = 5"),
        ),
    ) as base_url:
        inspect_status, inspect_body, inspect_headers = request(
            base_url, "/inspect", {}
        )
        inspect_text = inspect_body.decode("utf-8", errors="replace")
        if (
            inspect_status != 200
            or "Source summary" not in inspect_text
            or "来源摘要" not in inspect_text
            or 'response.headers.get("X-Request-ID")' not in inspect_text
            or "Source hash" in inspect_text
        ):
            raise AssertionError("/inspect page diagnostics contract is stale")
        assert_request_id(inspect_headers, "/inspect page")

        params = {
            "target": "clash",
            "url": MIHOMO_ONLY_ROUTE_URI,
            "config": DISABLE_RULEGEN_CONFIG,
            "list": "true",
            "explain": "true",
            "dev_id": "",
            "upload_path": "upload-path-secret",
            "groups": "groups-secret",
            "ruleset": "ruleset-secret",
            "rename": "rename-secret",
            "profile_data": "profile-secret",
            "token": "token-secret",
            "private_api_key": "unknown-secret",
            "怪<script>": "unicode-unknown-secret",
        }
        reports: list[dict[str, object]] = []
        for label in ("explain first", "explain repeated"):
            status, body, headers = request(base_url, "/sub", params)
            if status != 200:
                raise AssertionError(
                    f"{label} returned HTTP {status}: {body[-1000:]!r}"
                )
            if "no-store" not in headers.get("cache-control", ""):
                raise AssertionError(f"{label} is missing Cache-Control: no-store")
            if headers.get("pragma", "").lower() != "no-cache":
                raise AssertionError(f"{label} is missing Pragma: no-cache")
            response_ids.append(assert_request_id(headers, label))
            decoded = body.decode("utf-8", errors="replace")
            for secret in request_secrets:
                if secret in decoded:
                    raise AssertionError(f"{label} leaked secret {secret!r}")
            reports.append(json.loads(body))

        if len(set(response_ids)) != len(response_ids):
            raise AssertionError("repeated explain responses reused a request ID")
        independently_executed_ids = tuple(response_ids)

        recognized = {
            item["name"]: item
            for item in reports[0].get("parameters", {}).get("recognized", [])
        }
        for name in (
            "url",
            "config",
            "dev_id",
            "upload_path",
            "groups",
            "ruleset",
            "rename",
            "profile_data",
            "token",
        ):
            item = recognized.get(name)
            if item is None or item.get("sensitive") is not True:
                raise AssertionError(f"explain did not mark {name} sensitive: {item!r}")
            if item.get("value_hash") != "":
                raise AssertionError(f"explain retained a stable hash for {name}")
            if item.get("value_preview") not in ("", "[redacted]"):
                raise AssertionError(f"explain exposed a preview for {name}: {item!r}")
        if recognized["dev_id"].get("effective_value") != "configured":
            raise AssertionError("configured device ID lost its safe presence summary")
        if (
            recognized["dev_id"].get("source") != "default"
            or recognized["dev_id"].get("status") != "defaulted"
        ):
            raise AssertionError(
                "empty request device ID was not attributed to the configured default"
            )
        if (
            recognized["config"].get("source") != "request"
            or recognized["config"].get("status") != "applied"
            or f"scheme=data length={len(DISABLE_RULEGEN_CONFIG)}"
            not in recognized["config"].get("effective_value", "")
        ):
            raise AssertionError(
                f"external config source diagnostics are inaccurate: {recognized['config']!r}"
            )
        if (
            f"scheme=socks5 length={len(MIHOMO_ONLY_ROUTE_URI)}"
            not in recognized["url"].get("effective_value", "")
        ):
            raise AssertionError(
                f"direct source lost its safe URL summary: {recognized['url']!r}"
            )
        if (
            recognized["profile_data"].get("status") != "ignored"
            or recognized["profile_data"].get("effective_value") != "not used"
        ):
            raise AssertionError(
                "profile_data was reported as effective for Clash output"
            )

        default_config_params = dict(params)
        default_config_params["config"] = ""
        default_status, default_body, default_headers = request(
            base_url, "/sub", default_config_params
        )
        if default_status != 200:
            raise AssertionError(
                "empty config explain failed: "
                f"HTTP {default_status}: {default_body[-1000:]!r}"
            )
        default_report = json.loads(default_body)
        default_text = default_body.decode("utf-8", errors="replace")
        for secret in request_secrets:
            if secret in default_text:
                raise AssertionError(
                    f"empty config explain leaked secret {secret!r}"
                )
        default_parameters = {
            item["name"]: item
            for item in default_report.get("parameters", {}).get("recognized", [])
        }
        default_config = default_parameters.get("config", {})
        if (
            default_config.get("source") != "default"
            or default_config.get("status") != "defaulted"
            or default_config.get("effective_value") != "loaded"
        ):
            raise AssertionError(
                f"empty config was not attributed to the default: {default_config!r}"
            )
        if "no-store" not in default_headers.get("cache-control", ""):
            raise AssertionError("empty config explain lost no-store")
        response_ids.append(
            assert_request_id(default_headers, "empty config explain")
        )
        for name in ("groups", "ruleset"):
            if (
                recognized[name].get("status") != "ignored"
                or recognized[name].get("effective_value") != "not consumed"
            ):
                raise AssertionError(
                    f"unused compatibility parameter {name} was reported as applied"
                )

        unrecognized = reports[0].get("parameters", {}).get("unrecognized", [])
        private_key = next(
            (item for item in unrecognized if item.get("name") == "private_api_key"),
            None,
        )
        if (
            private_key is None
            or private_key.get("sensitive") is not True
            or private_key.get("value_preview") != "[redacted]"
            or private_key.get("value_hash") != ""
        ):
            raise AssertionError(
                f"unknown sensitive parameter was not fail-closed: {private_key!r}"
            )
        redacted_name = next(
            (item for item in unrecognized if item.get("name") == "[redacted-name]"),
            None,
        )
        if redacted_name is None or redacted_name.get("value_preview") != "[redacted]":
            raise AssertionError(
                f"unsafe unknown parameter name was not redacted: {redacted_name!r}"
            )

        error_status, error_body, error_headers = request(
            base_url,
            "/sub",
            {
                "target": "unsupported-target",
                "url": "https://user:pass@example.test/sub?token=early-error-secret",
                "explain": " true ",
            },
        )
        if error_status != 400:
            raise AssertionError(
                f"early explain error returned HTTP {error_status}: {error_body[-1000:]!r}"
            )
        if (
            "no-store" not in error_headers.get("cache-control", "")
            or error_headers.get("pragma", "").lower() != "no-cache"
        ):
            raise AssertionError("early explain error lost privacy cache headers")
        response_ids.append(assert_request_id(error_headers, "early explain error"))
        if b"early-error-secret" in error_body:
            raise AssertionError("early explain error leaked its source secret")

        head_status, head_body, head_headers = request(
            base_url, "/sub", params, method="HEAD"
        )
        if head_status != 200 or head_body:
            raise AssertionError(
                f"explain HEAD failed: HTTP {head_status}: {head_body[-1000:]!r}"
            )
        if (
            "no-store" not in head_headers.get("cache-control", "")
            or head_headers.get("pragma", "").lower() != "no-cache"
        ):
            raise AssertionError("explain HEAD lost privacy cache headers")
        response_ids.append(assert_request_id(head_headers, "explain HEAD"))

        provider_status, provider_body, provider_headers = request(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": (
                    "provider:ExplainPrivate,"
                    + fixture_base
                    + "/subscription.txt?token=provider-source-secret"
                ),
                "config": DISABLE_RULEGEN_CONFIG,
                "include": "Smoke",
                "exclude": "Expired",
                "explain": "true",
            },
        )
        if provider_status != 200:
            raise AssertionError(
                "provider explain failed: "
                f"HTTP {provider_status}: {provider_body[-1000:]!r}"
            )
        if "no-store" not in provider_headers.get("cache-control", ""):
            raise AssertionError("provider explain is missing no-store")
        response_ids.append(assert_request_id(provider_headers, "provider explain"))
        provider_text = provider_body.decode("utf-8", errors="replace")
        if "provider-source-secret" in provider_text:
            raise AssertionError("provider explain leaked its source query")
        providers = json.loads(provider_body).get("providers", [])
        if len(providers) != 1:
            raise AssertionError(f"provider explain mismatch: {providers!r}")
        provider = providers[0]
        if (
            provider.get("source_hash") != ""
            or provider.get("filter") != ""
            or provider.get("exclude_filter") != ""
            or provider.get("filter_present") is not True
            or provider.get("exclude_filter_present") is not True
            or provider.get("name_generated") is not False
            or "host=127.0.0.1" not in provider.get("source_summary", "")
        ):
            raise AssertionError(
                f"provider explain did not retain a safe structural summary: {provider!r}"
            )

        anonymous_provider_url = (
            fixture_base
            + "/subscription.txt?token=anonymous-provider-secret"
        )
        anonymous_provider_hash = hashlib.md5(
            urllib.parse.unquote(anonymous_provider_url).encode("utf-8")
        ).hexdigest()[:6].upper()
        anonymous_status, anonymous_body, anonymous_headers = request(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": anonymous_provider_url,
                "config": DISABLE_RULEGEN_CONFIG,
                "explain": "true",
            },
        )
        if anonymous_status != 200:
            raise AssertionError(
                "anonymous provider explain failed: "
                f"HTTP {anonymous_status}: {anonymous_body[-1000:]!r}"
            )
        anonymous_text = anonymous_body.decode("utf-8", errors="replace")
        if (
            "anonymous-provider-secret" in anonymous_text
            or f"Provider_{anonymous_provider_hash}" in anonymous_text
        ):
            raise AssertionError(
                "anonymous provider explain retained its source secret or stable hash"
            )
        anonymous_providers = json.loads(anonymous_body).get("providers", [])
        if len(anonymous_providers) != 1:
            raise AssertionError(
                f"anonymous provider explain mismatch: {anonymous_providers!r}"
            )
        anonymous_provider = anonymous_providers[0]
        if (
            anonymous_provider.get("name") != "Provider_Auto_1"
            or anonymous_provider.get("path")
            != "./providers/Provider_Auto_1.yaml"
            or anonymous_provider.get("name_generated") is not True
            or anonymous_provider.get("source_hash") != ""
            or "host=127.0.0.1"
            not in anonymous_provider.get("source_summary", "")
        ):
            raise AssertionError(
                "anonymous provider explain did not use a request-local safe name: "
                f"{anonymous_provider!r}"
            )
        response_ids.append(
            assert_request_id(anonymous_headers, "anonymous provider explain")
        )

        decoded_profile_url = (
            "https://managed.example.test/sub?token=profile-query-secret"
        )
        encoded_profile_url = base64.b64encode(
            decoded_profile_url.encode("utf-8")
        ).decode("ascii")
        profile_status, profile_body, profile_headers = request(
            base_url,
            "/sub",
            {
                "target": "surge",
                "url": fixture_base + "/subscription.txt",
                "config": DISABLE_RULEGEN_CONFIG,
                "profile_data": encoded_profile_url,
                "explain": "true",
            },
        )
        if profile_status != 200:
            raise AssertionError(
                "managed profile explain failed: "
                f"HTTP {profile_status}: {profile_body[-1000:]!r}"
            )
        profile_text = profile_body.decode("utf-8", errors="replace")
        if "profile-query-secret" in profile_text or encoded_profile_url in profile_text:
            raise AssertionError("managed profile explain leaked profile_data")
        profile_parameters = {
            item["name"]: item
            for item in json.loads(profile_body)
            .get("parameters", {})
            .get("recognized", [])
        }
        profile_parameter = profile_parameters.get("profile_data", {})
        if (
            profile_parameter.get("source") != "request"
            or profile_parameter.get("status") != "applied"
            or "scheme=https host=managed.example.test"
            not in profile_parameter.get("effective_value", "")
            or f"length={len(decoded_profile_url)}"
            not in profile_parameter.get("effective_value", "")
        ):
            raise AssertionError(
                "managed profile source diagnostics are inaccurate: "
                f"{profile_parameter!r}"
            )
        if "no-store" not in profile_headers.get("cache-control", ""):
            raise AssertionError("managed profile explain lost no-store")
        response_ids.append(
            assert_request_id(profile_headers, "managed profile explain")
        )

        FixtureHandler.slow_subscription_started.clear()
        FixtureHandler.slow_subscription_release.clear()
        coalesced_results: list[tuple[int, bytes, dict[str, str]]] = []
        coalesced_errors: list[BaseException] = []
        slow_params = {
            "target": "singbox",
            "url": fixture_base + "/slow-subscription.txt?case=explain-coalesce",
            "config": DISABLE_RULEGEN_CONFIG,
            "explain": "true",
        }

        def run_explain_request() -> None:
            try:
                coalesced_results.append(request(base_url, "/sub", slow_params))
            except BaseException as error:
                coalesced_errors.append(error)

        owner = threading.Thread(target=run_explain_request)
        waiter = threading.Thread(target=run_explain_request)
        owner.start()
        if not FixtureHandler.slow_subscription_started.wait(timeout=10):
            FixtureHandler.slow_subscription_release.set()
            owner.join(timeout=5)
            raise AssertionError("coalesced explain owner did not reach the fixture")
        waiter.start()
        time.sleep(0.2)
        FixtureHandler.slow_subscription_release.set()
        owner.join(timeout=20)
        waiter.join(timeout=20)
        if owner.is_alive() or waiter.is_alive():
            raise AssertionError("coalesced explain requests did not finish")
        if coalesced_errors:
            raise coalesced_errors[0]
        if len(coalesced_results) != 2:
            raise AssertionError("coalesced explain returned an unexpected result count")
        coalesced_ids: list[str] = []
        for status, body, headers in coalesced_results:
            if status != 200 or json.loads(body).get("nodes", {}).get("total", 0) < 1:
                raise AssertionError(
                    f"coalesced explain failed: HTTP {status}: {body[-1000:]!r}"
                )
            if "no-store" not in headers.get("cache-control", ""):
                raise AssertionError("coalesced explain response lost no-store")
            coalesced_ids.append(assert_request_id(headers, "coalesced explain"))
        if len(set(coalesced_ids)) != 2:
            raise AssertionError("coalesced explain responses reused a request ID")
        response_ids.extend(coalesced_ids)

    diagnostics = "".join(logs)
    for secret in request_secrets:
        if secret in diagnostics:
            raise AssertionError(f"explain service log leaked secret {secret!r}")
    for request_id in independently_executed_ids:
        if f"request_id={request_id} EXPLAIN_REQUEST_RECEIVED" not in diagnostics:
            raise AssertionError(
                "repeated explain request did not execute independently: "
                + request_id
            )
    if "/sub 响应微缓存命中。" in diagnostics:
        raise AssertionError("explain response entered the response microcache")
    assert_coalesced_request_link(
        diagnostics, coalesced_ids, "identical in-flight explain requests"
    )
    if f"Provider_{anonymous_provider_hash}" in diagnostics:
        raise AssertionError("anonymous provider stable hash leaked into diagnostics")
    if len(set(response_ids)) != len(response_ids):
        raise AssertionError("explain requests reused request correlation IDs")


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


def provider_direct_default_output_baseline(base_url: str, fixture_base: str) -> None:
    source = fixture_base + "/subscription.txt"

    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": f"provider:DefaultDirect,{source}?case=default-direct",
            "config": DISABLE_RULEGEN_CONFIG,
        },
    )
    output = body.decode("utf-8", errors="replace")
    if status != 200 or not provider_proxy_direct_from_output(
        output, "DefaultDirect"
    ):
        raise AssertionError(
            "the compatibility default no longer emits proxy: DIRECT"
        )

    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": f"provider:RequestFalse,{source}?case=request-false",
            "config": DISABLE_RULEGEN_CONFIG,
            "provider_proxy_direct": "false",
        },
    )
    output = body.decode("utf-8", errors="replace")
    if status != 200 or provider_proxy_direct_from_output(output, "RequestFalse"):
        raise AssertionError(
            "the existing provider_proxy_direct=false request parameter regressed"
        )

    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": "|".join(
                (
                    f"provider:LinkFalse,proxy_direct:false,{source}?case=link-false",
                    f"provider:LinkTrue,proxy_direct:true,{source}?case=link-true",
                    f"provider:RequestFallback,{source}?case=request-fallback",
                )
            ),
            "config": DISABLE_RULEGEN_CONFIG,
            "provider_proxy_direct": "false",
        },
    )
    output = body.decode("utf-8", errors="replace")
    if status != 200:
        raise AssertionError(
            f"mixed provider direct request returned HTTP {status}: {output!r}"
        )
    expected_direct = {
        "LinkFalse": False,
        "LinkTrue": True,
        "RequestFallback": False,
    }
    for provider_name, expected in expected_direct.items():
        actual = provider_proxy_direct_from_output(output, provider_name)
        if actual is not expected:
            raise AssertionError(
                f"{provider_name} proxy_direct mismatch: {actual} != {expected}"
            )

    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": f"provider:ExplainDirect,proxy_direct:false,{source}?case=explain",
            "config": DISABLE_RULEGEN_CONFIG,
            "explain": "true",
        },
    )
    if status != 200:
        raise AssertionError(f"proxy_direct explain returned HTTP {status}: {body!r}")
    report = json.loads(body)
    providers = report.get("providers", [])
    if len(providers) != 1:
        raise AssertionError(f"proxy_direct explain provider mismatch: {providers!r}")
    if (
        providers[0].get("proxy_direct") is not False
        or providers[0].get("proxy_field_emitted") is not False
    ):
        raise AssertionError(
            f"proxy_direct explain did not report field omission: {providers[0]!r}"
        )


def provider_interval_output_baseline(base_url: str, fixture_base: str) -> None:
    source = fixture_base + "/subscription.txt"
    multi_url = "|".join(
        (
            f"provider:Zero,interval:0,proxy_direct:false,{source}?case=zero",
            f"proxy_direct:true,interval:21600,provider:Slow,{source}?case=slow",
            f"tag:Tagged,proxy_direct:0,interval:1800,provider:Ordered,{source}?case=ordered",
            f"provider:Default,{source}?case=default",
        )
    )
    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": multi_url,
            "config": DISABLE_RULEGEN_CONFIG,
        },
    )
    output = body.decode("utf-8", errors="replace")
    if status != 200:
        raise AssertionError(
            f"multi-provider interval request returned HTTP {status}: {output!r}"
        )
    for provider_name, expected in {
        "Zero": 0,
        "Slow": 21600,
        "Ordered": 1800,
        "Default": 7200,
    }.items():
        actual = provider_interval_from_output(output, provider_name)
        if actual != expected:
            raise AssertionError(
                f"{provider_name} interval mismatch: {actual} != {expected}"
            )
    for provider_name, expected in {
        "Zero": False,
        "Slow": True,
        "Ordered": False,
        "Default": False,
    }.items():
        actual = provider_proxy_direct_from_output(output, provider_name)
        if actual is not expected:
            raise AssertionError(
                f"{provider_name} proxy_direct mismatch: {actual} != {expected}"
            )
    if output.count("      interval: 300") != 4:
        raise AssertionError("provider health-check intervals changed")

    encoded_value = urllib.parse.quote(
        f"provider:Encoded,interval:0,proxy_direct:false,{source}?case=encoded",
        safe="",
    )
    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": encoded_value,
            "config": DISABLE_RULEGEN_CONFIG,
        },
    )
    encoded_output = body.decode("utf-8", errors="replace")
    if (
        status != 200
        or provider_interval_from_output(encoded_output, "Encoded") != 0
        or provider_proxy_direct_from_output(encoded_output, "Encoded")
    ):
        raise AssertionError(
            f"encoded interval prefix failed: status={status}, body={encoded_output!r}"
        )

    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": f"provider:Managed,{source}?case=managed",
            "config": DISABLE_RULEGEN_CONFIG,
            "interval": "17",
        },
    )
    managed_output = body.decode("utf-8", errors="replace")
    if status != 200 or provider_interval_from_output(
        managed_output, "Managed"
    ) != 7200:
        raise AssertionError(
            "the existing request-level interval parameter changed provider interval"
        )
    if provider_proxy_direct_from_output(managed_output, "Managed"):
        raise AssertionError(
            "configured proxy_provider.proxy_direct=false was not applied"
        )

    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": f"provider:RequestTrue,{source}?case=request-true",
            "config": DISABLE_RULEGEN_CONFIG,
            "provider_proxy_direct": "true",
        },
    )
    request_true_output = body.decode("utf-8", errors="replace")
    if status != 200 or not provider_proxy_direct_from_output(
        request_true_output, "RequestTrue"
    ):
        raise AssertionError(
            "provider_proxy_direct=true did not override configured false"
        )

    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "clashr",
            "url": f"provider:ClashR,interval:0,proxy_direct:false,{source}?case=clashr",
            "config": DISABLE_RULEGEN_CONFIG,
        },
    )
    clashr_output = body.decode("utf-8", errors="replace")
    if (
        status != 200
        or provider_interval_from_output(clashr_output, "ClashR") != 0
        or provider_proxy_direct_from_output(clashr_output, "ClashR")
    ):
        raise AssertionError(
            f"ClashR provider interval failed: status={status}, body={clashr_output!r}"
        )

    secret = "private-token-issue-90"
    rejected_cases = (
        ("none", f"interval:none,https://example.invalid/sub?token={secret}"),
        ("negative", f"interval:-1,https://example.invalid/sub?token={secret}"),
        ("empty", f"interval:,https://example.invalid/sub?token={secret}"),
        ("overflow", f"interval:2147483648,https://example.invalid/sub?token={secret}"),
        ("duplicate", f"interval:0,interval:1,https://example.invalid/sub?token={secret}"),
        ("missing delimiter", f"interval:0https://example.invalid/sub?token={secret}"),
    )
    for label, source_value in rejected_cases:
        status, body, _ = request(
            base_url, "/sub", {"target": "clash", "url": source_value}
        )
        response = body.decode("utf-8", errors="replace")
        if status != 400:
            raise AssertionError(
                f"{label} interval returned HTTP {status}: {response!r}"
            )
        if secret in response:
            raise AssertionError(f"{label} interval leaked the subscription token")

    direct_rejected_cases = (
        ("none", f"proxy_direct:none,https://example.invalid/sub?token={secret}"),
        ("empty", f"proxy_direct:,https://example.invalid/sub?token={secret}"),
        (
            "duplicate",
            f"proxy_direct:true,proxy_direct:false,https://example.invalid/sub?token={secret}",
        ),
        (
            "missing delimiter",
            f"proxy_direct:falsehttps://example.invalid/sub?token={secret}",
        ),
    )
    for label, source_value in direct_rejected_cases:
        status, body, _ = request(
            base_url, "/sub", {"target": "clash", "url": source_value}
        )
        response = body.decode("utf-8", errors="replace")
        if status != 400:
            raise AssertionError(
                f"{label} proxy_direct returned HTTP {status}: {response!r}"
            )
        if secret in response:
            raise AssertionError(
                f"{label} proxy_direct leaked the subscription token"
            )

    scope_cases = (
        (
            "direct node",
            {"target": "clash", "url": f"interval:0,{SUBSCRIPTION.strip()}"},
        ),
        (
            "list=true",
            {"target": "clash", "url": f"interval:0,{source}", "list": "true"},
        ),
        (
            "non-Clash target",
            {"target": "surge", "url": f"interval:0,{source}", "list": "true"},
        ),
    )
    for label, params in scope_cases:
        status, body, _ = request(base_url, "/sub", params)
        if status != 400:
            raise AssertionError(
                f"interval on {label} returned HTTP {status}: {body!r}"
            )

    direct_scope_cases = (
        (
            "direct node",
            {
                "target": "clash",
                "url": f"proxy_direct:false,{SUBSCRIPTION.strip()}",
            },
        ),
        (
            "list=true",
            {
                "target": "clash",
                "url": f"proxy_direct:false,{source}",
                "list": "true",
            },
        ),
        (
            "non-Clash target",
            {
                "target": "surge",
                "url": f"proxy_direct:false,{source}",
            },
        ),
    )
    for label, params in direct_scope_cases:
        status, body, _ = request(base_url, "/sub", params)
        if status != 400:
            raise AssertionError(
                f"proxy_direct on {label} returned HTTP {status}: {body!r}"
            )


def dashboard_baseline(binary: Path, fixture_base: str) -> None:
    with running_service(
        binary,
        statistics=True,
        runtime_details=True,
        legacy_statistics=True,
    ) as runtime:
        base_url, statistics_path = runtime
        status, _, headers = request(base_url, "/dashboard")
        if status != 401 or "no-store" not in headers.get("cache-control", ""):
            raise AssertionError("Dashboard missing-auth baseline failed")
        token = base64.b64encode(
            b"fixture-admin:fixture-dashboard-secret"
        ).decode()
        status, body, page_headers = request(
            base_url, "/dashboard", headers={"Authorization": "Basic " + token}
        )
        if status != 200 or b"SubConverter-Extended Dashboard" not in body:
            raise AssertionError("Dashboard valid-auth baseline failed")
        if (
            len(body) != 100487
            or hashlib.sha256(body).hexdigest()
            != "265cbce59394ec1e966bdd137bd79e993768eaf7f95260700ee287957b503908"
        ):
            raise AssertionError("Dashboard HTTP response bytes changed")
        expected_page_headers = {
            "cache-control": (
                "no-store, no-cache, must-revalidate, proxy-revalidate, "
                "max-age=0, s-maxage=0"
            ),
            "pragma": "no-cache",
            "expires": "0",
            "surrogate-control": "no-store",
            "x-accel-expires": "0",
            "x-robots-tag": (
                "noindex, nofollow, noarchive, nosnippet, noimageindex"
            ),
            "content-type": "text/html; charset=utf-8",
        }
        for header, expected in expected_page_headers.items():
            if page_headers.get(header) != expected:
                raise AssertionError(
                    f"Dashboard {header} changed: {page_headers.get(header)!r}"
                )
        auth_headers = {"Authorization": "Basic " + token}
        status, first_body, first_headers = request(
            base_url, "/dashboard/data", headers=auth_headers
        )
        if status != 200 or "no-store" not in first_headers.get("cache-control", ""):
            raise AssertionError("Dashboard data cache-control baseline failed")
        data = json.loads(first_body)
        required_top_level = {
            "enabled",
            "generated_at",
            "started_at",
            "runtime",
            "windows",
            "country_windows",
            "countries",
            "china_region_windows",
            "china_regions",
            "series",
        }
        if not required_top_level.issubset(data):
            raise AssertionError(
                f"Dashboard data fields changed: {required_top_level - set(data)}"
            )
        window_names = {
            "startup",
            "hour",
            "day",
            "seven_days",
            "thirty_days",
            "half_year",
            "year",
            "lifetime",
        }
        if set(data["windows"]) != window_names:
            raise AssertionError("Dashboard window names changed")
        for window in data["windows"].values():
            if (
                not isinstance(window.get("subscription_requests"), int)
                or not isinstance(window.get("rule_conversions"), int)
            ):
                raise AssertionError("Dashboard counter types changed")
        if len(data["series"]) != 24 or not isinstance(data.get("revision"), int):
            raise AssertionError("Dashboard series/revision compatibility failed")
        status, second_body, _ = request(
            base_url, "/dashboard/data", headers=auth_headers
        )
        if status != 200 or second_body != first_body:
            raise AssertionError("Dashboard clients did not share the one-second snapshot")

        status, _, _ = request(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": fixture_base + "/subscription.txt",
                "config": DISABLE_RULEGEN_CONFIG,
                "list": "true",
            },
        )
        if status != 200:
            raise AssertionError("statistics-enabled /sub compatibility failed")
        time.sleep(1.1)
        status, updated_body, _ = request(
            base_url, "/dashboard/data", headers=auth_headers
        )
        updated = json.loads(updated_body)
        if (
            status != 200
            or updated["revision"] <= data["revision"]
            or updated["windows"]["lifetime"]["subscription_requests"] != 1
        ):
            raise AssertionError("Dashboard revision/request accounting failed")
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            checkpoints = list(
                statistics_path.glob("statistics-v2-*.bin")
            )
            wal = statistics_path / "statistics-v2.wal"
            if (
                checkpoints
                and wal.is_file()
                and wal.stat().st_size > 0
                and not (statistics_path / "statistics.json").exists()
            ):
                break
            time.sleep(0.1)
        else:
            raise AssertionError(
                "Statistics v2 checkpoint/WAL creation or legacy cleanup failed"
            )
        for expected in (401, 401, 429):
            status, _, _ = request(
                base_url,
                "/dashboard",
                headers={"Authorization": "Basic invalid"},
            )
            if status != expected:
                raise AssertionError(
                    f"Dashboard lockout expected HTTP {expected}, got {status}"
                )


def dashboard_client_ip_security_baseline(binary: Path, fixture_base: str) -> None:
    spoof_headers = (
        ("CF-Connecting-IP", "198.51.100.1"),
        ("True-Client-IP", "198.51.100.2"),
        ("X-Real-IP", "198.51.100.3"),
        ("X-Forwarded-For", "198.51.100.4"),
        ("X-Client-IP", "198.51.100.5"),
    )
    with running_service(
        binary,
        statistics=True,
        dashboard_client_ip_header="x-forwarded-for",
        dashboard_trusted_proxy_cidrs=("10.0.0.0/8",),
    ) as base_url:
        for expected, rotated in zip((401, 401, 429), spoof_headers):
            status, _, _ = request(
                base_url,
                "/dashboard",
                headers={
                    "Authorization": "Basic invalid",
                    rotated[0]: rotated[1],
                },
            )
            if status != expected:
                raise AssertionError(
                    "direct client bypassed peer bucket by rotating proxy "
                    f"headers: expected {expected}, got {status}"
                )

    with running_service(
        binary,
        statistics=True,
        dashboard_client_ip_header="x-forwarded-for",
        dashboard_trusted_proxy_cidrs=("127.0.0.1/32",),
    ) as base_url:
        client_a = "192.0.2.10, 127.0.0.1"
        client_b = "192.0.2.11, 127.0.0.1"
        for value in (client_a, client_b, client_a, client_b):
            status, _, _ = request(
                base_url,
                "/dashboard",
                headers={
                    "Authorization": "Basic invalid",
                    "X-Forwarded-For": value,
                },
            )
            if status != 401:
                raise AssertionError(
                    "trusted-proxy clients did not receive independent buckets"
                )

        token = base64.b64encode(
            b"fixture-admin:fixture-dashboard-secret"
        ).decode()
        status, body, _ = request(
            base_url,
            "/dashboard",
            headers={
                "Authorization": "Basic " + token,
                "X-Forwarded-For": client_a,
            },
        )
        if status != 200:
            raise AssertionError("successful auth did not clear the client bucket")
        status, _, _ = request(
            base_url,
            "/dashboard",
            headers={
                "Authorization": "Basic invalid",
                "X-Forwarded-For": client_a,
            },
        )
        if status != 401:
            raise AssertionError("client bucket was not reset after successful auth")
        status, _, _ = request(
            base_url,
            "/dashboard",
            headers={
                "Authorization": "Basic invalid",
                "X-Forwarded-For": client_b,
            },
        )
        if status != 429:
            raise AssertionError("third failure did not lock the second proxy client")

        duplicate_status = request_with_raw_headers(
            base_url,
            "/dashboard",
            [
                ("Authorization", "Basic invalid"),
                ("X-Forwarded-For", "192.0.2.20"),
                ("x-forwarded-for", "192.0.2.21"),
            ],
        )
        if duplicate_status != 401:
            raise AssertionError(
                "duplicate selected client-IP headers did not fail closed to peer"
            )

        status, _, _ = request(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": fixture_base + "/subscription.txt",
                "config": DISABLE_RULEGEN_CONFIG,
                "list": "true",
            },
        )
        if status != 200:
            raise AssertionError("client-IP policy changed /sub behavior")


def classic_protocol_baseline(base_url: str, fixture_base: str) -> None:
    def convert_text(target: str, source: str) -> str:
        status, body, _ = request(
            base_url,
            "/sub",
            {"target": target, "url": source, "list": "true"},
        )
        if status != 200:
            raise AssertionError(
                f"classic target={target} returned HTTP {status}: {body!r}"
            )
        return body.decode("utf-8").replace("\r\n", "\n")

    def decode_urlsafe(value: str) -> str:
        try:
            return base64.urlsafe_b64decode(
                value + "=" * (-len(value) % 4)
            ).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as error:
            raise AssertionError(f"invalid URL-safe Base64: {value!r}") from error

    ss_output = convert_text("ss", "|".join((SS_SIP002_URI, SS_2022_URI)))
    ss_lines = [line for line in ss_output.splitlines() if line]
    if len(ss_lines) != 2:
        raise AssertionError(f"classic SS conversion lost a node: {ss_output!r}")
    sip002_line = next(
        (line for line in ss_lines if line.endswith("#SS%20SIP002")), ""
    )
    if not sip002_line:
        raise AssertionError(f"SIP002 remark was not preserved: {ss_output!r}")
    sip002_userinfo = sip002_line.removeprefix("ss://").split("@", 1)[0]
    if decode_urlsafe(sip002_userinfo) != "aes-256-gcm:p@ss+word":
        raise AssertionError(f"SIP002 userinfo changed: {sip002_line!r}")
    sip002_parts = urllib.parse.urlsplit(sip002_line)
    sip002_query = urllib.parse.parse_qs(
        sip002_parts.query, keep_blank_values=True
    )
    expected_plugin = (
        "v2ray-plugin;mode=websocket;host=plugin.example.test;path=/ws;tls"
    )
    if (
        sip002_parts.hostname != "2001:db8::21"
        or sip002_parts.port != 8388
        or sip002_query.get("plugin") != [expected_plugin]
    ):
        raise AssertionError(
            f"SIP002 IPv6/plugin mapping changed: {sip002_line!r}"
        )

    ss2022_line = next(
        (line for line in ss_lines if line.endswith("#SS%202022")), ""
    )
    expected_2022_prefix = (
        "ss://2022-blake3-aes-256-gcm:"
        + urllib.parse.quote(SS_2022_PASSWORD, safe="")
        + "@[2001:db8::22]:8389"
    )
    if not ss2022_line.startswith(expected_2022_prefix):
        raise AssertionError(
            "Shadowsocks 2022 credentials were incorrectly Base64-wrapped: "
            f"{ss2022_line!r}"
        )

    quan_status, quan_body, _ = request(
        base_url,
        "/sub",
        {"target": "quan", "url": SS_SIP002_URI, "list": "true"},
    )
    quan_line = decode_urlsafe(
        quan_body.decode("utf-8", errors="replace").strip()
    ).strip()
    quan_parts = urllib.parse.urlsplit(quan_line)
    quan_query = urllib.parse.parse_qs(quan_parts.query, keep_blank_values=True)
    if (
        quan_status != 200
        or quan_query.get("plugin") != [expected_plugin]
        or decode_urlsafe(quan_query.get("group", [""])[0]) != "SSProvider"
        or ":8388&group=" in quan_line
    ):
        raise AssertionError(
            f"Quantumult SS nodelist query is malformed: {quan_line!r}"
        )

    sip008_object_output = convert_text("ss", fixture_base + "/sip008.json")
    if (
        "@[2001:db8::30]:8388/" not in sip008_object_output
        or "plugin=v2ray-plugin%3Bmode%3Dwebsocket" not in sip008_object_output
        or "#SIP008%20Plugin" not in sip008_object_output
    ):
        raise AssertionError(
            f"SIP008 object input was not preserved: {sip008_object_output!r}"
        )

    sip008_array_output = convert_text("ss", fixture_base + "/sip008-array.json")
    if not sip008_array_output.startswith(
        "ss://2022-blake3-aes-256-gcm:"
        + urllib.parse.quote(SS_2022_PASSWORD, safe="")
        + "@[2001:db8::31]:8391"
    ):
        raise AssertionError(
            f"SIP008 root-array input was not recognized: {sip008_array_output!r}"
        )

    sssub_status, sssub_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "sssub",
            "url": fixture_base + "/sip008.json",
            "list": "true",
        },
    )
    try:
        sssub = json.loads(sssub_body)
    except json.JSONDecodeError as error:
        raise AssertionError(
            f"SS subscription output is not JSON: {sssub_body!r}"
        ) from error
    if (
        sssub_status != 200
        or not isinstance(sssub, list)
        or len(sssub) != 1
        or sssub[0].get("password") != "sip008-password"
        or sssub[0].get("plugin") != "v2ray-plugin"
    ):
        raise AssertionError(f"SS subscription output changed: {sssub!r}")

    ssr_output = convert_text("ssr", SSR_IPV6_URI).strip()
    if not ssr_output.startswith("ssr://"):
        raise AssertionError(f"SSR output is not a share link: {ssr_output!r}")
    decoded_ssr = decode_urlsafe(ssr_output.removeprefix("ssr://"))
    for expected in (
        "[2001:db8::23]:8390:auth_sha1_v4:aes-256-cfb:tls1.2_ticket_auth:",
        "group=" + _urlsafe_b64("SSR Fixture"),
        "remarks=" + _urlsafe_b64("SSR IPv6"),
        "obfsparam=" + _urlsafe_b64("cdn.example.test"),
        "protoparam=" + _urlsafe_b64("64:fixture"),
    ):
        if expected not in decoded_ssr:
            raise AssertionError(f"SSR output lost {expected!r}: {decoded_ssr!r}")

    ssr_json_output = convert_text(
        "ssr", fixture_base + "/ssr-libev.json"
    ).strip()
    decoded_ssr_json = decode_urlsafe(ssr_json_output.removeprefix("ssr://"))
    if (
        "[2001:db8::32]:8392:auth_sha1_v4:aes-256-cfb:tls1.2_ticket_auth:"
        not in decoded_ssr_json
        or _urlsafe_b64("ssr-json-password") not in decoded_ssr_json
    ):
        raise AssertionError(
            f"SSR libev password/IPv6 input was lost: {decoded_ssr_json!r}"
        )

    classic_nodes = "|".join(
        (
            SS_SIP002_URI,
            SS_2022_URI,
            SOCKS_CURRENT_URI,
            SOCKS_LEGACY_URI,
            SOCKS_PLAIN_URI,
            SOCKS_NO_AUTH_URI,
            HTTP_LEGACY_URI,
            HTTPS_LEGACY_URI,
            TELEGRAM_SOCKS_URI,
            TELEGRAM_HTTP_URI,
        )
    )
    singbox_status, singbox_body, _ = request(
        base_url,
        "/sub",
        {"target": "singbox", "url": classic_nodes, "list": "true"},
    )
    try:
        singbox = json.loads(singbox_body)
    except json.JSONDecodeError as error:
        raise AssertionError(
            f"classic sing-box output is not JSON: {singbox_body!r}"
        ) from error
    if singbox_status != 200 or not isinstance(singbox, dict):
        raise AssertionError(
            f"classic sing-box conversion failed: HTTP {singbox_status} {singbox!r}"
        )
    outbounds = {
        item.get("tag"): item
        for item in singbox.get("outbounds", [])
        if isinstance(item, dict) and isinstance(item.get("tag"), str)
    }
    expected_outbounds = {
        "SS SIP002": {
            "type": "shadowsocks",
            "server": "2001:db8::21",
            "server_port": 8388,
            "method": "aes-256-gcm",
            "password": "p@ss+word",
            "plugin": "v2ray-plugin",
            "plugin_opts": expected_plugin.removeprefix("v2ray-plugin;"),
        },
        "SS 2022": {
            "type": "shadowsocks",
            "server": "2001:db8::22",
            "server_port": 8389,
            "method": "2022-blake3-aes-256-gcm",
            "password": SS_2022_PASSWORD,
        },
        "SOCKS Current": {
            "type": "socks",
            "server": "2001:db8::24",
            "server_port": 1080,
            "username": "current-user",
            "password": "p@ss+word:tail",
        },
        "SOCKS Legacy": {
            "type": "socks",
            "server": "2001:db8::25",
            "server_port": 1081,
            "username": "legacy-user",
            "password": "legacy-pass",
        },
        "SOCKS Plain": {
            "type": "socks",
            "server": "2001:db8::26",
            "server_port": 1082,
            "username": "plain-user",
            "password": "p@ss+word",
        },
        "SOCKS NoAuth": {
            "type": "socks",
            "server": "2001:db8::27",
            "server_port": 1083,
            "username": "",
            "password": "",
        },
        "HTTP Legacy": {
            "type": "http",
            "server": "2001:db8::28",
            "server_port": 8080,
            "username": "http-user",
            "password": "http-pass",
        },
        "HTTPS Legacy": {
            "type": "http",
            "server": "2001:db8::29",
            "server_port": 8443,
            "username": "https-user",
            "password": "https-pass",
        },
        "Telegram SOCKS": {
            "type": "socks",
            "server": "telegram-socks.example.test",
            "server_port": 1084,
            "username": "tg-user",
            "password": "tg+pass",
        },
        "Telegram HTTP": {
            "type": "http",
            "server": "telegram-http.example.test",
            "server_port": 8081,
            "username": "tg-http",
            "password": "tg+http",
        },
    }
    for tag, expected in expected_outbounds.items():
        actual = outbounds.get(tag)
        if actual is None or any(actual.get(key) != value for key, value in expected.items()):
            raise AssertionError(
                f"classic protocol mapping for {tag!r} is incomplete: {actual!r}"
            )

    mellow_status, mellow_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "mellow",
            "url": "|".join((SS_2022_URI, SOCKS_CURRENT_URI, HTTP_LEGACY_URI)),
            "list": "false",
        },
    )
    mellow = mellow_body.decode("utf-8", errors="replace")
    for expected in (
        "SS 2022, ss, ss://2022-blake3-aes-256-gcm:",
        "SOCKS Current, builtin, socks, address=2001:db8::24, port=1080, "
        "user=current-user, pass=p@ss+word:tail",
        "HTTP Legacy, builtin, http, address=2001:db8::28, port=8080, "
        "user=http-user, pass=http-pass",
    ):
        if expected not in mellow:
            raise AssertionError(
                f"Mellow classic endpoint lost {expected!r}: {mellow!r}"
            )
    if mellow_status != 200:
        raise AssertionError(
            f"Mellow classic conversion returned HTTP {mellow_status}: {mellow!r}"
        )

    unsafe_surge_uri = (
        "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:8388"
        "#Unsafe%2CInjected"
    )
    unsafe_surge_status, unsafe_surge_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "surge",
            "ver": "4",
            "url": unsafe_surge_uri,
            "list": "true",
        },
    )
    if unsafe_surge_status != 400 or b"Unsafe,Injected =" in unsafe_surge_body:
        raise AssertionError(
            "Surge accepted a comma-delimited Shadowsocks field: "
            f"HTTP {unsafe_surge_status} {unsafe_surge_body!r}"
        )

    for malformed in (
        "ss://not-base64@bad.example.test:70000#BadSS",
        "ssr://not-base64",
        "socks://not-base64#BadSOCKS",
        "http://not-base64?remarks=BadHTTP",
    ):
        status, _, _ = request(
            base_url,
            "/sub",
            {"target": "singbox", "url": malformed, "list": "true"},
        )
        if status != 400:
            raise AssertionError(
                f"malformed classic URI did not fail closed: {malformed!r} -> {status}"
            )


def simple_target_protocol_baseline(base_url: str, fixture_base: str) -> None:
    source = fixture_base + "/mixed-protocol-subscription.txt"

    def convert(target: str, url: str, list_mode: bool) -> str:
        status, body, _ = request(
            base_url,
            "/sub",
            {
                "target": target,
                "url": url,
                "list": "true" if list_mode else "false",
            },
        )
        if status != 200:
            raise AssertionError(
                f"target={target} list={list_mode} returned HTTP {status}: {body!r}"
            )
        if not list_mode:
            try:
                body = base64.b64decode(body)
            except ValueError as error:
                raise AssertionError(
                    f"target={target} did not return valid Base64"
                ) from error
        return body.decode("utf-8").replace("\r\n", "\n")

    vless = convert("vless", source, True)
    vless_lines = [line for line in vless.splitlines() if line]
    if not vless_lines or any(
        not line.startswith("vless://") for line in vless_lines
    ):
        raise AssertionError(f"VLESS target filtering is incorrect: {vless!r}")
    if "11111111-1111-1111-1111-111111111111" not in vless:
        raise AssertionError("VLESS target lost the fixture UUID")
    for expected in (
        "security=tls",
        "type=ws",
        "host=vless.example.test",
        "path=%2Fws",
    ):
        if expected not in vless:
            raise AssertionError(
                f"VLESS target lost {expected!r}: {vless!r}"
            )

    hysteria2 = convert("hysteria2", source, True)
    hysteria2_lines = [line for line in hysteria2.splitlines() if line]
    if not hysteria2_lines or any(
        not line.startswith("hysteria2://") for line in hysteria2_lines
    ):
        raise AssertionError(
            f"Hysteria2 target filtering is incorrect: {hysteria2!r}"
        )
    if "obfs=salamander" not in hysteria2:
        raise AssertionError(f"Hysteria2 output lost the obfs type: {hysteria2!r}")
    if "insecure=1" not in hysteria2:
        raise AssertionError("Hysteria2 output lost skip-cert-verify semantics")
    if "obfs-password=real-obfs-password" not in hysteria2:
        raise AssertionError(
            "Hysteria2 output did not preserve the real obfs password"
        )
    if "obfs-password=salamander" in hysteria2:
        raise AssertionError("Hysteria2 output reused the obfs type as its password")

    modern_hysteria2 = convert("hysteria2", HYSTERIA2_MODERN_URI, True).strip()
    if not modern_hysteria2.startswith(
        "hysteria2://user%3Apass%2Btoken@[2001:db8::10]:8443,12000-12002/"
    ):
        raise AssertionError(
            "modern Hysteria2 authority did not preserve IPv6, credentials, or "
            f"port hopping: {modern_hysteria2!r}"
        )
    modern_hy2_parts = urllib.parse.urlsplit(modern_hysteria2)
    modern_hy2_query = urllib.parse.parse_qs(
        modern_hy2_parts.query, keep_blank_values=True
    )
    for key, expected in {
        "insecure": ["1"],
        "obfs": ["salamander"],
        "obfs-password": ["obfs+secret"],
        "sni": ["hy2-tls.example.test"],
        "pinSHA256": ["AA:BB:CC"],
        "ech": ["AE+config/value"],
    }.items():
        if modern_hy2_query.get(key) != expected:
            raise AssertionError(
                f"modern Hysteria2 output lost {key}: {modern_hysteria2!r}"
            )
    if urllib.parse.unquote(modern_hy2_parts.fragment) != "Hy2 Modern+Literal":
        raise AssertionError("modern Hysteria2 output lost the decoded remark")

    def convert_json(target: str, url: str) -> dict[str, object]:
        status, body, _ = request(
            base_url,
            "/sub",
            {"target": target, "url": url, "list": "true"},
        )
        if status != 200:
            raise AssertionError(
                f"target={target} modern protocol conversion returned HTTP "
                f"{status}: {body!r}"
            )
        try:
            result = json.loads(body)
        except json.JSONDecodeError as error:
            raise AssertionError(
                f"target={target} did not return valid JSON: {body!r}"
            ) from error
        if not isinstance(result, dict):
            raise AssertionError(f"target={target} JSON is not an object: {result!r}")
        return result

    modern_singbox = convert_json(
        "singbox", "|".join((HYSTERIA2_MODERN_URI, TUIC_MODERN_URI, ANYTLS_MODERN_URI))
    )
    modern_outbounds = {
        item.get("type"): item
        for item in modern_singbox.get("outbounds", [])
        if isinstance(item, dict)
        and item.get("type") in {"hysteria2", "tuic", "anytls"}
    }
    if set(modern_outbounds) != {"hysteria2", "tuic", "anytls"}:
        raise AssertionError(
            f"sing-box lost a modern Legacy protocol: {modern_outbounds!r}"
        )

    hy2_outbound = modern_outbounds["hysteria2"]
    if (
        hy2_outbound.get("server") != "2001:db8::10"
        or hy2_outbound.get("server_port") is not None
        or hy2_outbound.get("server_ports") != ["8443:8443", "12000:12002"]
        or hy2_outbound.get("password") != "user:pass+token"
        or hy2_outbound.get("obfs")
        != {"type": "salamander", "password": "obfs+secret"}
        or hy2_outbound.get("tls", {}).get("server_name")
        != "hy2-tls.example.test"
        # The fixture runtime's explicit global scv=false remains authoritative
        # over per-node values in generated client configs.
        or hy2_outbound.get("tls", {}).get("insecure") is not False
    ):
        raise AssertionError(
            f"sing-box Hysteria2 mapping is incomplete: {hy2_outbound!r}"
        )

    tuic_outbound = modern_outbounds["tuic"]
    if (
        tuic_outbound.get("server") != "2001:db8::11"
        or tuic_outbound.get("server_port") != 10443
        or tuic_outbound.get("uuid")
        != "99999999-9999-4999-8999-999999999999"
        or tuic_outbound.get("password") != "p@ss+word"
        or tuic_outbound.get("congestion_control") != "bbr"
        or tuic_outbound.get("udp_relay_mode") != "quic"
        or tuic_outbound.get("zero_rtt_handshake") is not True
        or tuic_outbound.get("tls", {}).get("server_name")
        != "tuic-tls.example.test"
        or tuic_outbound.get("tls", {}).get("insecure") is not False
        or tuic_outbound.get("tls", {}).get("disable_sni") is not False
    ):
        raise AssertionError(f"sing-box TUIC mapping is incomplete: {tuic_outbound!r}")

    anytls_outbound = modern_outbounds["anytls"]
    if (
        anytls_outbound.get("server") != "2001:db8::12"
        or anytls_outbound.get("server_port") != 443
        or anytls_outbound.get("password") != "p@ss+word"
        or anytls_outbound.get("idle_session_check_interval") != "45s"
        or anytls_outbound.get("idle_session_timeout") != "60s"
        or anytls_outbound.get("min_idle_session") != 3
        or "network" in anytls_outbound
        or "tcp_fast_open" in anytls_outbound
        or anytls_outbound.get("tls", {}).get("server_name")
        != "anytls-tls.example.test"
        or anytls_outbound.get("tls", {}).get("insecure") is not False
        or anytls_outbound.get("tls", {}).get("alpn") != ["h2", "http/1.1"]
        or anytls_outbound.get("tls", {}).get("utls", {}).get("fingerprint")
        != "chrome"
    ):
        raise AssertionError(
            f"sing-box AnyTLS mapping is incomplete: {anytls_outbound!r}"
        )

    surge_status, surge_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "surge",
            "ver": "4",
            "url": "|".join(
                (HYSTERIA2_SURGE_GECKO_URI, TUIC_SURGE_URI, ANYTLS_MODERN_URI)
            ),
            "list": "true",
        },
    )
    surge_text = surge_body.decode("utf-8", errors="replace")
    if surge_status != 200 or not all(
        expected in surge_text
        for expected in (
            "password=user:pass+token",
            "sni=hy2-tls.example.test",
            "server-cert-fingerprint-sha256=AA:BB:CC",
            "gecko-password=obfs+secret",
            "port-hopping=8443;12000-12002",
            "tuic, 2001:db8::13, 11443, token=surge+token",
            "sni=tuic-surge.example.test",
            "alpn=h3",
            "anytls, 2001:db8::12, 443, password=p@ss+word",
            "sni=anytls-tls.example.test",
            "alpn=h2",
        )
    ):
        raise AssertionError(
            f"Surge modern protocol mapping is incomplete: HTTP {surge_status} "
            f"{surge_text!r}"
        )

    mixed = convert("mixed", source, True)
    mixed_lines = [line for line in mixed.splitlines() if line]
    if len(mixed_lines) != 3 or not all(
        any(line.startswith(prefix) for line in mixed_lines)
        for prefix in ("ss://", "vless://", "hysteria2://")
    ):
        raise AssertionError(f"mixed target lost a protocol: {mixed!r}")
    if "obfs-password=real-obfs-password" not in mixed:
        raise AssertionError("mixed output did not preserve Hysteria2 obfs password")

    xray_source = fixture_base + "/xray-protocol-subscription.txt"
    xray_mixed = convert("mixed", xray_source, True)
    xray_lines = [line for line in xray_mixed.splitlines() if line]
    if len(xray_lines) != 3 or not all(
        any(line.startswith(prefix) for line in xray_lines)
        for prefix in ("vmess://", "vless://", "trojan://")
    ):
        raise AssertionError(
            f"fetched Xray subscription lost a protocol: {xray_mixed!r}"
        )

    for target, uri, prefix in (
        ("vless", VLESS_URI, "vless://"),
        ("hysteria2", HYSTERIA2_URI, "hysteria2://"),
    ):
        direct = convert(target, uri, True)
        encoded = convert(target, source, False)
        if not direct.startswith(prefix):
            raise AssertionError(f"single-link {target} input failed: {direct!r}")
        if not encoded.startswith(prefix):
            raise AssertionError(
                f"Base64 {target} output decoded incorrectly: {encoded!r}"
            )

    def parse_single_link(link: str, expected_scheme: str) -> tuple[
        urllib.parse.SplitResult, dict[str, list[str]]
    ]:
        parsed = urllib.parse.urlsplit(link.strip())
        if parsed.scheme != expected_scheme:
            raise AssertionError(
                f"expected {expected_scheme} single link, got {link!r}"
            )
        return parsed, urllib.parse.parse_qs(
            parsed.query, keep_blank_values=True
        )

    def parse_vmess_qr(link: str) -> dict[str, object]:
        if not link.startswith("vmess://"):
            raise AssertionError(f"expected VMess QR link, got {link!r}")
        payload = link.removeprefix("vmess://").strip()
        payload += "=" * (-len(payload) % 4)
        try:
            decoded = base64.urlsafe_b64decode(payload)
            value = json.loads(decoded)
        except (ValueError, json.JSONDecodeError) as error:
            raise AssertionError(f"invalid VMess QR output: {link!r}") from error
        if not isinstance(value, dict):
            raise AssertionError(f"VMess QR output is not an object: {value!r}")
        return value

    standard_vmess = parse_vmess_qr(
        convert("v2ray", VMESS_STANDARD_URI, True)
    )
    for key, expected in {
        "id": "22222222-2222-2222-2222-222222222222",
        "net": "tcp",
        "scy": "none",
        "tls": "tls",
        "sni": "tls.example.test",
        "alpn": "h2,http/1.1",
        "fp": "chrome",
    }.items():
        if standard_vmess.get(key) != expected:
            raise AssertionError(
                f"standard VMess lost {key}: {standard_vmess!r}"
            )

    legacy_vmess_qr = parse_vmess_qr(convert("v2ray", VMESS_QR_URI, True))
    for key, expected in {
        "net": "grpc",
        "type": "multi",
        "path": "grpc-service",
        "scy": "chacha20-poly1305",
        "sni": "grpc.example.test",
        "alpn": "h2,http/1.1",
        "fp": "firefox",
    }.items():
        if legacy_vmess_qr.get(key) != expected:
            raise AssertionError(
                f"VMess QR compatibility lost {key}: {legacy_vmess_qr!r}"
            )

    quic_vmess_qr = parse_vmess_qr(
        convert("v2ray", VMESS_QR_QUIC_URI, True)
    )
    for key, expected in {
        "net": "quic",
        "type": "srtp",
        "host": "aes-128-gcm",
        "path": "quic-secret",
    }.items():
        if quic_vmess_qr.get(key) != expected:
            raise AssertionError(
                f"VMess QUIC lost {key}: {quic_vmess_qr!r}"
            )

    default_vless, default_vless_query = parse_single_link(
        convert("vless", VLESS_DEFAULT_TCP_URI, True), "vless"
    )
    if default_vless.hostname != "2001:db8::1" or default_vless.port != 443:
        raise AssertionError(
            f"VLESS IPv6 authority was not preserved: {default_vless!r}"
        )
    for key, expected in {
        "encryption": ["none"],
        "security": ["tls"],
        "type": ["tcp"],
        "sni": ["vless-tls.example.test"],
        "alpn": ["h2,http/1.1"],
        "insecure": ["1"],
    }.items():
        if default_vless_query.get(key) != expected:
            raise AssertionError(
                f"default VLESS TCP lost {key}: {default_vless_query!r}"
            )

    _, xhttp_query = parse_single_link(
        convert("vless", VLESS_XHTTP_URI, True), "vless"
    )
    for key, expected in {
        "type": ["xhttp"],
        "path": ["/split?token=1"],
        "host": ["xhttp.example.test"],
        "mode": ["stream-one"],
        "extra": ['{"xPaddingBytes":"100-1000"}'],
        "security": ["reality"],
        "pbk": ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
        "sid": ["00112233"],
    }.items():
        if xhttp_query.get(key) != expected:
            raise AssertionError(
                f"VLESS XHTTP lost {key}: {xhttp_query!r}"
            )
    if xhttp_query.get("type") == ["h2"]:
        raise AssertionError("VLESS XHTTP was silently downgraded to h2")

    _, grpc_query = parse_single_link(
        convert("vless", VLESS_GRPC_URI, True), "vless"
    )
    for key, expected in {
        "type": ["grpc"],
        "serviceName": ["service/name"],
        "mode": ["multi"],
        "authority": ["authority.example.test"],
    }.items():
        if grpc_query.get(key) != expected:
            raise AssertionError(
                f"VLESS gRPC lost {key}: {grpc_query!r}"
            )

    _, tcp_http_query = parse_single_link(
        convert("vless", VLESS_TCP_HTTP_URI, True), "vless"
    )
    for key, expected in {
        "type": ["tcp"],
        "headerType": ["http"],
        "host": ["header.example.test"],
        "path": ["/header"],
    }.items():
        if tcp_http_query.get(key) != expected:
            raise AssertionError(
                f"VLESS TCP HTTP header lost {key}: {tcp_http_query!r}"
            )

    _, vless_quic_query = parse_single_link(
        convert("vless", VLESS_QUIC_URI, True), "vless"
    )
    for key, expected in {
        "type": ["quic"],
        "headerType": ["utp"],
        "quicSecurity": ["chacha20-poly1305"],
        "key": ["vless-quic-secret"],
    }.items():
        if vless_quic_query.get(key) != expected:
            raise AssertionError(
                f"VLESS QUIC lost {key}: {vless_quic_query!r}"
            )

    trojan, trojan_query = parse_single_link(
        convert("trojan", TROJAN_WS_URI, True), "trojan"
    )
    if (
        urllib.parse.unquote(trojan.username or "") != "p@ss+word/token"
        or trojan.hostname != "2001:db8::2"
        or trojan.port != 443
    ):
        raise AssertionError(f"Trojan credentials/IPv6 were changed: {trojan!r}")
    for key, expected in {
        "type": ["ws"],
        "host": ["ws.example.test"],
        "path": ["/socket"],
        "sni": ["trojan-tls.example.test"],
        "alpn": ["h2,http/1.1"],
        "fp": ["chrome"],
        "insecure": ["1"],
    }.items():
        if trojan_query.get(key) != expected:
            raise AssertionError(
                f"Trojan WS lost {key}: {trojan_query!r}"
            )

    _, trojan_kcp_query = parse_single_link(
        convert("trojan", TROJAN_KCP_URI, True), "trojan"
    )
    for key, expected in {
        "type": ["kcp"],
        "headerType": ["wechat-video"],
        "seed": ["trojan-kcp-seed"],
    }.items():
        if trojan_kcp_query.get(key) != expected:
            raise AssertionError(
                f"Trojan KCP lost {key}: {trojan_kcp_query!r}"
            )

    for uri, expected_type in (
        (VMESS_STANDARD_URI, "vmess"),
        (VLESS_HTTPUPGRADE_URI, "vless"),
        (TROJAN_WS_URI, "trojan"),
    ):
        singbox = json.loads(convert("singbox", uri, True))
        outbounds = singbox.get("outbounds", [])
        if len(outbounds) != 1 or outbounds[0].get("type") != expected_type:
            raise AssertionError(
                f"sing-box lost {expected_type} node: {singbox!r}"
            )
        outbound = outbounds[0]
        if expected_type == "vmess":
            if outbound.get("security") != "none" or "transport" in outbound:
                raise AssertionError(
                    f"sing-box VMess default TCP was changed: {outbound!r}"
                )
            tls = outbound.get("tls", {})
            if (
                tls.get("server_name") != "tls.example.test"
                or tls.get("alpn") != ["h2", "http/1.1"]
                or tls.get("utls", {}).get("fingerprint") != "chrome"
            ):
                raise AssertionError(
                    f"sing-box VMess TLS options were lost: {outbound!r}"
                )
        elif expected_type == "vless":
            transport = outbound.get("transport", {})
            if transport != {
                "type": "httpupgrade",
                "host": "upgrade-host.example.test",
                "path": "/upgrade",
            }:
                raise AssertionError(
                    f"sing-box VLESS HTTPUpgrade was changed: {outbound!r}"
                )
        else:
            transport = outbound.get("transport", {})
            if transport.get("type") != "ws" or transport.get("path") != "/socket":
                raise AssertionError(
                    f"sing-box Trojan WS was changed: {outbound!r}"
                )
            tls = outbound.get("tls", {})
            if (
                tls.get("server_name") != "trojan-tls.example.test"
                or tls.get("alpn") != ["h2", "http/1.1"]
                or tls.get("utls", {}).get("fingerprint") != "chrome"
            ):
                raise AssertionError(
                    f"sing-box Trojan TLS options were lost: {outbound!r}"
                )

    for uri, expected_transport in (
        (
            VLESS_GRPC_URI,
            {"type": "grpc", "service_name": "service/name"},
        ),
        (
            VLESS_TCP_HTTP_URI,
            {
                "type": "http",
                "host": ["header.example.test"],
                "path": "/header",
            },
        ),
    ):
        singbox = json.loads(convert("singbox", uri, True))
        outbounds = singbox.get("outbounds", [])
        if len(outbounds) != 1 or outbounds[0].get("transport") != expected_transport:
            raise AssertionError(
                f"sing-box VLESS transport changed: {singbox!r}"
            )

    status, body, _ = request(
        base_url, "/sub", {"target": "unsupported-fixture", "url": source}
    )
    error = body.decode("utf-8", errors="replace")
    if status != 400 or "vless" not in error or "hysteria2" not in error:
        raise AssertionError(
            "unsupported target response did not retain 400 with the current list"
        )


def sensitive_log_baseline(binary: Path, fixture_base: str) -> None:
    logs: list[str] = []
    secrets = (
        "11111111-1111-1111-1111-111111111111",
        "request-token-secret",
        "request-userinfo-secret",
        "provider-header-secret",
        "provider-source-secret",
        "private-config-secret",
    )
    with running_service(
        binary,
        log_capture=logs,
        log_level="verbose",
    ) as base_url:
        status, body, response_headers = request(
            base_url,
            "/sub",
            {
                "target": "mixed",
                "url": (
                    fixture_base
                    + "/mixed-protocol-subscription.txt?token="
                    + "provider-source-secret"
                ),
                "list": "true",
                "token": "request-token-secret",
                "userinfo": "request-userinfo-secret",
                "config": (
                    "data:text/plain;private-config-secret,"
                    "enable_rule_generator=false"
                ),
            },
            headers={"X-Provider-Secret": "provider-header-secret"},
        )
        if status != 200:
            raise AssertionError(
                "verbose-log fixture conversion returned "
                f"HTTP {status}: {body!r}"
            )
        request_id = assert_request_id(response_headers, "verbose-log fixture")
    if not logs:
        raise AssertionError("verbose-log fixture did not capture service logs")
    for secret in secrets:
        if secret in logs[0]:
            raise AssertionError(f"verbose service log leaked fixture secret: {secret}")
    if (
        f"request_id={request_id} SUB_ROUTE_RESULT" not in logs[0]
        or f"request_id={request_id} HTTP_RESPONSE_PREPARED" not in logs[0]
    ):
        raise AssertionError("safe request diagnostics disappeared from verbose logs")
    if "X-Provider-Secret" in logs[0]:
        raise AssertionError("request header names should not be copied into logs")


def template_error_redaction_baseline(binary: Path, fixture_base: str) -> None:
    secret = "template-exception-cookie-secret"
    logs: list[str] = []
    with running_service(
        binary,
        log_capture=logs,
        log_level="verbose",
    ) as base_url:
        status, body, headers = request(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": fixture_base + "/subscription.txt",
                "config": fixture_base + "/external-malicious-base.ini",
                "token": "query-secret",
            },
            headers={
                "Authorization": "Bearer authorization-secret",
                "Cookie": "session=cookie-secret",
            },
        )
        error = body.decode("utf-8", errors="replace")
        if status != 400:
            raise AssertionError(
                f"template render failure changed status: {status}, body={error!r}"
            )
        if "Invalid template" not in error or "模板渲染失败" not in error:
            raise AssertionError("template render failure lost stable bilingual guidance")
        for leaked in (
            secret,
            "query-secret",
            "authorization-secret",
            "cookie-secret",
        ):
            if leaked in error:
                raise AssertionError(f"template error response leaked secret: {leaked}")
        if "no-store" not in headers.get("cache-control", ""):
            raise AssertionError("template render failure lost no-store policy")

        status, body, _ = request(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": fixture_base + "/subscription.txt",
                "config": fixture_base + "/external-valid.ini",
            },
        )
        if status != 200 or not body:
            raise AssertionError("successful template render behavior changed")

    if not logs:
        raise AssertionError("template error fixture did not capture logs")
    for leaked in (
        secret,
        "query-secret",
        "authorization-secret",
        "cookie-secret",
    ):
        if leaked in logs[0]:
            raise AssertionError(f"template error log leaked secret: {leaked}")
    if "TEMPLATE_RENDER_FAILED" not in logs[0]:
        raise AssertionError("template error log lost its stable event identifier")


def persistence_degradation_baseline(binary: Path, fixture_base: str) -> None:
    with running_service(
        binary,
        statistics=True,
        invalid_statistics_path=True,
    ) as base_url:
        token = base64.b64encode(
            b"fixture-admin:fixture-dashboard-secret"
        ).decode()
        status, body, _ = request(
            base_url,
            "/dashboard/data",
            headers={"Authorization": "Basic " + token},
        )
        if status != 200 or not json.loads(body).get("enabled"):
            raise AssertionError(
                "Dashboard failed after persistence degradation"
            )
        status, _, _ = request(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": fixture_base + "/subscription.txt",
                "config": DISABLE_RULEGEN_CONFIG,
                "list": "true",
            },
        )
        if status != 200:
            raise AssertionError(
                "/sub failed after persistence degradation"
            )

    with running_service(
        binary,
        statistics=False,
        runtime_details=True,
    ) as runtime:
        base_url, statistics_path = runtime
        status, body, _ = request(base_url, "/healthz")
        if status != 200 or body.strip() != b"ok":
            raise AssertionError("statistics-disabled service failed")
        if statistics_path.exists():
            raise AssertionError(
                "statistics-disabled service touched the data directory"
            )


def public_request_baseline(binary: Path, fixture_base: str) -> None:
    with running_service(binary, security_profile="public") as base_url:
        status, _, _ = request(
            base_url,
            "/sub",
            {
                "target": "clash",
                "url": fixture_base + "/subscription.txt",
                "config": DISABLE_RULEGEN_CONFIG,
                "list": "true",
            },
        )
        if status != 400:
            raise AssertionError(
                f"PublicRequest accepted loopback HTTP source with status {status}"
            )
        legacy_routes = (
            ("GET", "/get"),
            ("GET", "/getlocal"),
            ("GET", "/refreshrules"),
            ("GET", "/readconf"),
            ("POST", "/updateconf"),
            ("GET", "/flushcache"),
            ("GET", "/sub2clashr"),
            ("GET", "/surge2clash"),
            ("GET", "/getprofile"),
            ("GET", "/render"),
            ("POST", "/create-profile"),
            ("GET", "/list-profiles"),
        )
        for method, path in legacy_routes:
            status, _, _ = request(
                base_url, path, {"path": "../secret"}, method=method
            )
            if status != 404:
                raise AssertionError(
                    f"legacy route {method} {path} became reachable"
                )


def security_endpoint_matrix_baseline(binary: Path, fixture_base: str) -> None:
    sub_params = {
        "target": "clash",
        "url": fixture_base + "/subscription.txt",
        "config": DISABLE_RULEGEN_CONFIG,
        "list": "true",
    }
    encoded_ruleset = base64.urlsafe_b64encode(
        (fixture_base + "/rules.list").encode()
    ).decode()

    with running_service(binary, security_profile="lan") as base_url:
        status, baseline_body, _ = request(base_url, "/sub", sub_params)
        if status != 200:
            raise AssertionError(
                f"lan profile changed loopback /sub behavior: HTTP {status}"
            )
        request_script_params = dict(sub_params)
        request_script_params["filter_script"] = (
            "function filter(node) { return false; }"
        )
        status, scripted_body, _ = request(
            base_url, "/sub", request_script_params
        )
        if status != 200 or scripted_body != baseline_body:
            raise AssertionError(
                "public /sub request regained executable filter authorization"
            )
        status, _, _ = request(
            base_url,
            "/getruleset",
            {"url": encoded_ruleset, "type": "6"},
        )
        if status != 200:
            raise AssertionError(
                f"lan profile changed loopback /getruleset behavior: HTTP {status}"
            )

    for profile in ("public", "strict"):
        with running_service(binary, security_profile=profile) as base_url:
            status, _, _ = request(base_url, "/sub", sub_params)
            if status != 400:
                raise AssertionError(
                    f"{profile} profile accepted loopback /sub source: HTTP {status}"
                )
            status, _, _ = request(
                base_url,
                "/getruleset",
                {"url": encoded_ruleset, "type": "6"},
            )
            if status != 400:
                raise AssertionError(
                    f"{profile} profile accepted loopback /getruleset source: "
                    f"HTTP {status}"
                )

    upload_params = {
        "target": "clash",
        "url": SUBSCRIPTION.strip(),
        "config": DISABLE_RULEGEN_CONFIG,
        "list": "true",
        "upload": "true",
    }
    cases = (
        ("lan", False, 200, 1, "reason=lan-compatibility"),
        ("public", False, 403, 0, "reason=public-upload-setting"),
        ("public", True, 200, 1, "reason=public-upload-setting"),
        ("strict", True, 403, 0, "reason=strict-policy"),
    )
    for profile, configured_allow, expected_status, gist_delta, reason in cases:
        logs: list[str] = []
        before = FixtureHandler.gist_request_count
        with running_service(
            binary,
            security_profile=profile,
            allow_public_upload=configured_allow,
            listen_address="0.0.0.0" if profile == "lan" else "127.0.0.1",
            gist_api_base=fixture_base,
            log_capture=logs,
        ) as base_url:
            status, _, _ = request(base_url, "/sub", upload_params)
        actual_delta = FixtureHandler.gist_request_count - before
        if status != expected_status or actual_delta != gist_delta:
            raise AssertionError(
                f"upload policy changed for profile={profile}, "
                f"allow_public_upload={configured_allow}: HTTP {status}, "
                f"gist requests {actual_delta}"
            )
        effective = "allowed" if gist_delta else "blocked"
        expected_log = (
            f"SECURITY_UPLOAD_EFFECTIVE profile={profile} "
            "configured_allow_public_upload="
            f"{str(configured_allow).lower()} source=file:toml "
            f"effective={effective} {reason}"
        )
        if not logs or expected_log not in logs[0]:
            raise AssertionError(
                f"effective upload policy log missing for {profile}: {logs!r}"
            )
        if gist_delta and "GIST_UPLOAD_COMPLETE" not in logs[0]:
            raise AssertionError(
                f"successful Gist upload lacks completion evidence: {logs!r}"
            )
        if logs and "fixture-token" in logs[0]:
            raise AssertionError("Gist upload logs leaked the configured token")
        if profile == "lan" and (
            "SECURITY_EXPOSURE_POSSIBLE profile=lan bind=0.0.0.0:" not in logs[0]
            or "public_reachability=unknown" not in logs[0]
        ):
            raise AssertionError(
                "wildcard LAN binding did not emit reachability-unknown warning"
            )


def upload_failure_compatibility_baseline(binary: Path, fixture_base: str) -> None:
    subscription_query_secret = "subscription-query-secret"
    request_query_secret = "request-query-secret"
    request_header_secret = "request-header-secret"
    subscription_url = (
        f"{fixture_base}/subscription.txt?private={subscription_query_secret}"
    )
    upload_params = {
        "target": "clash",
        "url": subscription_url,
        "config": DISABLE_RULEGEN_CONFIG,
        "list": "true",
        "upload": "true",
        "compat_secret": request_query_secret,
    }
    request_headers = {"X-Compatibility-Secret": request_header_secret}
    diagnostic_secrets = (
        GIST_FIXTURE_TOKEN,
        subscription_url,
        subscription_query_secret,
        request_query_secret,
        request_header_secret,
        GIST_REMOTE_FAILURE_SECRET,
        "invalid-section-token",
    )
    log_only_secrets = diagnostic_secrets + (SUBSCRIPTION.strip(),)
    baseline_params = dict(upload_params)
    baseline_params.pop("upload")

    success_logs: list[str] = []
    with running_service(
        binary,
        security_profile="lan",
        gist_api_base=fixture_base,
        log_capture=success_logs,
        log_level="verbose",
    ) as base_url:
        baseline_status, expected_body, _ = request(
            base_url, "/sub", baseline_params, request_headers
        )
        failed_conversion_params = dict(baseline_params)
        failed_conversion_params["url"] = ""
        failed_upload_params = dict(upload_params)
        failed_upload_params["url"] = ""
        failed_before = FixtureHandler.gist_request_count
        failed_baseline_status, failed_baseline_body, _ = request(
            base_url, "/sub", failed_conversion_params, request_headers
        )
        failed_upload_status, failed_upload_body, _ = request(
            base_url, "/sub", failed_upload_params, request_headers
        )
        failed_gist_requests = FixtureHandler.gist_request_count - failed_before
        before = FixtureHandler.gist_request_count
        success_status, success_body, success_headers = request(
            base_url, "/sub", upload_params, request_headers
        )
        success_request_id = assert_request_id(
            success_headers, "successful Gist upload"
        )
    if baseline_status != 200:
        raise AssertionError(
            f"upload compatibility conversion baseline failed: HTTP {baseline_status}"
        )
    if (
        failed_baseline_status != 400
        or failed_upload_status != failed_baseline_status
        or failed_upload_body != failed_baseline_body
        or failed_gist_requests != 0
    ):
        raise AssertionError(
            "upload compatibility handling swallowed a conversion failure: "
            f"baseline HTTP {failed_baseline_status}, upload HTTP "
            f"{failed_upload_status}, "
            f"body_equal={failed_upload_body == failed_baseline_body}, "
            f"gist requests={failed_gist_requests}"
        )
    if (
        success_status != 200
        or success_body != expected_body
        or FixtureHandler.gist_request_count - before != 1
    ):
        raise AssertionError(
            "successful Gist upload changed conversion response: "
            f"HTTP {success_status}, body_equal={success_body == expected_body}, "
            f"gist requests={FixtureHandler.gist_request_count - before}"
        )
    if not success_logs or (
        "GIST_UPLOAD_COMPLETE" not in success_logs[0]
        or "GIST_OPTIONAL_UPLOAD_FAILED" in success_logs[0]
    ):
        raise AssertionError(
            f"successful Gist upload diagnostics changed: {success_logs!r}"
        )

    for secret in log_only_secrets:
        if secret in success_logs[0]:
            raise AssertionError(
                f"successful Gist upload leaked diagnostic secret {secret!r}"
            )
    for secret in diagnostic_secrets:
        if secret.encode() in success_body:
            raise AssertionError(
                f"successful Gist response leaked diagnostic secret {secret!r}"
            )
    if "X-Compatibility-Secret" in success_logs[0]:
        raise AssertionError(
            "verbose upload diagnostics retained a request header name"
        )
    if (
        f"request_id={success_request_id}" not in success_logs[0]
        or "HTTP_RESPONSE_PREPARED" not in success_logs[0]
    ):
        raise AssertionError("successful upload lost safe request correlation")

    failure_cases = (
        (
            "missing configuration",
            fixture_base,
            None,
            False,
            0,
            "未找到 gistconf.ini",
        ),
        (
            "invalid configuration",
            fixture_base,
            "[invalid]\ntoken=invalid-section-token\n",
            False,
            0,
            "gistconf.ini 格式不正确",
        ),
        (
            "remote upload",
            f"{fixture_base}/failure",
            GIST_FIXTURE_CONFIG,
            False,
            1,
            "GIST_CREATE_FAILED status=502 detail=length=",
        ),
        (
            "local persistence",
            fixture_base,
            GIST_FIXTURE_CONFIG,
            True,
            1,
            "GIST_REMOTE_UPLOAD_COMPLETED_LOCAL_STATE_FAILED",
        ),
    )
    for (
        label,
        gist_api_base,
        gist_config_text,
        hardlink_failure,
        expected_gist_requests,
        expected_failure_log,
    ) in failure_cases:
        logs: list[str] = []
        before = FixtureHandler.gist_request_count
        with running_service(
            binary,
            security_profile="lan",
            gist_api_base=gist_api_base,
            gist_config_text=gist_config_text,
            gist_config_hardlink_failure=hardlink_failure,
            log_capture=logs,
            log_level="verbose",
        ) as base_url:
            status, body, _ = request(
                base_url, "/sub", upload_params, request_headers
            )
        actual_gist_requests = FixtureHandler.gist_request_count - before
        if (
            status != 200
            or body != expected_body
            or actual_gist_requests != expected_gist_requests
        ):
            raise AssertionError(
                f"{label} failure replaced the v1.3.0 conversion response: "
                f"HTTP {status}, body_equal={body == expected_body}, "
                f"gist requests={actual_gist_requests}"
            )
        if not logs or (
            expected_failure_log not in logs[0]
            or "GIST_OPTIONAL_UPLOAD_FAILED action=return-conversion-result"
            not in logs[0]
            or "GIST_UPLOAD_COMPLETE" in logs[0]
        ):
            raise AssertionError(
                f"{label} failure diagnostics are ambiguous: {logs!r}"
            )
        for secret in log_only_secrets:
            if secret in logs[0]:
                raise AssertionError(
                    f"{label} failure leaked diagnostic secret {secret!r}"
                )
        for secret in diagnostic_secrets:
            if secret.encode() in body:
                raise AssertionError(
                    f"{label} failure response leaked diagnostic secret {secret!r}"
                )


def settings_reload_compatibility_baseline(helper: Path) -> None:
    insertions = {
        ".ini": (
            "append_proxy_type=false",
            "fallback_to_default_external_config=true\nappend_proxy_type=false",
        ),
        ".yml": (
            "  append_proxy_type: false",
            "  fallback_to_default_external_config: true\n"
            "  append_proxy_type: false",
        ),
        ".toml": (
            "append_proxy_type = false",
            "fallback_to_default_external_config = true\n"
            "append_proxy_type = false",
        ),
    }
    runtime_dir = REPOSITORY / "build" / "test-baseline-runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=runtime_dir) as temporary:
        temporary_path = Path(temporary)
        for fixture_name in (
            "legacy-pref.ini",
            "legacy-pref.yml",
            "legacy-pref.toml",
        ):
            original = COMPAT_FIXTURES / fixture_name
            marker, replacement = insertions[original.suffix]
            enabled = temporary_path / fixture_name
            enabled.write_text(
                original.read_text(encoding="utf-8").replace(
                    marker, replacement, 1
                ),
                encoding="utf-8",
                newline="\n",
            )
            enabled_snapshot = load_settings_snapshot(helper, enabled)
            if not enabled_snapshot["common"][
                "fallback_to_default_external_config"
            ]:
                raise AssertionError(
                    f"{original.suffix} did not load the new fallback switch"
                )
            reloaded = reload_settings_snapshot(helper, enabled, original)
            if reloaded["common"]["fallback_to_default_external_config"]:
                raise AssertionError(
                    f"{original.suffix} hot reload retained a removed switch"
                )


def common_scalar_binding_compatibility_baseline(helper: Path) -> None:
    configured_values: dict[str, str | bool] = {
        "prepend_insert_url": False,
        "base_path": "stage-c-base",
        "clash_rule_base": "stage-c/clash.tpl",
        "surge_rule_base": "stage-c/surge.tpl",
        "surfboard_rule_base": "stage-c/surfboard.tpl",
        "mellow_rule_base": "stage-c/mellow.tpl",
        "quan_rule_base": "stage-c/quan.tpl",
        "quanx_rule_base": "stage-c/quanx.tpl",
        "loon_rule_base": "stage-c/loon.tpl",
        "sssub_rule_base": "stage-c/sssub.tpl",
        "singbox_rule_base": "stage-c/singbox.tpl",
        "default_external_config": "data:,enable_rule_generator=false",
        "fallback_to_default_external_config": True,
        "append_proxy_type": True,
        "proxy_config": "NONE",
        "proxy_ruleset": "SYSTEM",
        "proxy_subscription": "http://127.0.0.1:8080",
        "proxy_bypass": "LAN,CGNAT,CIDR:10.200.0.0/16,DOMAIN:corp.example",
        "reload_conf_on_request": True,
    }

    def render_value(suffix: str, value: str | bool) -> str:
        if isinstance(value, bool):
            return str(value).lower()
        if suffix == ".ini":
            return value
        return json.dumps(value)

    def field_pattern(suffix: str, key: str) -> str:
        if suffix == ".ini":
            return rf"(?m)^{re.escape(key)}=.*$"
        if suffix == ".yml":
            return rf"(?m)^  {re.escape(key)}:.*$"
        if suffix == ".toml":
            return rf"(?m)^{re.escape(key)}\s*=.*$"
        raise AssertionError(f"unsupported config suffix: {suffix}")

    def field_line(suffix: str, key: str, value: str | bool) -> str:
        rendered = render_value(suffix, value)
        if suffix == ".ini":
            return f"{key}={rendered}"
        if suffix == ".yml":
            return f"  {key}: {rendered}"
        return f"{key} = {rendered}"

    def configure(content: str, suffix: str) -> str:
        for key, value in configured_values.items():
            replacement = field_line(suffix, key, value)
            content, count = re.subn(
                field_pattern(suffix, key), replacement, content, count=1
            )
            if count == 0:
                marker = field_pattern(suffix, "append_proxy_type")
                match = re.search(marker, content)
                if match is None:
                    raise AssertionError(
                        f"common scalar insertion marker missing: {suffix}"
                    )
                content = (
                    content[: match.start()]
                    + replacement
                    + "\n"
                    + content[match.start() :]
                )
        return content

    def empty_default_external_config(content: str, suffix: str) -> str:
        replacement = field_line(suffix, "default_external_config", "")
        content, count = re.subn(
            field_pattern(suffix, "default_external_config"),
            replacement,
            content,
            count=1,
        )
        if count != 1:
            raise AssertionError(
                f"default external config field missing: {suffix}"
            )
        return content

    runtime_dir = REPOSITORY / "build" / "test-baseline-runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=runtime_dir) as temporary:
        temporary_path = Path(temporary)
        configured_snapshots: list[dict[str, object]] = []
        configured_paths: dict[str, Path] = {}
        empty_snapshots: list[dict[str, object]] = []
        legacy_snapshots: list[dict[str, object]] = []
        for fixture_name in (
            "legacy-pref.ini",
            "legacy-pref.yml",
            "legacy-pref.toml",
        ):
            original = COMPAT_FIXTURES / fixture_name
            content = original.read_text(encoding="utf-8")
            if re.search(field_pattern(original.suffix, "proxy_bypass"), content):
                raise AssertionError(
                    f"legacy compatibility fixture unexpectedly contains "
                    f"proxy_bypass: {fixture_name}"
                )
            legacy_snapshots.append(load_settings_snapshot(helper, original))
            configured = temporary_path / ("common-scalars-" + fixture_name)
            configured.write_text(
                configure(content, original.suffix),
                encoding="utf-8",
                newline="\n",
            )
            configured_paths[original.suffix] = configured
            configured_snapshots.append(load_settings_snapshot(helper, configured))

            empty = temporary_path / ("empty-default-" + fixture_name)
            empty.write_text(
                empty_default_external_config(content, original.suffix),
                encoding="utf-8",
                newline="\n",
            )
            empty_snapshots.append(load_settings_snapshot(helper, empty))

        if configured_snapshots[1:] != configured_snapshots[:1] * 2:
            raise AssertionError("INI/YAML/TOML common scalar bindings differ")
        if legacy_snapshots[1:] != legacy_snapshots[:1] * 2:
            raise AssertionError("legacy INI/YAML/TOML defaults differ")
        if any(
            snapshot["proxies"]["bypass"] != "LOOPBACK,PRIVATE"
            for snapshot in legacy_snapshots
        ):
            raise AssertionError(
                "legacy preferences without proxy_bypass did not use "
                "the LOOPBACK+PRIVATE default"
            )
        common = configured_snapshots[0]["common"]
        proxies = configured_snapshots[0]["proxies"]
        expected_rule_bases = {
            name: f"stage-c/{name}.tpl"
            for name in (
                "clash",
                "surge",
                "surfboard",
                "mellow",
                "quan",
                "quanx",
                "loon",
                "sssub",
                "singbox",
            )
        }
        if (
            common["base_path"] != "stage-c-base"
            or common["rule_bases"] != expected_rule_bases
            or common["prepend_insert"] is not False
            or common["append_proxy_type"] is not True
            or common["reload_conf_on_request"] is not True
            or common["fallback_to_default_external_config"] is not True
        ):
            raise AssertionError(f"common scalar values were misbound: {common!r}")
        if proxies["bypass"] != "LOOPBACK,LAN,CGNAT,CIDR(1),DOMAIN(1)":
            raise AssertionError(
                f"proxy_bypass common scalar was misbound: {proxies!r}"
            )

        for suffix, configured in configured_paths.items():
            original = COMPAT_FIXTURES / ("legacy-pref" + suffix)
            reloaded = reload_settings_snapshot(helper, configured, original)
            if reloaded["proxies"]["bypass"] != "LOOPBACK,PRIVATE":
                raise AssertionError(
                    f"{suffix} removal did not restore the default proxy_bypass"
                )

            invalid_bypass = temporary_path / ("invalid-bypass-pref" + suffix)
            invalid_bypass.write_text(
                configure(original.read_text(encoding="utf-8"), suffix).replace(
                    field_line(
                        suffix,
                        "proxy_bypass",
                        configured_values["proxy_bypass"],
                    ),
                    field_line(suffix, "proxy_bypass", "LAN,ALL"),
                    1,
                ),
                encoding="utf-8",
                newline="\n",
            )
            retained = reload_settings_snapshot(
                helper, configured, invalid_bypass, expect_failure=True
            )
            expected_index = {".ini": 0, ".yml": 1, ".toml": 2}[suffix]
            if retained != configured_snapshots[expected_index]:
                raise AssertionError(
                    f"{suffix} invalid proxy_bypass replaced previous settings"
                )

        if empty_snapshots[1:] != empty_snapshots[:1] * 2 or any(
            snapshot["common"]["default_external_config"]["configured"] is not True
            for snapshot in empty_snapshots
        ):
            raise AssertionError(
                "empty default external config no longer uses the common fallback"
            )

        invalid_ini = temporary_path / "invalid-bool-pref.ini"
        invalid_ini.write_text(
            re.sub(
                field_pattern(".ini", "prepend_insert_url"),
                "prepend_insert_url=not-a-bool",
                (COMPAT_FIXTURES / "legacy-pref.ini").read_text(encoding="utf-8"),
                count=1,
            ),
            encoding="utf-8",
            newline="\n",
        )
        if load_settings_snapshot(helper, invalid_ini)["common"]["prepend_insert"]:
            raise AssertionError("legacy INI invalid boolean handling changed")

        for suffix, invalid_value in (
            (".yml", "not-a-bool"),
            (".toml", '"not-a-bool"'),
        ):
            original = COMPAT_FIXTURES / ("legacy-pref" + suffix)
            invalid = temporary_path / ("invalid-bool-pref" + suffix)
            invalid.write_text(
                re.sub(
                    field_pattern(suffix, "prepend_insert_url"),
                    field_line(suffix, "prepend_insert_url", False).replace(
                        "false", invalid_value
                    ),
                    original.read_text(encoding="utf-8"),
                    count=1,
                ),
                encoding="utf-8",
                newline="\n",
            )
            retained = reload_settings_snapshot(
                helper,
                configured_paths[suffix],
                invalid,
                expect_failure=True,
            )
            expected_index = {".ini": 0, ".yml": 1, ".toml": 2}[suffix]
            if retained != configured_snapshots[expected_index]:
                raise AssertionError(
                    f"{suffix} invalid common scalar replaced previous settings"
                )


def settings_parser_diagnostic_redaction_baseline(helper: Path) -> None:
    secret = "yaml-parser-diagnostic-secret"
    runtime_dir = REPOSITORY / "build" / "test-baseline-runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=runtime_dir) as temporary:
        malformed = Path(temporary) / "malformed-secret.yml"
        malformed.write_text(
            "common:\n"
            f"  token: {secret}\n"
            "  malformed: [\n",
            encoding="utf-8",
            newline="\n",
        )
        completed = subprocess.run(
            [
                str(helper),
                str(COMPAT_FIXTURES / "legacy-pref.yml"),
                str(malformed),
                "--expect-reload-failure",
            ],
            cwd=REPOSITORY,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        json.loads(completed.stdout)
        if "PREFERENCE_YAML_PARSE_FAILED detail=length=" not in completed.stderr:
            raise AssertionError(
                "malformed YAML did not emit the stable parser failure event"
            )
        if secret in completed.stderr:
            raise AssertionError("malformed YAML secret leaked to diagnostics")
        if "hash=" in completed.stderr:
            raise AssertionError("parser diagnostics retained a guessable hash")


def external_config_failure_baseline(binary: Path, fixture_base: str) -> None:
    common = {
        "target": "clash",
        "url": fixture_base + "/subscription.txt",
        "list": "true",
    }
    with running_service(binary, legacy_publish_enabled=True) as base_url:
        status, _, _ = request(
            base_url,
            "/sub",
            {**common, "config": fixture_base + "/external-valid.ini"},
        )
        if status != 200:
            raise AssertionError(
                f"valid explicit external config returned HTTP {status}"
            )

        for path in (
            "/external-empty.ini",
            "/external-template-failure.ini",
            "/external-template-fetch-failure.ini",
            "/external-no-effective.ini",
            "/external-import-failure.ini",
        ):
            status, _, headers = request(
                base_url,
                "/sub",
                {**common, "config": fixture_base + path},
            )
            if status != 400 or "no-store" not in headers.get(
                "cache-control", ""
            ):
                raise AssertionError(
                    f"explicit config failure {path} returned HTTP {status} "
                    "without no-store"
                )

        status, _, _ = request(
            base_url,
            "/Custom_OpenClash_Rules/main/rule/example.yaml",
        )
        if status != 404:
            raise AssertionError("removed COCR publication route is still active")

    with running_service(
        binary, fallback_to_default_external_config=True
    ) as base_url:
        status, _, _ = request(
            base_url,
            "/sub",
            {
                **common,
                "config": fixture_base + "/external-no-effective.ini",
            },
        )
        if status != 200:
            raise AssertionError(
                "explicitly enabled default external config fallback failed"
            )

    invalid_default = fixture_base + "/external-no-effective.ini"
    with running_service(
        binary,
        fallback_to_default_external_config=True,
        default_external_config=invalid_default,
    ) as base_url:
        status, _, headers = request(
            base_url,
            "/sub",
            {**common, "config": fixture_base + "/external-empty.ini"},
        )
        if status != 400 or "no-store" not in headers.get(
            "cache-control", ""
        ):
            raise AssertionError(
                "failed explicit and default configs did not fail closed"
            )

    with running_service(
        binary, default_external_config=invalid_default
    ) as base_url:
        status, _, headers = request(base_url, "/sub", common)
        if status != 500 or "no-store" not in headers.get(
            "cache-control", ""
        ):
            raise AssertionError(
                "failed implicit default config did not return 500/no-store"
            )


def loopback_proxy_route_baseline(binary: Path, fixture_base: str) -> None:
    proxy_secret = "loopback-proxy-secret"
    unavailable_proxy = (
        "http://loopback-user:"
        + proxy_secret
        + f"@127.0.0.1:{unused_port()}"
    )
    replacements = (
        (
            'proxy_config = "NONE"',
            f'proxy_config = "{unavailable_proxy}"\n'
            'proxy_bypass = "LAN,CGNAT,CIDR:10.200.0.0/16,'
            'DOMAIN:corp.example"',
        ),
        ("cache_config = 300", "cache_config = 0"),
    )
    common = {
        "target": "clash",
        "url": (
            "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:8388"
            "#LoopbackProxy"
        ),
        "list": "true",
    }

    lan_logs: list[str] = []
    parsed_fixture = urllib.parse.urlsplit(fixture_base)
    fixture_port = parsed_fixture.port
    if fixture_port is None:
        raise AssertionError("loopback fixture URL is missing a port")
    lan_config_urls = (
        fixture_base + "/external-valid.ini?route=explicit-loopback",
        f"http://127.1:{fixture_port}/external-valid.ini?route=short-ipv4",
        f"http://0x7f000001:{fixture_port}/external-valid.ini?route=hex-ipv4",
        f"http://0177.0.0.1:{fixture_port}/external-valid.ini?route=octal-ipv4",
        f"http://%31%32%37.0.0.1:{fixture_port}"
        "/external-valid.ini?route=encoded-ipv4",
        f"http://localhost.:{fixture_port}"
        "/external-valid.ini?route=absolute-localhost",
    )
    with FixtureHandler.counter_lock:
        before = FixtureHandler.external_valid_count
    with running_service(
        binary,
        security_profile="lan",
        config_replacements=replacements,
        log_capture=lan_logs,
        log_level="verbose",
    ) as base_url:
        for config_url in lan_config_urls:
            status, _, _ = request(
                base_url, "/sub", {**common, "config": config_url}
            )
            if status != 200:
                raise AssertionError(
                    "lan explicit-proxy loopback config returned HTTP "
                    f"{status}: {config_url!r}"
                )
    with FixtureHandler.counter_lock:
        after = FixtureHandler.external_valid_count
    if after != before + len(lan_config_urls):
        raise AssertionError(
            "loopback external configs did not each connect directly once"
        )
    lan_diagnostics = "\n".join(lan_logs)
    if (
        "初始主机按 proxy_bypass 直连：127.0.0.1；匹配规则：LOOPBACK"
        not in lan_diagnostics
    ):
        raise AssertionError("loopback proxy bypass was not diagnosed")
    if proxy_secret in lan_diagnostics or "loopback-user" in lan_diagnostics:
        raise AssertionError("loopback proxy credentials leaked to diagnostics")

    userinfo_config = (
        f"{parsed_fixture.scheme}://fixture-user@{parsed_fixture.netloc}"
        "/external-valid.ini?route=userinfo-loopback"
    )
    restricted_config_urls = (
        *lan_config_urls,
        userinfo_config,
        f"http://127.0.0.1:{fixture_port}"
        "?route=query-without-path-loopback",
    )
    for profile in ("public", "strict"):
        restricted_logs: list[str] = []
        with FixtureHandler.counter_lock:
            before = FixtureHandler.external_valid_count
            before_requests = FixtureHandler.get_request_count
        with running_service(
            binary,
            security_profile=profile,
            config_replacements=replacements,
            log_capture=restricted_logs,
            log_level="verbose",
        ) as base_url:
            for config_url in restricted_config_urls:
                status, _, _ = request(
                    base_url, "/sub", {**common, "config": config_url}
                )
                if status != 400:
                    raise AssertionError(
                        f"{profile} loopback external config returned HTTP "
                        f"{status}, expected 400"
                    )
        with FixtureHandler.counter_lock:
            after = FixtureHandler.external_valid_count
            after_requests = FixtureHandler.get_request_count
        if after != before:
            raise AssertionError(
                f"{profile} loopback security rejection reached the fixture"
            )
        if after_requests != before_requests:
            raise AssertionError(
                f"{profile} loopback security rejection made a network request"
            )
        restricted_diagnostics = "\n".join(restricted_logs)
        if "初始主机按 proxy_bypass 直连" in restricted_diagnostics:
            raise AssertionError(
                f"{profile} security rejection enabled proxy bypass"
            )
        if restricted_diagnostics.count(
            "已阻止公开请求访问本地或私有主机"
        ) < len(restricted_config_urls):
            raise AssertionError(
                f"{profile} did not reject every loopback URL spelling"
            )


def loopback_redirect_route_baseline(binary: Path, fixture_base: str) -> None:
    parsed_fixture = urllib.parse.urlsplit(fixture_base)
    fixture_port = parsed_fixture.port
    if fixture_port is None:
        raise AssertionError("redirect fixture URL is missing a port")

    proxy_username = "redirect-proxy-user"
    proxy_secret = "redirect-proxy-secret"
    logs: list[str] = []
    with authenticated_proxy_server(proxy_username, proxy_secret) as (
        proxy_url,
        proxy_handler,
    ):
        replacements = (
            ('proxy_config = "NONE"', f'proxy_config = "{proxy_url}"'),
            ("cache_config = 300", "cache_config = 0"),
        )
        common = {
            "target": "clash",
            "url": (
                "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:8388"
                "#RedirectProxy"
            ),
            "list": "true",
        }

        with running_service(
            binary,
            security_profile="lan",
            config_replacements=replacements,
            log_capture=logs,
            log_level="verbose",
        ) as base_url:

            def assert_route(
                label: str, config_url: str, expected_hosts: list[str]
            ) -> None:
                with proxy_handler.request_lock:
                    before = len(proxy_handler.request_hosts)
                status, _, _ = request(
                    base_url, "/sub", {**common, "config": config_url}
                )
                with proxy_handler.request_lock:
                    actual_hosts = proxy_handler.request_hosts[before:]
                if status != 200 or actual_hosts != expected_hosts:
                    raise AssertionError(
                        f"{label} route changed: HTTP {status}, "
                        f"proxy hosts={actual_hosts!r}"
                    )

            assert_route(
                "loopback-to-remote redirect",
                fixture_base + "/redirect-loopback-to-remote.ini",
                ["target.test"],
            )
            assert_route(
                "numeric-suffix redirect",
                fixture_base + "/redirect-loopback-to-suffix.ini",
                ["foo.127.0.0.1"],
            )
            assert_route(
                "remote-to-loopback redirect",
                f"http://target.test:{fixture_port}"
                "/redirect-remote-to-loopback.ini",
                ["target.test", "127.0.0.1"],
            )

    diagnostics = "\n".join(logs)
    if (
        "初始主机按 proxy_bypass 直连：127.0.0.1；匹配规则：LOOPBACK"
        not in diagnostics
    ):
        raise AssertionError("redirect baseline did not diagnose loopback bypass")
    if proxy_username in diagnostics or proxy_secret in diagnostics:
        raise AssertionError("redirect proxy credentials leaked to diagnostics")


def request_generation_reload_baseline(binary: Path, fixture_base: str) -> None:
    pref_paths: list[Path] = []
    old_prefix = "https://managed-old.snapshot.test"
    new_prefix = "https://managed-new.snapshot.test"
    replacements = (
        (
            "reload_conf_on_request = false",
            "reload_conf_on_request = true",
        ),
        (
            "async_fetch_ruleset = false",
            "async_fetch_ruleset = true",
        ),
        (
            "enable_request_coalescing = true",
            "enable_request_coalescing = false",
        ),
        (
            'managed_config_prefix = "https://managed.example.test"',
            f'managed_config_prefix = "{old_prefix}"',
        ),
    )

    def write_config_atomically(path: Path, content: str) -> None:
        candidate = path.with_name(path.name + ".next")
        candidate.write_text(content, encoding="utf-8", newline="\n")
        os.replace(candidate, path)

    def stable_response(
        result: tuple[int, bytes, dict[str, str]],
    ) -> tuple[int, bytes, dict[str, str | None]]:
        status, body, headers = result
        stable_headers = {
            name: headers.get(name)
            for name in ("content-type", "profile-update-interval")
        }
        return status, body, stable_headers

    dashboard_headers = {
        "Authorization": "Basic "
        + base64.b64encode(
            b"fixture-admin:fixture-dashboard-secret"
        ).decode()
    }

    def lifetime_subscription_requests(base_url: str) -> int:
        # Dashboard snapshots are deliberately cached for one second.
        time.sleep(1.1)
        status, body, _ = request(
            base_url, "/dashboard/data", headers=dashboard_headers
        )
        if status != 200:
            raise AssertionError(
                f"generation statistics query returned HTTP {status}: {body!r}"
            )
        return int(
            json.loads(body)["windows"]["lifetime"]["subscription_requests"]
        )

    def require_generation(
        result: tuple[int, bytes, dict[str, str]],
        *,
        prefix: str,
        clash_modes: bool,
        complete_ruleset: bool,
    ) -> None:
        status, body, _ = result
        if status != 200:
            raise AssertionError(
                f"generation request returned HTTP {status}: {body!r}"
            )
        document = json.loads(body)
        if document.get("snapshot_link") != prefix + "/snapshot":
            raise AssertionError(
                "template getLink observed the wrong settings generation: "
                f"{document.get('snapshot_link')!r}"
            )
        if document.get("template_fetch") != "template-ok":
            raise AssertionError("template fetch did not complete")
        tags = {
            outbound.get("tag")
            for outbound in document.get("outbounds", [])
            if isinstance(outbound, dict)
        }
        if ("GLOBAL" in tags) is not clash_modes:
            raise AssertionError(
                "singBoxAddClashModes came from the wrong settings generation"
            )
        serialized_rules = json.dumps(
            document.get("route", {}).get("rules", []), sort_keys=True
        )
        has_third_rule = "third.snapshot.test" in serialized_rules
        if has_third_rule is not complete_ruleset:
            raise AssertionError(
                "maxAllowedRules came from the wrong settings generation"
            )

    with running_service(
        binary,
        statistics=True,
        extra_args=("-cfw",),
        config_replacements=replacements,
        pref_path_capture=pref_paths,
    ) as base_url:
        if len(pref_paths) != 1:
            raise AssertionError("mutable runtime preference path was not captured")
        pref = pref_paths[0]
        old_config = pref.read_text(encoding="utf-8")
        common = {
            "target": "singbox",
            "url": fixture_base + "/subscription.txt",
            "config": fixture_base + "/external-generation.ini",
        }

        pure_old = request(base_url, "/sub", common)
        require_generation(
            pure_old,
            prefix=old_prefix,
            clash_modes=True,
            complete_ruleset=True,
        )
        old_request_count = lifetime_subscription_requests(base_url)
        if old_request_count != 1:
            raise AssertionError(
                "old generation statistics setup did not record exactly one request"
            )

        FixtureHandler.slow_subscription_started.clear()
        FixtureHandler.slow_subscription_release.clear()
        FixtureHandler.slow_ruleset_started.clear()
        FixtureHandler.slow_ruleset_release.clear()
        slow_result: list[tuple[int, bytes, dict[str, str]]] = []
        slow_error: list[BaseException] = []

        def run_slow_request() -> None:
            try:
                slow_result.append(
                    request(
                        base_url,
                        "/sub",
                        {
                            **common,
                            "url": fixture_base + "/slow-subscription.txt",
                            "config": fixture_base
                            + "/external-generation-slow.ini",
                        },
                    )
                )
            except BaseException as error:  # propagate worker diagnostics
                slow_error.append(error)

        slow_thread = threading.Thread(target=run_slow_request)
        slow_thread.start()
        try:
            if not FixtureHandler.slow_subscription_started.wait(timeout=10):
                raise AssertionError("slow request did not reach nodemanip fetch")
            if not FixtureHandler.slow_ruleset_started.wait(timeout=10):
                raise AssertionError("async ruleset worker did not start")

            new_config = old_config.replace(
                "singbox_add_clash_modes = true",
                "singbox_add_clash_modes = false",
                1,
            ).replace(
                "max_allowed_rules = 4096",
                "max_allowed_rules = 1",
                1,
            ).replace(old_prefix, new_prefix, 1).replace(
                "enabled = true\n",
                "enabled = false\n",
                1,
            )
            if new_config == old_config:
                raise AssertionError("new generation configuration was not changed")
            write_config_atomically(pref, new_config)
            new_result = request(base_url, "/sub", common)
        finally:
            FixtureHandler.slow_ruleset_release.set()
            FixtureHandler.slow_subscription_release.set()
            slow_thread.join(timeout=20)

        if slow_thread.is_alive():
            raise AssertionError("slow request did not finish after fixture release")
        if slow_error:
            raise slow_error[0]
        if len(slow_result) != 1:
            raise AssertionError("slow request did not produce one response")

        require_generation(
            slow_result[0],
            prefix=old_prefix,
            clash_modes=True,
            complete_ruleset=True,
        )
        if stable_response(slow_result[0]) != stable_response(pure_old):
            raise AssertionError(
                "request captured before reload did not remain byte-equivalent "
                "to the old generation"
            )

        require_generation(
            new_result,
            prefix=new_prefix,
            clash_modes=False,
            complete_ruleset=False,
        )
        later_new = request(base_url, "/sub", common)
        if stable_response(later_new) != stable_response(new_result):
            raise AssertionError(
                "request started after reload did not retain the new generation"
            )

        write_config_atomically(pref, "version = 1\n[common\n")
        failed_reload = request(base_url, "/sub", common)
        require_generation(
            failed_reload,
            prefix=new_prefix,
            clash_modes=False,
            complete_ruleset=False,
        )
        if stable_response(failed_reload) != stable_response(new_result):
            raise AssertionError(
                "failed reload changed the last published request generation"
            )
        final_request_count = lifetime_subscription_requests(base_url)
        if final_request_count != old_request_count + 1:
            raise AssertionError(
                "statistics attribution crossed request generations: "
                f"old={old_request_count}, final={final_request_count}"
            )


def getruleset_generation_reload_baseline(binary: Path, fixture_base: str) -> None:
    pref_paths: list[Path] = []
    replacements = (
        (
            "reload_conf_on_request = false",
            "reload_conf_on_request = true",
        ),
    )

    def write_config_atomically(path: Path, content: str) -> None:
        candidate = path.with_name(path.name + ".next")
        candidate.write_text(content, encoding="utf-8", newline="\n")
        os.replace(candidate, path)

    slow_sources = "|".join(
        (
            fixture_base + "/slow-generation-rules.list",
            fixture_base + "/generation-rules.list",
        )
    )
    encoded_slow_sources = base64.urlsafe_b64encode(slow_sources.encode()).decode()
    encoded_source = base64.urlsafe_b64encode(
        (fixture_base + "/generation-rules.list").encode()
    ).decode()
    reload_request = {
        "target": "clash",
        "url": SUBSCRIPTION.strip(),
        "config": DISABLE_RULEGEN_CONFIG,
        "list": "true",
    }

    with running_service(
        binary,
        extra_args=("-cfw",),
        config_replacements=replacements,
        pref_path_capture=pref_paths,
    ) as base_url:
        if len(pref_paths) != 1:
            raise AssertionError("mutable runtime preference path was not captured")
        pref = pref_paths[0]
        old_config = pref.read_text(encoding="utf-8")
        new_config = old_config.replace('profile = "lan"', 'profile = "strict"', 1)
        if new_config == old_config:
            raise AssertionError("new getruleset generation was not changed")

        FixtureHandler.slow_ruleset_started.clear()
        FixtureHandler.slow_ruleset_release.clear()
        slow_result: list[tuple[int, bytes, dict[str, str]]] = []
        slow_error: list[BaseException] = []

        def run_slow_getruleset() -> None:
            try:
                slow_result.append(
                    request(
                        base_url,
                        "/getruleset",
                        {"url": encoded_slow_sources, "type": "6"},
                    )
                )
            except BaseException as error:  # propagate worker diagnostics
                slow_error.append(error)

        slow_thread = threading.Thread(target=run_slow_getruleset)
        slow_thread.start()
        try:
            if not FixtureHandler.slow_ruleset_started.wait(timeout=10):
                raise AssertionError("slow getruleset request did not reach fixture")
            write_config_atomically(pref, new_config)
            reload_status, reload_body, _ = request(
                base_url, "/sub", reload_request
            )
            if reload_status != 200:
                raise AssertionError(
                    "successful getruleset generation reload trigger failed: "
                    f"HTTP {reload_status}: {reload_body!r}"
                )
        finally:
            FixtureHandler.slow_ruleset_release.set()
            slow_thread.join(timeout=20)

        if slow_thread.is_alive():
            raise AssertionError("slow getruleset request did not finish")
        if slow_error:
            raise slow_error[0]
        if len(slow_result) != 1:
            raise AssertionError("slow getruleset request did not return once")
        slow_status, slow_body, _ = slow_result[0]
        slow_text = slow_body.decode("utf-8", errors="replace")
        if slow_status != 200 or slow_text.count("first.snapshot.test") != 2:
            raise AssertionError(
                "getruleset request crossed settings generations: "
                f"HTTP {slow_status}: {slow_text!r}"
            )

        new_status, _, _ = request(
            base_url,
            "/getruleset",
            {"url": encoded_source, "type": "6"},
        )
        if new_status != 400:
            raise AssertionError(
                "getruleset request started after reload did not use strict generation: "
                f"HTTP {new_status}"
            )

        write_config_atomically(pref, "version = 1\n[common\n")
        retained_status, retained_body, _ = request(
            base_url, "/sub", reload_request
        )
        if retained_status != 200:
            raise AssertionError(
                "failed reload did not retain the last successful generation: "
                f"HTTP {retained_status}: {retained_body!r}"
            )
        retained_ruleset_status, _, _ = request(
            base_url,
            "/getruleset",
            {"url": encoded_source, "type": "6"},
        )
        if retained_ruleset_status != 400:
            raise AssertionError(
                "failed reload changed the published getruleset generation: "
                f"HTTP {retained_ruleset_status}"
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument(
        "--settings-snapshot-helper", type=Path, required=True
    )
    parser.add_argument("--update-golden", action="store_true")
    parser.add_argument("--mihomo-binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    settings_snapshot_helper = args.settings_snapshot_helper.resolve()
    mihomo_binary = (
        args.mihomo_binary.resolve() if args.mihomo_binary is not None else None
    )
    if not binary.is_file():
        parser.error(f"binary does not exist: {binary}")
    if not settings_snapshot_helper.is_file():
        parser.error(
            "settings snapshot helper does not exist: "
            f"{settings_snapshot_helper}"
        )
    if settings_snapshot_helper == binary:
        parser.error(
            "settings snapshot helper must be separate from the runtime binary"
        )
    if mihomo_binary is not None and not mihomo_binary.is_file():
        parser.error(f"Mihomo binary does not exist: {mihomo_binary}")

    deployment_security_defaults_baseline()
    runtime_cli_isolation_baseline(binary)
    log_redirection_baseline(binary)
    early_log_level_parsing_baseline(settings_snapshot_helper)

    snapshots = [
        load_settings_snapshot(settings_snapshot_helper, COMPAT_FIXTURES / name)
        for name in ("legacy-pref.ini", "legacy-pref.yml", "legacy-pref.toml")
    ]
    if snapshots[1:] != snapshots[:1] * 2:
        raise AssertionError("INI/YAML/TOML SettingsSnapshot values differ")
    if "publish_enabled" in snapshots[0]["custom_openclash_rules"]:
        raise AssertionError("removed publish setting remains in runtime state")
    if snapshots[0]["common"]["fallback_to_default_external_config"]:
        raise AssertionError("new default fallback switch did not default false")
    if snapshots[0]["proxy_provider"]["interval"] != 3600:
        raise AssertionError("missing provider interval did not default to 3600")
    if snapshots[0]["proxy_provider"]["proxy_direct"] is not True:
        raise AssertionError("missing provider proxy_direct did not default to true")
    if snapshots[0]["security"]["profile"] != "lan":
        raise AssertionError("historical security profile default changed")
    security_configuration_matrix_baseline(settings_snapshot_helper)
    settings_reload_compatibility_baseline(settings_snapshot_helper)
    common_scalar_binding_compatibility_baseline(settings_snapshot_helper)
    settings_parser_diagnostic_redaction_baseline(settings_snapshot_helper)
    settings_provider_interval_compatibility_baseline(settings_snapshot_helper)
    settings_provider_direct_compatibility_baseline(settings_snapshot_helper)
    settings_dashboard_client_ip_baseline(settings_snapshot_helper)

    with fixture_server() as fixture_base:
        parser_invocation_log_baseline(binary, fixture_base)
        provider_no_fetch_vary_and_route_log_baseline(binary, fixture_base)
        quanx_server_remote_baseline(binary, fixture_base)
        parser_failure_level_and_mixed_request_baseline(binary)
        insert_url_parser_route_baseline(binary, fixture_base)
        vary_cache_and_coalesce_baseline(binary, fixture_base)
        explain_privacy_and_cache_baseline(binary, fixture_base)
        with running_service(binary) as base_url:
            conversion_baselines(base_url, fixture_base, args.update_golden)
            parser_route_isolation_baseline(base_url, fixture_base)
            classic_protocol_baseline(base_url, fixture_base)
            simple_target_protocol_baseline(base_url, fixture_base)
            provider_direct_default_output_baseline(base_url, fixture_base)
        with running_service(
            binary,
            config_replacements=(
                (
                    'managed_config_prefix = "https://managed.example.test"',
                    'managed_config_prefix = ""',
                ),
            ),
        ) as base_url:
            issue_98_reality_baseline(base_url, fixture_base, mihomo_binary)
        with running_service(
            binary,
            proxy_provider_interval=7200,
            proxy_provider_direct=False,
        ) as base_url:
            provider_interval_output_baseline(base_url, fixture_base)
        dashboard_baseline(binary, fixture_base)
        sensitive_log_baseline(binary, fixture_base)
        template_error_redaction_baseline(binary, fixture_base)
        dashboard_client_ip_security_baseline(binary, fixture_base)
        persistence_degradation_baseline(binary, fixture_base)
        public_request_baseline(binary, fixture_base)
        security_endpoint_matrix_baseline(binary, fixture_base)
        upload_failure_compatibility_baseline(binary, fixture_base)
        external_config_failure_baseline(binary, fixture_base)
        loopback_proxy_route_baseline(binary, fixture_base)
        loopback_redirect_route_baseline(binary, fixture_base)
        getruleset_generation_reload_baseline(binary, fixture_base)
        request_generation_reload_baseline(binary, fixture_base)

    print("compatibility and security baselines passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"compatibility/security baseline failed: {error}", file=sys.stderr)
        raise
