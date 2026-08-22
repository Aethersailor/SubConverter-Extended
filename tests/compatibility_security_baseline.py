#!/usr/bin/env python3
"""Offline compatibility and security baselines for the built service."""

from __future__ import annotations

import argparse
import base64
import binascii
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
SECONDARY_SS_LINK = (
    "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@second.example.com:8389#Second"
)
ENCODED_SUBSCRIPTION = base64.urlsafe_b64encode(SUBSCRIPTION.encode()).decode()
LOCAL_GROUP_MATCHER_CONFIG = "data:text/plain;base64," + base64.urlsafe_b64encode(
    "\n".join(
        (
            "enable_rule_generator=false",
            "custom_proxy_group=Plain`select`Smoke",
            "custom_proxy_group=ByGroup`select`!!GROUP=public!!Smoke",
            "custom_proxy_group=ByGroupCapture`select`!!GROUP=pub(lic)!!Sm(oke)",
            "custom_proxy_group=BySecondaryGroup`select`!!GROUP=secondary!!Second",
            "custom_proxy_group=ByPrimaryGroupId`select`!!GROUPID=0!!Smoke",
            "custom_proxy_group=ByGroupId`select`!!GROUPID=1!!Second",
            "custom_proxy_group=ByInsert`select`!!INSERT=-1!!Second",
            "custom_proxy_group=ByType`select`!!TYPE=SS",
            "custom_proxy_group=ByPortExact`select`!!PORT=8388",
            "custom_proxy_group=ByPortRange`select`!!PORT=8380-8390",
            "custom_proxy_group=ByPortLess`select`!!PORT=9000-",
            "custom_proxy_group=ByPortMore`select`!!PORT=8000+",
            "custom_proxy_group=ByPortNot`select`!!PORT=!8389",
            "custom_proxy_group=LegacyNotRange`select`!!PORT=8000-9000,!7000-7100",
            "custom_proxy_group=LegacyNegationOrder`select`!!PORT=!8388,!9999",
            "custom_proxy_group=ByServer`select`!!SERVER=^example\\.com$",
            "custom_proxy_group=MalformedGroup`select`!!GROUP=",
            "custom_proxy_group=NoGroup`select`!!GROUP=missing!!Smoke",
            "custom_proxy_group=NoPort`select`!!PORT=!8388!!Smoke",
            "custom_proxy_group=LegacyNotRangeExcluded`select`!!PORT=!8000-9000",
            "custom_proxy_group=NoInsertPositive`select`!!INSERT=1!!Second",
            "custom_proxy_group=NoTypePartial`select`!!TYPE=S",
            "custom_proxy_group=InvalidPlain`select`[",
            "custom_proxy_group=InvalidGroup`select`!!GROUP=[!!Smoke",
        )
    ).encode()
).decode()
SELECT_HEALTH_HTTP_URL = "http://wifi.vivo.com.cn/generate_204"
SELECT_HEALTH_HTTPS_URL = "https://cp.cloudflare.com/generate_204"
SELECT_HEALTH_INI_CONFIG = "data:text/plain;base64," + base64.urlsafe_b64encode(
    "\n".join(
        (
            "enable_rule_generator=false",
            "custom_proxy_group=DIRECT-HEALTH-HTTP`select`[]DIRECT`"
            + SELECT_HEALTH_HTTP_URL,
            "custom_proxy_group=DIRECT-HEALTH-HTTPS`select`[]DIRECT`"
            + SELECT_HEALTH_HTTPS_URL,
        )
    ).encode()
).decode()
SELECT_HEALTH_TOML_CONFIG = "\n".join(
    (
        "version = 1",
        "[custom]",
        "enable_rule_generator = false",
        "[[custom_groups]]",
        'name = "DIRECT-HEALTH-TOML"',
        'type = "select"',
        'rule = ["[]DIRECT"]',
        f'url = "{SELECT_HEALTH_HTTPS_URL}"',
        "[[custom_groups]]",
        'name = "DIRECT-HEALTH-TOML-RULE"',
        'type = "select"',
        f'rule = ["[]DIRECT", "{SELECT_HEALTH_HTTP_URL}"]',
    )
)
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
VMESS_QR_UNSUPPORTED_SECURITY_URI = "vmess://" + base64.urlsafe_b64encode(
    json.dumps(
        {
            "v": "2",
            "ps": "VMessUnsupportedSecurity",
            "add": "vmess-security.example.test",
            "port": "443",
            "id": "99999999-9999-4999-8999-999999999998",
            "aid": "0",
            "scy": "unsupported-security",
            "net": "tcp",
            "type": "none",
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
    "&fp=chrome&sni=vless-reality.example.test#VLESSXHTTP"
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
VLESS_UNSUPPORTED_FLOW_URI = (
    "vless://aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab@flow.example.test:443"
    "?encryption=none&security=tls&type=tcp&flow=unsupported-flow"
    "#VLESSUnsupportedFlow"
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
HYSTERIA2_REALM_V2RAYN_URI = (
    "hysteria2+realm://realm-token@rendezvous.example.test:8443/realm-id"
    "?auth=realm-password&stun=stun.example.test%3A3478"
    "&sni=realm-tls.example.test&obfs=gecko"
    "&obfs-password=realm-obfs&minPacketSize=600&maxPacketSize=1300"
    "#Hysteria2%20Realm"
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
TUIC_V2RAYN_URI = (
    "tuic://99999999-9999-4999-8999-999999999999:tuic-password"
    "@tuic-v2rayn.example.test:10443?allow_insecure=1"
    "&sni=tuic-v2rayn-tls.example.test&alpn=h3"
    "&congestion_control=bbr#TUIC%20v2rayN"
)
ANYTLS_V2RAYN_URI = (
    "anytls://anytls-password@anytls-v2rayn.example.test:443"
    "?sni=anytls-v2rayn-tls.example.test&insecure=1#AnyTLS%20v2rayN"
)
ANYTLS_SHADOWROCKET_URI = (
    "anytls://p%40ss%2Bword@[2001:db8::16]:443/"
    "?sni=anytls-shadowrocket.example.test&insecure=1"
    "#AnyTLS%20Shadowrocket"
)
SHADOWROCKET_STAGE_ONE_MIXED_SHA256 = (
    "32681630201a639d9ebfa784304a870f08d6fcb522e8b0ac8f610c495dd70c22"
)
NAIVE_HTTPS_URI = (
    "naive+https://naive-user:naive%2Bpassword@naive.example.test:443"
    "?sni=naive-tls.example.test&insecure-concurrency=4#Naive%20HTTPS"
)
NAIVE_QUIC_URI = (
    "naive+quic://naive-user:quic-password@naive-quic.example.test:443"
    "?sni=naive-quic-tls.example.test#Naive%20QUIC"
)
WIREGUARD_URI = (
    "wireguard://private%2Bkey%2Fvalue%3D@wg.example.test:51820"
    "?publickey=public%2Bkey%2Fvalue%3D"
    "&presharedkey=preshared%2Bkey%2Fvalue%3D"
    "&reserved=1%2C2%2C3"
    "&address=172.16.0.2%2F32%2C2606%3A4700%3A110%3A8765%3A%3A2%2F128"
    "&mtu=1420#WireGuard%20URI"
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
HYSTERIA_V1_URI = (
    "hy://[2001:db8::14]:36712?protocol=udp&auth=p%40ss%2Bword"
    "&peer=hy1-tls.example.test&insecure=1&upmbps=100"
    "&downmbps=200&alpn=h3%2Chysteria&obfs=xplus"
    "&obfsParam=obfs%2Bsecret#Hysteria%20V1+Literal"
)
HYSTERIA_SHADOWROCKET_URI = HYSTERIA_V1_URI.replace(
    "alpn=h3%2Chysteria", "alpn=hysteria"
)
HYSTERIA_V1_SINGBOX_CONFIG = json.dumps(
    {
        "outbounds": [
            {
                "type": "hysteria",
                "tag": "Hysteria V1 sing-box",
                "server": "2001:db8::15",
                "server_ports": ["20000:20002", "30000"],
                "hop_interval": "45s",
                "up": "640 KBps",
                "down_mbps": 200,
                "obfs": "singbox-obfs",
                "auth": "YmluYXJ5LWF1dGg=",
                "network": ["tcp"],
                "tls": {
                    "enabled": True,
                    "server_name": "singbox-hy1.example.test",
                    "insecure": True,
                    "alpn": ["h3", "hysteria"],
                },
            },
            {
                "type": "hysteria",
                "tag": "Hysteria V1 scalar ports",
                "server": "hy1-scalar.example.test",
                "server_ports": "40000:40002",
                "up_mbps": 20,
                "down_mbps": 80,
                "auth_str": "scalar-auth",
                "tls": {
                    "enabled": True,
                    "server_name": "hy1-scalar.example.test",
                },
            }
        ]
    },
    separators=(",", ":"),
)
SINGBOX_TRANSPORT_FIDELITY_CONFIG = json.dumps(
    {
        "outbounds": [
            {
                "type": "vmess",
                "tag": "Singbox WS Edge",
                "server": "vmess-import.example.test",
                "server_port": 443,
                "uuid": "15151515-1515-4515-8515-151515151515",
                "security": "auto",
                "transport": {
                    "type": "ws",
                    "path": "/edge",
                    "headers": {"Host": "ws-import.example.test", "Edge": "edge-1"},
                },
                "tls": {
                    "enabled": True,
                    "server_name": "tls-import.example.test",
                    "utls": {"enabled": True, "fingerprint": "firefox"},
                },
            },
            {
                "type": "vless",
                "tag": "Singbox HTTPUpgrade",
                "server": "vless-import.example.test",
                "server_port": 443,
                "uuid": "16161616-1616-4616-8616-161616161616",
                "transport": {
                    "type": "httpupgrade",
                    "host": "upgrade-import.example.test",
                    "path": "/upgrade",
                },
                "tls": {"enabled": True, "server_name": "vless-tls.example.test"},
            },
            {
                "type": "trojan",
                "tag": "Singbox Trojan gRPC",
                "server": "trojan-import.example.test",
                "server_port": 443,
                "password": "trojan-import-password",
                "transport": {"type": "grpc", "service_name": "trojan/service"},
                "tls": {
                    "enabled": True,
                    "server_name": "trojan-tls.example.test",
                    "utls": {"enabled": True, "fingerprint": "safari"},
                },
            },
            {
                "type": "vless",
                "tag": "Unsupported Transport",
                "server": "unsupported-import.example.test",
                "server_port": 443,
                "uuid": "17171717-1717-4717-8717-171717171717",
                "transport": {"type": "future-transport"},
            },
        ]
    },
    separators=(",", ":"),
)
HYSTERIA_V1_CLASH_CONFIG = """proxies:
  - name: Hysteria V1 Clash
    type: hysteria
    server: hy1-clash.example.test
    port: 443
    ports: 443,10000-10002
    auth-str: clash-auth
    protocol: udp
    up: 30 Mbps
    down: 200 Mbps
    obfs: clash-obfs
    alpn: [h3, hysteria]
    sni: clash-hy1.example.test
    skip-cert-verify: true
"""
SNELL_SURGE_CONFIG = """[Proxy]
Snell V4 = snell, snell-v4.example.test, 443, psk=snell-secret==, version=4, reuse=true, obfs=http, obfs-host=cdn.example.test, obfs-uri=/resource
Snell Shadow = snell, snell-shadow.example.test, 8443, psk=shadow-secret, version=4, reuse=false, shadow-tls-password=shadow-password, shadow-tls-sni=shadow.example.test, shadow-tls-version=3
Snell V3 TLS = snell, snell-v3.example.test, 7443, psk=snell-v3-secret, version=3, obfs=tls, obfs-host=tls.example.test, udp-port=7444
Snell V6 = snell, snell-v6.example.test, 9443, psk=123456789012, version=6, reuse=true, mode=unshaped
"""
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
    "stash",
    "mellow",
    "singbox",
    "ss",
    "ssd",
    "ssr",
    "sssub",
    "v2ray",
    "v2rayn",
    "v2rayng",
    "shadowrocket",
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
    gist_uploaded_paths: list[str] = []
    provider_never_fetch_count = 0
    quanx_remote_fetch_count = 0
    stash_rule_source_count = 0
    stash_legacy_text_fetch_count = 0
    external_valid_count = 0
    get_request_count = 0
    subscription_request_count = 0
    recoverable_retry_request_count = 0
    recoverable_retry_failures = 0
    slow_subscription_request_count = 0
    webget_probe_counts: dict[str, int] = {}
    counter_lock = threading.Lock()
    slow_subscription_started = threading.Event()
    slow_subscription_release = threading.Event()
    slow_ruleset_started = threading.Event()
    slow_ruleset_release = threading.Event()
    quanx_roundtrip_config = ""
    stash_invalid_bases: dict[str, str] = {}

    def do_GET(self) -> None:  # noqa: N802
        with type(self).counter_lock:
            type(self).get_request_count += 1
        request_url = urllib.parse.urlsplit(self.path)
        request_path = request_url.path
        request_query = urllib.parse.parse_qs(request_url.query)
        if request_path == "/subscription.txt":
            with type(self).counter_lock:
                type(self).subscription_request_count += 1
            body = ENCODED_SUBSCRIPTION.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/recoverable-retry-subscription.txt":
            with type(self).counter_lock:
                type(self).recoverable_retry_request_count += 1
                attempt = type(self).recoverable_retry_request_count
                failures = type(self).recoverable_retry_failures
            if attempt <= failures:
                self.close_connection = True
                self.connection.close()
                return
            body = ENCODED_SUBSCRIPTION.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/select-health.toml":
            body = SELECT_HEALTH_TOML_CONFIG.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/provider-must-not-fetch.txt":
            type(self).provider_never_fetch_count += 1
            body = ENCODED_SUBSCRIPTION.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/quanx-remote.txt":
            type(self).quanx_remote_fetch_count += 1
            body = ENCODED_SUBSCRIPTION.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path in (
            "/stash-domain.mrs",
            "/stash-domain-yaml.yaml",
            "/stash-domain-text.list",
            "/stash-domain-api",
            "/stash-ip.mrs",
            "/stash-ip-yaml.yml",
            "/stash-ip-text.txt",
            "/stash-classical.txt",
            "/stash-classical-yaml.yaml",
        ):
            type(self).stash_rule_source_count += 1
            body = b"fixture body must never be fetched by the server"
            content_type = "application/octet-stream"
        elif request_path == "/stash-legacy-domain.txt":
            type(self).stash_legacy_text_fetch_count += 1
            body = b"DOMAIN,legacy-text.example\n"
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/mihomo-raw-subscription.txt":
            body = SUBSCRIPTION.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/slow-subscription.txt":
            with type(self).counter_lock:
                type(self).slow_subscription_request_count += 1
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
        elif request_path == "/hysteria-v1-singbox.json":
            body = HYSTERIA_V1_SINGBOX_CONFIG.encode()
            content_type = "application/json; charset=utf-8"
        elif request_path == "/singbox-transport-fidelity.json":
            body = SINGBOX_TRANSPORT_FIDELITY_CONFIG.encode()
            content_type = "application/json; charset=utf-8"
        elif request_path == "/quanx-roundtrip.conf":
            body = type(self).quanx_roundtrip_config.encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/hysteria-v1-clash.yaml":
            body = HYSTERIA_V1_CLASH_CONFIG.encode()
            content_type = "text/yaml; charset=utf-8"
        elif request_path == "/snell-surge.conf":
            body = SNELL_SURGE_CONFIG.encode()
            content_type = "text/plain; charset=utf-8"
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
        elif request_path == "/singbox-modern-rules.list":
            body = (
                "GEOSITE,cn\n"
                "GEOIP,cn\n"
                "SRC-GEOIP,us\n"
                "DOMAIN-SUFFIX,modern-singbox.example\n"
                "IP-CIDR,198.51.100.0/24\n"
                "SRC-PORT,41641\n"
                "PORT,999999999999999999999999\n"
                "GEOSITE,../../unsafe\n"
                "FINAL,Proxy\n"
            ).encode()
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
        elif request_path == "/external-singbox-modern.ini":
            host = self.headers.get("Host", "127.0.0.1")
            body = (
                "[custom]\n"
                "enable_rule_generator=true\n"
                "overwrite_original_rules=true\n"
                "custom_proxy_group=Proxy`select`.*\n"
                f"ruleset=Proxy,http://{host}/singbox-modern-rules.list\n"
            ).encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/external-stash-invalid.ini":
            case = request_query.get("case", [""])[0]
            if case not in type(self).stash_invalid_bases:
                self.send_error(404)
                return
            host = self.headers.get("Host", "127.0.0.1")
            encoded_case = urllib.parse.quote(case, safe="")
            body = (
                "[custom]\n"
                "enable_rule_generator=false\n"
                f"stash_rule_base=http://{host}/stash-invalid-base.yaml?"
                f"case={encoded_case}\n"
            ).encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/external-stash-rules.ini":
            host = self.headers.get("Host", "127.0.0.1")
            body = (
                "[custom]\n"
                "enable_rule_generator=true\n"
                "overwrite_original_rules=true\n"
                "custom_proxy_group=RuleGroup`select`.*\n"
                f"ruleset=RuleGroup,clash-domain:http://{host}/stash-domain.mrs?"
                "token=stash-domain-token,3600\n"
                f"ruleset=RuleGroup,clash-domain:http://{host}/stash-domain-yaml.yaml?"
                "token=stash-domain-yaml-token,3601\n"
                f"ruleset=RuleGroup,clash-domain:http://{host}/stash-domain-text.list?"
                "token=stash-domain-text-token,3602|stash-format=text\n"
                f"ruleset=RuleGroup,clash-domain:http://{host}/stash-domain-api?"
                "token=stash-domain-api-token,3603|stash-format=yaml\n"
                f"ruleset=RuleGroup,clash-ipcidr:http://{host}/stash-ip.mrs?"
                "token=stash-ip-token,7200|no-resolve\n"
                f"ruleset=RuleGroup,clash-ipcidr:http://{host}/stash-ip-yaml.yml?"
                "token=stash-ip-yaml-token,7201\n"
                f"ruleset=RuleGroup,clash-ipcidr:http://{host}/stash-ip-text.txt?"
                "token=stash-ip-text-token,7202|stash-format=text\n"
                f"ruleset=RuleGroup,clash-classic:http://{host}/stash-classical.txt?"
                "token=stash-classical-token,1800|stash-format=text\n"
                f"ruleset=RuleGroup,clash-classic:http://{host}/stash-classical-yaml.yaml?"
                "token=stash-classical-yaml-token,1801\n"
                "ruleset=RuleGroup,[]GEOSITE,telegram\n"
                "ruleset=RuleGroup,[]GEOIP,CN\n"
            ).encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/external-stash-rules-invalid.ini":
            host = self.headers.get("Host", "127.0.0.1")
            case = request_query.get("case", [""])[0]
            ruleset = {
                "classical-mrs": (
                    f"clash-classic:http://{host}/stash-classical.mrs,3600"
                ),
                "unknown-format": (
                    f"clash-domain:http://{host}/stash-domain.bin,3600"
                ),
                "src-port": "[]SRC-PORT,41641",
                "non-country-geoip": "[]GEOIP,telegram",
                "existing-policy": "[]DOMAIN,policy.example,DIRECT",
                "conflicting-format": (
                    f"clash-domain:http://{host}/stash-domain.mrs,"
                    "3600|stash-format=text|stash-format=yaml"
                ),
            }.get(case)
            if ruleset is None:
                self.send_error(404)
                return
            ruleset_lines = [f"ruleset=RuleGroup,{ruleset}"]
            if case == "existing-policy":
                ruleset_lines.insert(
                    0,
                    f"ruleset=RuleGroup,clash-domain:http://{host}/"
                    "stash-domain.mrs?token=stash-atomic-token,3600",
                )
            body = (
                "[custom]\n"
                "enable_rule_generator=true\n"
                "overwrite_original_rules=true\n"
                "custom_proxy_group=RuleGroup`select`.*\n"
                + "\n".join(ruleset_lines)
                + "\n"
            ).encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/external-stash-rules-legacy-text.ini":
            host = self.headers.get("Host", "127.0.0.1")
            body = (
                "[custom]\n"
                "enable_rule_generator=true\n"
                "overwrite_original_rules=true\n"
                "custom_proxy_group=RuleGroup`select`.*\n"
                f"ruleset=RuleGroup,clash-domain:http://{host}/"
                "stash-legacy-domain.txt,3600\n"
            ).encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/external-stash-rules-merge.ini":
            host = self.headers.get("Host", "127.0.0.1")
            case = request_query.get("case", ["merge"])[0]
            if case not in ("merge", "path-collision"):
                self.send_error(404)
                return
            body = (
                "[custom]\n"
                "enable_rule_generator=true\n"
                "overwrite_original_rules=false\n"
                "custom_proxy_group=RuleGroup`select`.*\n"
                f"stash_rule_base=http://{host}/stash-rules-merge-base.yaml?"
                f"case={case}\n"
                f"ruleset=RuleGroup,clash-domain:http://{host}/stash-domain.mrs?"
                "token=stash-merge-token,3600\n"
            ).encode()
            content_type = "text/plain; charset=utf-8"
        elif request_path == "/stash-rules-merge-base.yaml":
            case = request_query.get("case", ["merge"])[0]
            existing_name = "stash-domain" if case == "merge" else "base-domain"
            existing_path = (
                "./rules/existing-domain.txt"
                if case == "merge"
                else "./rules/stash-domain.mrs"
            )
            body = (
                "mode: rule\n"
                "proxies: []\n"
                "proxy-providers: {}\n"
                "proxy-groups:\n"
                "  - name: Proxy\n"
                "    type: select\n"
                "    proxies: [DIRECT]\n"
                "rule-providers:\n"
                f"  {existing_name}:\n"
                "    behavior: domain\n"
                "    format: text\n"
                "    url: https://127.0.0.1:1/existing-domain.txt\n"
                f"    path: {existing_path}\n"
                "rules:\n"
                f"  - RULE-SET,{existing_name},RuleGroup\n"
                "  - DOMAIN,base.example,RuleGroup\n"
                "  - MATCH,Proxy\n"
            ).encode()
            content_type = "text/yaml; charset=utf-8"
        elif request_path == "/stash-invalid-base.yaml":
            case = request_query.get("case", [""])[0]
            invalid_base = type(self).stash_invalid_bases.get(case)
            if invalid_base is None:
                self.send_error(404)
                return
            body = invalid_base.encode()
            content_type = "text/yaml; charset=utf-8"
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
        elif request_path == "/webget-probe-hit":
            with type(self).counter_lock:
                count = type(self).webget_probe_counts.get(request_path, 0) + 1
                type(self).webget_probe_counts[request_path] = count
            if (
                request_query.get("payload-singleflight") == ["1"]
                or request_query.get("owned-async-cache") == ["1"]
            ):
                time.sleep(0.25)
            body = ("owned-webget:" + request_path).encode()
            content_type = "text/plain; charset=utf-8"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        if request_path.startswith("/webget-probe-"):
            self.send_header("X-WebGet-Probe", "present")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _write_gist_response(self) -> None:
        content_length = int(self.headers.get("Content-Length", "0"))
        request_body = self.rfile.read(content_length) if content_length else b""
        try:
            request_data = json.loads(request_body) if request_body else {}
            uploaded_paths = list(request_data.get("files", {}).keys())
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            uploaded_paths = []
        with type(self).counter_lock:
            type(self).gist_request_count += 1
            type(self).gist_uploaded_paths.extend(uploaded_paths)
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
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

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
    FixtureHandler.gist_uploaded_paths = []
    FixtureHandler.provider_never_fetch_count = 0
    FixtureHandler.quanx_remote_fetch_count = 0
    FixtureHandler.stash_rule_source_count = 0
    FixtureHandler.stash_legacy_text_fetch_count = 0
    FixtureHandler.external_valid_count = 0
    FixtureHandler.get_request_count = 0
    FixtureHandler.subscription_request_count = 0
    FixtureHandler.recoverable_retry_request_count = 0
    FixtureHandler.recoverable_retry_failures = 0
    FixtureHandler.slow_subscription_request_count = 0
    FixtureHandler.webget_probe_counts = {}
    FixtureHandler.stash_invalid_bases = {}
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


def disconnect_raw_request(
    base_url: str,
    path: str,
    params: dict[str, str],
    *,
    hold_seconds: float = 0.1,
    headers: dict[str, str] | None = None,
) -> None:
    parsed = urllib.parse.urlsplit(base_url)
    query = urllib.parse.urlencode(params)
    target = path + (f"?{query}" if query else "")
    with socket.create_connection((parsed.hostname, parsed.port), timeout=20) as sock:
        request_lines = [
            f"GET {target} HTTP/1.1",
            f"Host: {parsed.hostname}:{parsed.port}",
            "Connection: close",
        ]
        request_lines.extend(
            f"{name}: {value}" for name, value in (headers or {}).items()
        )
        request_lines.extend(("", ""))
        sock.sendall("\r\n".join(request_lines).encode("ascii"))
        time.sleep(hold_seconds)


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
    environment: dict[str, str] | None = None,
):
    port = unused_port()
    baseline = (COMPAT_FIXTURES / "legacy-pref.toml").read_text(
        encoding="utf-8"
    )
    base_path = (REPOSITORY / "base" / "base").as_posix()
    baseline = baseline.replace('base_path = "base"', f'base_path = "{base_path}"')
    stash_base_setting = 'stash_rule_base = "base/stash.yaml"'
    if stash_base_setting in baseline:
        baseline = baseline.replace(
            stash_base_setting,
            f'stash_rule_base = "{base_path}/stash.yaml"',
            1,
        )
    else:
        baseline = baseline.replace(
            f'base_path = "{base_path}"',
            f'base_path = "{base_path}"\nstash_rule_base = "{base_path}/stash.yaml"',
            1,
        )
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
        # The temporary preference contains deterministic fixture credentials
        # used to prove runtime redaction; it never contains a production secret.
        # codeql[py/clear-text-storage-sensitive-data]
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
        if environment:
            env.update(environment)
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
            if body_error is not None and diagnostics and hasattr(body_error, "add_note"):
                body_error.add_note(
                    f"service stderr tail: {diagnostics[-8000:]!r}"
                )
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


def owned_webget_boundary_baseline(helper: Path, fixture_base: str) -> None:
    with tempfile.TemporaryDirectory(
        dir=REPOSITORY / "build", prefix="owned-webget-boundary-"
    ) as temporary:
        temporary_path = Path(temporary)
        pref = temporary_path / "pref.toml"
        pref.write_text(
            (COMPAT_FIXTURES / "legacy-pref.toml").read_text(encoding="utf-8"),
            encoding="utf-8",
            newline="\n",
        )
        environment = os.environ.copy()
        environment["SUBCONVERTER_FETCH_ENGINE"] = "multi"
        environment["NO_PROXY"] = "127.0.0.1,localhost"
        environment["no_proxy"] = "127.0.0.1,localhost"

        def run_probe(path: str, ttl: int, delay_ms: int) -> dict[str, object]:
            completed = subprocess.run(
                [
                    str(helper),
                    "--webget-probe",
                    str(pref),
                    fixture_base + path,
                    str(ttl),
                    str(delay_ms),
                ],
                cwd=temporary_path,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
            )
            if completed.returncode != 0:
                raise AssertionError(
                    "owned webGet helper failed: "
                    f"exit={completed.returncode}, stderr={completed.stderr[-4000:]!r}"
                )
            return json.loads(completed.stdout)

        with FixtureHandler.counter_lock:
            hit_before = FixtureHandler.webget_probe_counts.get(
                "/webget-probe-hit", 0
            )
        hit = run_probe("/webget-probe-hit", 60, 0)
        with FixtureHandler.counter_lock:
            hit_requests = (
                FixtureHandler.webget_probe_counts.get("/webget-probe-hit", 0)
                - hit_before
            )
        if (
            hit_requests != 3
            or hit["first_status"] != 200
            or hit["second_status"] != 200
            or hit["first_body"] != hit["second_body"]
            or hit["early_header_preserved"] is not True
            or "X-WebGet-Probe: present" not in str(hit["second_headers"])
            or int(hit["first_retained_bytes"]) < len(str(hit["first_body"]))
            or int(hit["second_retained_bytes"]) < len(str(hit["second_body"]))
            or hit["payload_bodies_equal"] is not True
            or int(hit["payload_peak_retained_bytes"]) <= 0
            or int(hit["payload_retained_bytes"]) != 0
            or int(hit["operation_success_callbacks"]) != 2
            or int(hit["operation_exception_callbacks"]) != 1
            or int(hit["operation_unsubscribed_callbacks"]) != 0
            or hit["operation_duplicate_publish_rejected"] is not True
            or hit["operation_exception_rethrown_to_waiter"] is not True
            or hit["operation_no_consumers_cancelled"] is not True
            or hit["operation_owner_kinds_isolated"] is not True
            or hit["async_consumer_probe_ok"] is not True
            or hit["async_data_ok"] is not True
            or hit["async_cache_ok"] is not True
            or hit["async_cache_rejection_ok"] is not True
            or hit["async_cache_resources_ok"] is not True
            or hit["continuation_runtime_ok"] is not True
        ):
            raise AssertionError(
                f"owned webGet TTL hit contract changed: requests={hit_requests}, "
                f"result={hit!r}"
            )


def fetch_shutdown_construction_race_baseline(helper: Path) -> None:
    with tempfile.TemporaryDirectory(
        dir=REPOSITORY / "build", prefix="fetch-shutdown-race-"
    ) as temporary:
        temporary_path = Path(temporary)
        pref = temporary_path / "pref.toml"
        pref.write_text(
            (COMPAT_FIXTURES / "legacy-pref.toml").read_text(
                encoding="utf-8"
            ),
            encoding="utf-8",
            newline="\n",
        )
        environment = os.environ.copy()
        environment["SUBCONVERTER_FETCH_ENGINE"] = "multi"
        for iteration in range(20):
            completed = subprocess.run(
                [
                    str(helper),
                    "--fetch-shutdown-race",
                    str(pref),
                ],
                cwd=temporary_path,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
            )
            if completed.returncode != 0:
                raise AssertionError(
                    "fetch construction/shutdown race did not join: "
                    f"iteration={iteration} exit={completed.returncode} "
                    f"stdout={completed.stdout!r} "
                    f"stderr={completed.stderr[-2000:]!r}"
                )
            snapshot = json.loads(completed.stdout)
            if snapshot != {
                "available": False,
                "pending": 0,
                "active": 0,
                "running": 0,
            }:
                raise AssertionError(
                    "fetch construction/shutdown race leaked runtime state: "
                    f"iteration={iteration} snapshot={snapshot!r}"
                )



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


def validate_singbox_config(binary: Path, content: bytes, label: str) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        config_path = Path(temporary) / "generated-singbox.json"
        config_path.write_bytes(content)
        completed = subprocess.run(
            [
                str(binary),
                "check",
                "--disable-color",
                "-c",
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
                f"pinned sing-box {label} rejected the generated profile: "
                f"exit={completed.returncode}, output={diagnostics[-8000:]!r}"
            )


def singbox_modern_full_profile_baseline(
    base_url: str,
    fixture_base: str,
    stable_binary: Path | None,
    next_binary: Path | None,
) -> None:
    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "singbox",
            "url": SUBSCRIPTION.strip(),
            "config": fixture_base + "/external-singbox-modern.ini",
        },
    )
    if status != 200:
        raise AssertionError(
            f"modern sing-box full profile returned HTTP {status}: {body!r}"
        )
    document = json.loads(body)

    dns = document.get("dns", {})
    dns_servers = dns.get("servers", [])
    if [server.get("type") for server in dns_servers] != [
        "tls",
        "h3",
        "fakeip",
        "udp",
    ]:
        raise AssertionError("built-in sing-box DNS servers are not modernized")
    if any(
        "address" in server or "address_resolver" in server
        for server in dns_servers
    ):
        raise AssertionError("legacy sing-box DNS server fields remain")
    if "fakeip" in dns or "independent_cache" in dns:
        raise AssertionError("legacy sing-box DNS options remain")
    if any("action" not in rule for rule in dns.get("rules", [])):
        raise AssertionError("modern sing-box DNS rules lost explicit actions")

    tun = next(
        inbound
        for inbound in document.get("inbounds", [])
        if inbound.get("type") == "tun"
    )
    if tun.get("address") != ["172.19.0.1/30"]:
        raise AssertionError("sing-box TUN addresses were not merged correctly")
    if any(
        field in tun for field in ("inet4_address", "inet6_address", "sniff")
    ):
        raise AssertionError("legacy sing-box TUN or sniff fields remain")

    route = document.get("route", {})
    route_rules = route.get("rules", [])
    if not any(rule.get("action") == "sniff" for rule in route_rules):
        raise AssertionError("sing-box route lost the sniff action")
    if not any(rule.get("action") == "hijack-dns" for rule in route_rules):
        raise AssertionError("sing-box route lost the DNS hijack action")
    if any("action" not in rule for rule in route_rules):
        raise AssertionError("sing-box route contains a legacy actionless rule")
    if any(
        legacy in rule
        for rule in route_rules
        for legacy in ("geosite", "geoip", "source_geoip")
    ):
        raise AssertionError("legacy GeoIP/Geosite route fields remain")
    if route.get("final") != "Proxy":
        raise AssertionError("sing-box final rule was not preserved")

    rule_sets = {
        item.get("tag"): item
        for item in route.get("rule_set", [])
        if isinstance(item, dict)
    }
    for expected in (
        "geosite-category-ads-all",
        "geosite-geolocation-!cn",
        "geosite-cn",
        "geoip-cn",
        "geoip-us",
    ):
        rule_set = rule_sets.get(expected)
        if (
            rule_set is None
            or rule_set.get("type") != "remote"
            or rule_set.get("format") != "binary"
            or not str(rule_set.get("url", "")).endswith(f"/{expected}.srs")
        ):
            raise AssertionError(
                f"sing-box remote rule-set is missing or malformed: {expected}"
            )

    source_geoip_rule = next(
        (
            rule
            for rule in route_rules
            if "geoip-us" in rule.get("rule_set", [])
        ),
        None,
    )
    if not source_geoip_rule or not source_geoip_rule.get(
        "rule_set_ip_cidr_match_source"
    ):
        raise AssertionError("source GeoIP did not retain source matching")
    ip_rule = next(
        (rule for rule in route_rules if "198.51.100.0/24" in rule.get("ip_cidr", [])),
        None,
    )
    source_port_rule = next(
        (rule for rule in route_rules if rule.get("source_port") == 41641),
        None,
    )
    if ip_rule is None or source_port_rule is None or ip_rule is source_port_rule:
        raise AssertionError("heterogeneous sing-box rules were not kept as OR rules")
    if any(
        rule.get("port") == 999999999999999999999999 for rule in route_rules
    ):
        raise AssertionError("out-of-range sing-box integer rule was not rejected")
    if any("unsafe" in str(item) for item in route.get("rule_set", [])):
        raise AssertionError("unsafe sing-box rule-set code was not rejected")

    ipv6_status, ipv6_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "singbox",
            "url": SUBSCRIPTION.strip(),
            "config": fixture_base + "/external-singbox-modern.ini",
            "singbox.ipv6": "1",
        },
    )
    if ipv6_status != 200:
        raise AssertionError(
            f"IPv6 sing-box full profile returned HTTP {ipv6_status}: "
            f"{ipv6_body!r}"
        )
    ipv6_document = json.loads(ipv6_body)
    ipv6_fakeip = next(
        server
        for server in ipv6_document.get("dns", {}).get("servers", [])
        if server.get("type") == "fakeip"
    )
    if ipv6_fakeip.get("inet6_range") != "fc00::/18":
        raise AssertionError("sing-box IPv6 FakeIP range was not rendered")
    ipv6_tun = next(
        inbound
        for inbound in ipv6_document.get("inbounds", [])
        if inbound.get("type") == "tun"
    )
    if ipv6_tun.get("address") != [
        "172.19.0.1/30",
        "fdfe:dcba:9876::1/126",
    ]:
        raise AssertionError("sing-box IPv6 TUN address was not rendered")

    if stable_binary is not None:
        validate_singbox_config(stable_binary, body, "stable")
        validate_singbox_config(stable_binary, ipv6_body, "stable IPv6")
    if next_binary is not None:
        validate_singbox_config(next_binary, body, "next")
        validate_singbox_config(next_binary, ipv6_body, "next IPv6")


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


def local_group_matcher_baseline(base_url: str) -> None:
    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "surge",
            "ver": "4",
            "url": "|".join(
                (
                    "tag:public," + SUBSCRIPTION.strip(),
                    "tag:secondary," + SECONDARY_SS_LINK,
                )
            ),
            "config": LOCAL_GROUP_MATCHER_CONFIG,
        },
    )
    output = body.decode("utf-8", errors="replace")
    if status != 200:
        raise AssertionError(
            f"local group matcher matrix returned HTTP {status}: {output!r}"
        )

    group_section = re.search(
        r"(?ms)^\[Proxy Group\]\s*\n(.*?)(?=^\[|\Z)", output
    )
    if group_section is None:
        raise AssertionError("Surge local matcher output is missing [Proxy Group]")
    observed_groups: dict[str, list[str]] = {}
    for line in group_section.group(1).splitlines():
        if " = " not in line:
            continue
        name, value = line.split(" = ", 1)
        fields = [field.strip() for field in value.split(",")]
        observed_groups[name] = fields[1:]

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
        observed = observed_groups.get(group_name)
        if observed != expected_members:
            raise AssertionError(
                f"Surge local matcher group {group_name} changed members: "
                f"{observed!r}; expected {expected_members!r}"
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
        observed = observed_groups.get(group_name)
        if observed is not None:
            raise AssertionError(
                f"Surge local matcher negative group {group_name} changed members: "
                f"{observed!r}; expected the empty group to be omitted"
            )


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


def vary_cache_and_coalesce_baseline(
    binary: Path, fixture_base: str, resource_mode: str | None = None
) -> None:
    logs: list[str] = []
    environment = (
        {"SUBCONVERTER_RESOURCE_CONTROL": resource_mode}
        if resource_mode is not None
        else None
    )
    with running_service(
        binary,
        statistics=True,
        log_capture=logs,
        log_level="debug",
        environment=environment,
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

        FixtureHandler.slow_subscription_started.clear()
        FixtureHandler.slow_subscription_release.clear()
        owner_disconnect_result: list[tuple[int, bytes, dict[str, str]]] = []
        owner_disconnect_error: list[BaseException] = []
        singleflight_headers = {
            "User-Agent": "Singleflight-Lifecycle-Test/1.0"
        }
        owner_disconnect_params = {
            **slow_params,
            "url": fixture_base
            + "/slow-subscription.txt?case=disconnect-owner",
        }
        with FixtureHandler.counter_lock:
            owner_disconnect_before = (
                FixtureHandler.slow_subscription_request_count
            )

        def run_owner_disconnect_follower() -> None:
            try:
                owner_disconnect_result.append(
                    request(
                        base_url,
                        "/sub",
                        owner_disconnect_params,
                        singleflight_headers,
                    )
                )
            except BaseException as error:
                owner_disconnect_error.append(error)

        disconnected_owner = threading.Thread(
            target=disconnect_raw_request,
            args=(base_url, "/sub", owner_disconnect_params),
            kwargs={
                "hold_seconds": 1.0,
                "headers": singleflight_headers,
            },
        )
        disconnected_owner.start()
        if not FixtureHandler.slow_subscription_started.wait(timeout=10):
            FixtureHandler.slow_subscription_release.set()
            disconnected_owner.join(timeout=5)
            raise AssertionError(
                "disconnecting owner did not reach the slow fixture"
            )
        surviving_follower = threading.Thread(
            target=run_owner_disconnect_follower
        )
        surviving_follower.start()
        time.sleep(0.3)
        disconnected_owner.join(timeout=5)
        if disconnected_owner.is_alive():
            FixtureHandler.slow_subscription_release.set()
            surviving_follower.join(timeout=5)
            raise AssertionError("singleflight owner socket did not close")
        time.sleep(0.2)
        FixtureHandler.slow_subscription_release.set()
        surviving_follower.join(timeout=20)
        if surviving_follower.is_alive() or owner_disconnect_error:
            raise AssertionError(
                "disconnecting owner prevented the follower from finishing: "
                f"{owner_disconnect_error!r}"
            )
        if (
            len(owner_disconnect_result) != 1
            or owner_disconnect_result[0][0] != 200
            or b"Smoke" not in owner_disconnect_result[0][1]
        ):
            raise AssertionError(
                "surviving follower did not receive the shared result after "
                f"owner disconnect: {owner_disconnect_result!r}"
            )
        with FixtureHandler.counter_lock:
            owner_disconnect_requests = (
                FixtureHandler.slow_subscription_request_count
                - owner_disconnect_before
            )
        if owner_disconnect_requests != 1:
            raise AssertionError(
                "owner disconnect started more than one upstream request: "
                f"{owner_disconnect_requests}"
            )

        FixtureHandler.slow_subscription_started.clear()
        FixtureHandler.slow_subscription_release.clear()
        surviving_owner: list[tuple[int, bytes, dict[str, str]]] = []
        surviving_error: list[BaseException] = []
        disconnect_params = {
            **slow_params,
            "url": fixture_base
            + "/slow-subscription.txt?case=disconnect-follower",
        }

        def run_surviving_owner() -> None:
            try:
                surviving_owner.append(
                    request(
                        base_url,
                        "/sub",
                        disconnect_params,
                        singleflight_headers,
                    )
                )
            except BaseException as error:
                surviving_error.append(error)

        owner = threading.Thread(target=run_surviving_owner)
        owner.start()
        if not FixtureHandler.slow_subscription_started.wait(timeout=10):
            FixtureHandler.slow_subscription_release.set()
            owner.join(timeout=5)
            raise AssertionError("disconnect owner did not reach the slow fixture")
        disconnect_raw_request(
            base_url,
            "/sub",
            disconnect_params,
            headers=singleflight_headers,
        )
        FixtureHandler.slow_subscription_release.set()
        owner.join(timeout=20)
        if owner.is_alive() or surviving_error:
            raise AssertionError(
                "disconnecting follower prevented the owner from finishing: "
                f"{surviving_error!r}"
            )
        if len(surviving_owner) != 1 or surviving_owner[0][0] != 200:
            raise AssertionError(
                f"disconnecting follower changed owner result: {surviving_owner!r}"
            )

        FixtureHandler.slow_subscription_started.clear()
        FixtureHandler.slow_subscription_release.clear()
        abandoned_params = {
            **slow_params,
            "url": fixture_base
            + "/slow-subscription.txt?case=no-consumers",
        }
        with FixtureHandler.counter_lock:
            abandoned_before = FixtureHandler.slow_subscription_request_count
        abandoned_owner = threading.Thread(
            target=disconnect_raw_request,
            args=(base_url, "/sub", abandoned_params),
            kwargs={
                "hold_seconds": 1.0,
                "headers": singleflight_headers,
            },
        )
        abandoned_owner.start()
        if not FixtureHandler.slow_subscription_started.wait(timeout=10):
            FixtureHandler.slow_subscription_release.set()
            abandoned_owner.join(timeout=5)
            raise AssertionError("abandoned owner did not reach the slow fixture")
        abandoned_follower = threading.Thread(
            target=disconnect_raw_request,
            args=(base_url, "/sub", abandoned_params),
            kwargs={
                "hold_seconds": 0.4,
                "headers": singleflight_headers,
            },
        )
        abandoned_follower.start()
        abandoned_follower.join(timeout=5)
        abandoned_owner.join(timeout=5)
        if abandoned_owner.is_alive() or abandoned_follower.is_alive():
            FixtureHandler.slow_subscription_release.set()
            raise AssertionError("abandoned consumer sockets did not close")
        time.sleep(0.2)
        dashboard_headers = {
            "Authorization": "Basic "
            + base64.b64encode(
                b"fixture-admin:fixture-dashboard-secret"
            ).decode()
        }
        time.sleep(1.1)
        status, body, _ = request(
            base_url, "/dashboard/data", headers=dashboard_headers
        )
        if status != 200:
            raise AssertionError(
                f"retained-byte dashboard returned HTTP {status}: {body!r}"
            )
        dashboard = json.loads(body)
        retained = dashboard["retained_response_bytes"]
        retained_bytes = int(retained["used"])
        outbound = dashboard["outbound_fetch"]
        if outbound["active"] != 0 or outbound["pending"] != 0:
            raise AssertionError(
                "all-consumer disconnect did not cancel outbound work: "
                f"{outbound!r}"
            )
        with FixtureHandler.counter_lock:
            abandoned_requests = (
                FixtureHandler.slow_subscription_request_count
                - abandoned_before
            )
        if abandoned_requests != 1:
            raise AssertionError(
                "all-consumer disconnect did not remain singleflight: "
                f"upstream requests={abandoned_requests}"
            )
        if retained_bytes <= 0 or retained_bytes > 8 * 1024 * 1024:
            raise AssertionError(
                "completed microcache result did not retain a bounded byte "
                f"lease: {retained_bytes}"
            )
        effective_resource_mode = (
            resource_mode
            if resource_mode is not None
            else os.environ.get("SUBCONVERTER_RESOURCE_CONTROL")
        )
        if effective_resource_mode == "adaptive":
            valid_retained_limit = retained["limit"] == 64 * 1024 * 1024
        elif effective_resource_mode == "force_max":
            valid_retained_limit = (
                retained["limit"] >= 64 * 1024 * 1024
                and retained["used"] <= retained["limit"]
            )
        else:
            valid_retained_limit = retained["limit"] == 0
        if not valid_retained_limit:
            raise AssertionError(
                "resource profile retained-byte limit changed: "
                f"mode={effective_resource_mode!r}, actual={retained!r}"
            )
        if effective_resource_mode == "force_max":
            singleflight = dashboard["subscription_singleflight"]
            if (
                int(singleflight["active_owners"]) != 0
                or int(singleflight["waiting_followers"]) != 0
                or int(singleflight["followers_cancelled_total"]) < 2
            ):
                raise AssertionError(
                    "force_max cancellation fanout telemetry did not settle: "
                    f"{singleflight!r}"
                )
        FixtureHandler.slow_subscription_release.set()

    diagnostics = "".join(logs)
    if "/sub 响应微缓存命中。" not in diagnostics:
        raise AssertionError("microcache Vary probe did not hit the response cache")
    assert_coalesced_request_link(
        diagnostics, coalesced_request_ids, "coalesced Vary probe"
    )


def response_microcache_eviction_baseline(binary: Path) -> None:
    dashboard_headers = {
        "Authorization": "Basic "
        + base64.b64encode(
            b"fixture-admin:fixture-dashboard-secret"
        ).decode()
    }
    with running_service(
        binary,
        statistics=True,
        config_replacements=(
            ("response_cache_ttl = 0", "response_cache_ttl = 2"),
        ),
    ) as base_url:
        params = {
            "target": "clash",
            "url": SUBSCRIPTION.strip(),
            "config": DISABLE_RULEGEN_CONFIG,
            "list": "true",
        }
        status, body, _ = request(base_url, "/sub", params)
        if status != 200 or b"Smoke" not in body:
            raise AssertionError(
                f"microcache expiry setup failed: HTTP {status}: {body!r}"
            )
        status, body, _ = request(
            base_url, "/dashboard/data", headers=dashboard_headers
        )
        if status != 200:
            raise AssertionError(
                f"microcache setup dashboard returned HTTP {status}: {body!r}"
            )
        before = json.loads(body)["response_microcache"]
        if before["entries"] != 1 or before["bytes"] <= 0:
            raise AssertionError(
                f"microcache expiry setup did not retain one entry: {before!r}"
            )

        time.sleep(2.2)
        status, body, _ = request(base_url, "/sub", params)
        if status != 200 or b"Smoke" not in body:
            raise AssertionError(
                f"expired microcache refill failed: HTTP {status}: {body!r}"
            )
        status, body, _ = request(
            base_url, "/dashboard/data", headers=dashboard_headers
        )
        if status != 200:
            raise AssertionError(
                f"microcache refill dashboard returned HTTP {status}: {body!r}"
            )
        after = json.loads(body)["response_microcache"]
        if after["entries"] != 1 or after["bytes"] != before["bytes"]:
            raise AssertionError(
                "expired microcache replacement retained stale byte "
                f"accounting: before={before!r}, after={after!r}"
            )

    with running_service(
        binary,
        statistics=True,
        config_replacements=(
            ("response_cache_ttl = 0", "response_cache_ttl = 5"),
        ),
        environment={"SUBCONVERTER_RESPONSE_CACHE_MAX_BYTES": "1024"},
    ) as base_url:
        for index in range(8):
            uri = SUBSCRIPTION.strip().replace("#Smoke", f"#Cache-{index}")
            status, body, _ = request(
                base_url,
                "/sub",
                {
                    "target": "clash",
                    "url": uri,
                    "config": DISABLE_RULEGEN_CONFIG,
                    "list": "true",
                },
            )
            if status != 200 or f"Cache-{index}".encode() not in body:
                raise AssertionError(
                    f"microcache eviction fixture {index} failed: "
                    f"HTTP {status}: {body!r}"
                )
        time.sleep(1.1)
        status, body, _ = request(
            base_url, "/dashboard/data", headers=dashboard_headers
        )
        if status != 200:
            raise AssertionError(
                f"microcache dashboard returned HTTP {status}: {body!r}"
            )
        cache = json.loads(body)["response_microcache"]
        if cache["max_bytes"] != 1024:
            raise AssertionError(f"microcache byte limit changed: {cache!r}")
        if not (0 < cache["entries"] < 8 and 0 < cache["bytes"] <= 1024):
            raise AssertionError(
                f"microcache did not evict by retained bytes: {cache!r}"
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


def proxy_group_block_from_output(output: str, group_name: str) -> str:
    marker = f"  - name: {group_name}\n"
    start = output.find(marker)
    if start < 0:
        raise AssertionError(f"proxy group block is missing: {group_name}")
    following = output[start + len(marker) :]
    next_group = re.search(r"(?m)^  - name: ", following)
    end = len(following) if next_group is None else next_group.start()
    return marker + following[:end]


def assert_select_health_group(
    output: str, group_name: str, expected_url: str, label: str
) -> None:
    block = proxy_group_block_from_output(output, group_name)
    url_match = re.search(
        r'(?m)^    url: ["\']?' + re.escape(expected_url) + r'["\']?\s*$',
        block,
    )
    if url_match is None:
        raise AssertionError(
            f"{label} did not preserve the select health-check URL\n{block}"
        )

    members = re.findall(r"(?m)^      - (.+?)\s*$", block)
    if not members:
        compact = re.search(r"(?m)^    proxies: \[(.*?)\]\s*$", block)
        if compact is not None:
            members = [
                value.strip().strip('"\'')
                for value in compact.group(1).split(",")
                if value.strip()
            ]
    if members != ["DIRECT"]:
        raise AssertionError(
            f"{label} changed select health group members: {members!r}\n{block}"
        )
    if re.search(r"(?m)^    (?:use|filter):", block):
        raise AssertionError(
            f"{label} added provider selection to a DIRECT-only group\n{block}"
        )


def select_health_check_output_baseline(base_url: str, fixture_base: str) -> None:
    provider_source = fixture_base + "/subscription.txt"
    cases = (
        ("INI direct", SUBSCRIPTION.strip(), SELECT_HEALTH_INI_CONFIG, False),
        (
            "INI provider",
            f"provider:HealthOne,{provider_source}?case=select-health-one",
            SELECT_HEALTH_INI_CONFIG,
            True,
        ),
        (
            "INI providers",
            "|".join(
                (
                    f"provider:HealthOne,{provider_source}?case=select-health-a",
                    f"provider:HealthTwo,{provider_source}?case=select-health-b",
                )
            ),
            SELECT_HEALTH_INI_CONFIG,
            True,
        ),
        (
            "INI mixed",
            "|".join(
                (
                    SUBSCRIPTION.strip(),
                    f"provider:HealthOne,{provider_source}?case=select-health-mixed",
                )
            ),
            SELECT_HEALTH_INI_CONFIG,
            True,
        ),
        (
            "TOML provider",
            f"provider:HealthOne,{provider_source}?case=select-health-toml",
            fixture_base + "/select-health.toml",
            True,
        ),
    )

    for label, source, config, expects_provider in cases:
        status, body, _ = request(
            base_url,
            "/sub",
            {"target": "clash", "url": source, "config": config},
        )
        output = body.decode("utf-8", errors="replace")
        if status != 200:
            raise AssertionError(
                f"{label} select health request returned HTTP {status}: {output!r}"
            )
        if ("proxy-providers:" in output) is not expects_provider:
            raise AssertionError(
                f"{label} did not exercise the intended provider mode\n{output}"
            )

        if label.startswith("INI"):
            assert_select_health_group(
                output,
                "DIRECT-HEALTH-HTTP",
                SELECT_HEALTH_HTTP_URL,
                label,
            )
            assert_select_health_group(
                output,
                "DIRECT-HEALTH-HTTPS",
                SELECT_HEALTH_HTTPS_URL,
                label,
            )
        else:
            assert_select_health_group(
                output,
                "DIRECT-HEALTH-TOML",
                SELECT_HEALTH_HTTPS_URL,
                label,
            )
            assert_select_health_group(
                output,
                "DIRECT-HEALTH-TOML-RULE",
                SELECT_HEALTH_HTTP_URL,
                label,
            )


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


def legacy_niche_protocol_baseline(base_url: str, fixture_base: str) -> None:
    def reject_duplicate_json_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise AssertionError(
                    f"sing-box output contains duplicate JSON key {key!r}"
                )
            result[key] = value
        return result

    def singbox_outbound(source: str, tag: str) -> dict:
        status, body, _ = request(
            base_url,
            "/sub",
            {
                "target": "singbox",
                "url": source,
                "list": "true",
                "udp": "true",
                "tfo": "false",
                "scv": "true",
            },
        )
        if status != 200:
            raise AssertionError(
                f"sing-box legacy protocol conversion failed: HTTP {status} {body!r}"
            )
        payload = json.loads(
            body.decode("utf-8"), object_pairs_hook=reject_duplicate_json_keys
        )
        for outbound in payload.get("outbounds", []):
            if outbound.get("tag") == tag:
                return outbound
        raise AssertionError(f"missing sing-box outbound {tag!r}: {payload!r}")

    uri_outbound = singbox_outbound(HYSTERIA_V1_URI, "Hysteria V1+Literal")
    expected_uri_fields = {
        "type": "hysteria",
        "server": "2001:db8::14",
        "server_port": 36712,
        "up_mbps": 100,
        "down_mbps": 200,
        "obfs": "obfs+secret",
        "auth_str": "p@ss+word",
    }
    if any(uri_outbound.get(key) != expected for key, expected in expected_uri_fields.items()):
        raise AssertionError(f"Hysteria v1 URI mapping drifted: {uri_outbound!r}")
    if uri_outbound.get("tls") != {
        "enabled": True,
        "server_name": "hy1-tls.example.test",
        "insecure": True,
        "alpn": ["h3", "hysteria"],
    }:
        raise AssertionError(f"Hysteria v1 URI TLS drifted: {uri_outbound!r}")

    singbox_outbound_from_config = singbox_outbound(
        fixture_base + "/hysteria-v1-singbox.json",
        "Hysteria V1 sing-box",
    )
    for key, expected in (
        ("server_ports", ["20000:20002", "30000:30000"]),
        ("hop_interval", "45s"),
        ("up", "640 KBps"),
        ("down_mbps", 200),
        ("auth", "YmluYXJ5LWF1dGg="),
        ("network", "tcp"),
    ):
        if singbox_outbound_from_config.get(key) != expected:
            raise AssertionError(
                f"sing-box Hysteria v1 {key} drifted: "
                f"{singbox_outbound_from_config!r}"
            )
    if "auth_str" in singbox_outbound_from_config:
        raise AssertionError(
            "base64 Hysteria v1 authentication was rewritten as auth_str"
        )
    scalar_ports_outbound = singbox_outbound(
        fixture_base + "/hysteria-v1-singbox.json",
        "Hysteria V1 scalar ports",
    )
    if scalar_ports_outbound.get("server_ports") != ["40000:40002"]:
        raise AssertionError(
            "sing-box scalar Hysteria v1 server_ports was not preserved: "
            f"{scalar_ports_outbound!r}"
        )

    clash_outbound = singbox_outbound(
        fixture_base + "/hysteria-v1-clash.yaml",
        "Hysteria V1 Clash",
    )
    for key, expected in (
        ("server_ports", ["443:443", "10000:10002"]),
        ("auth_str", "clash-auth"),
        ("up_mbps", 30),
        ("down_mbps", 200),
        ("obfs", "clash-obfs"),
    ):
        if clash_outbound.get(key) != expected:
            raise AssertionError(
                f"Clash Hysteria v1 {key} drifted: {clash_outbound!r}"
            )
    if clash_outbound.get("tls") != {
        "enabled": True,
        "server_name": "clash-hy1.example.test",
        "insecure": True,
        "alpn": ["h3", "hysteria"],
    }:
        raise AssertionError(f"Clash Hysteria v1 TLS drifted: {clash_outbound!r}")

    faketcp_status, faketcp_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "singbox",
            "url": HYSTERIA_V1_URI.replace("protocol=udp", "protocol=faketcp"),
            "list": "true",
        },
    )
    if faketcp_status == 200 and b"Hysteria V1+Literal" in faketcp_body:
        raise AssertionError(
            "sing-box emitted a Hysteria v1 faketcp outbound it cannot express"
        )

    missing_speed_status, _, _ = request(
        base_url,
        "/sub",
        {
            "target": "singbox",
            "url": HYSTERIA_V1_URI.replace("&downmbps=200", ""),
            "list": "true",
        },
    )
    if missing_speed_status != 400:
        raise AssertionError("Hysteria v1 URI without downlink speed was accepted")
    invalid_speed_status, _, _ = request(
        base_url,
        "/sub",
        {
            "target": "singbox",
            "url": HYSTERIA_V1_URI.replace(
                "downmbps=200", "downmbps=2%20Gbps"
            ),
            "list": "true",
        },
    )
    if invalid_speed_status != 400:
        raise AssertionError("Hysteria v1 URI accepted a non-Mbps speed value")

    no_tls_config = json.dumps(
        {
            "outbounds": [
                {
                    "type": "hysteria",
                    "tag": "Missing TLS",
                    "server": "hy1-no-tls.example.test",
                    "server_port": 443,
                    "up_mbps": 20,
                    "down_mbps": 80,
                }
            ]
        },
        separators=(",", ":"),
    )
    no_tls_url = "data:application/json;base64," + base64.b64encode(
        no_tls_config.encode("utf-8")
    ).decode("ascii")
    no_tls_status, _, _ = request(
        base_url,
        "/sub",
        {"target": "singbox", "url": no_tls_url, "list": "true"},
    )
    if no_tls_status != 400:
        raise AssertionError("sing-box Hysteria v1 without TLS was accepted")

    snell_status, snell_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "surge",
            "ver": "4",
            "url": fixture_base + "/snell-surge.conf",
            "list": "true",
        },
    )
    snell = snell_body.decode("utf-8", errors="replace")
    expected_snell_fragments = (
        "Snell V4 = snell, snell-v4.example.test, 443, psk=snell-secret==",
        "version=4",
        "reuse=true",
        "obfs=http",
        "obfs-host=cdn.example.test",
        "obfs-uri=/resource",
        "Snell Shadow = snell, snell-shadow.example.test, 8443, psk=shadow-secret",
        "shadow-tls-password=shadow-password",
        "shadow-tls-sni=shadow.example.test",
        "shadow-tls-version=3",
        "Snell V3 TLS = snell, snell-v3.example.test, 7443, psk=snell-v3-secret",
        "obfs=tls",
        "obfs-host=tls.example.test",
        "udp-port=7444",
        "Snell V6 = snell, snell-v6.example.test, 9443, psk=123456789012",
        "version=6",
        "reuse=true",
        "mode=unshaped",
    )
    if snell_status != 200 or any(
        fragment not in snell for fragment in expected_snell_fragments
    ):
        raise AssertionError(
            f"Surge Snell v4/v6 conversion drifted: HTTP {snell_status} {snell!r}"
        )

    invalid_snell_lines = (
        "Bad V6 Obfs = snell, bad.example.test, 443, psk=secret, version=6, obfs=http",
        "Bad V5 Mode = snell, bad.example.test, 443, psk=secret, version=5, mode=unshaped",
        "Bad V2 UDP = snell, bad.example.test, 443, psk=secret, version=2, udp-port=7444",
        "Bad Shadow TLS = snell, bad.example.test, 443, psk=secret, version=4, shadow-tls-password=shadow, shadow-tls-version=3",
        "Bad Reuse = snell, bad.example.test, 443, psk=secret, version=4, reuse=maybe",
    )
    for invalid_line in invalid_snell_lines:
        invalid_source = "data:text/plain;base64," + base64.b64encode(
            ("[Proxy]\n" + invalid_line + "\n").encode("utf-8")
        ).decode("ascii")
        invalid_status, _, _ = request(
            base_url,
            "/sub",
            {
                "target": "surge",
                "ver": "4",
                "url": invalid_source,
                "list": "true",
            },
        )
        if invalid_status != 400:
            raise AssertionError(
                f"invalid Surge Snell combination was accepted: {invalid_line!r}"
            )


def singbox_snell_outbound_baseline(
    default_base_url: str, enabled_base_url: str
) -> None:
    def reject_duplicate_json_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise AssertionError(
                    f"sing-box output contains duplicate JSON key {key!r}"
                )
            result[key] = value
        return result

    def data_url(content: str, media_type: str = "text/plain") -> str:
        encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
        return f"data:{media_type};base64,{encoded}"

    def convert(
        service: str, source: str, *, target: str = "singbox", ver: str = ""
    ) -> tuple[int, dict[str, object] | None]:
        params = {"target": target, "url": source, "list": "true"}
        if ver:
            params["ver"] = ver
        status, body, _ = request(service, "/sub", params)
        if status != 200:
            return status, None
        return status, json.loads(
            body.decode("utf-8"), object_pairs_hook=reject_duplicate_json_keys
        )

    legacy_source = data_url(
        "[Proxy]\n"
        "Snell V4 = snell, snell-v4.example.test, 443, "
        "psk=snell-v4-secret, version=4, reuse=true, "
        "obfs=http, obfs-host=cdn.example.test\n"
        "Snell V5 = snell, snell-v5.example.test, 8443, "
        "psk=snell-v5-secret, version=5, reuse=false\n"
        "Snell V6 = snell, snell-v6.example.test, 9443, "
        "psk=123456789012, version=6, reuse=true, mode=unshaped\n"
    )
    disabled_status, _ = convert(default_base_url, legacy_source)
    if disabled_status != 400:
        raise AssertionError(
            "sing-box Snell output changed without the opt-in switch: "
            f"HTTP {disabled_status}"
        )

    enabled_status, enabled_payload = convert(enabled_base_url, legacy_source)
    if enabled_status != 200 or enabled_payload is None:
        raise AssertionError(
            f"enabled sing-box Snell conversion failed: HTTP {enabled_status}"
        )
    enabled_outbounds = {
        outbound.get("tag"): outbound
        for outbound in enabled_payload.get("outbounds", [])
        if isinstance(outbound, dict)
    }
    if enabled_outbounds.get("Snell V4") != {
        "type": "snell",
        "tag": "Snell V4",
        "server": "snell-v4.example.test",
        "server_port": 443,
        "version": 4,
        "psk": "snell-v4-secret",
        "reuse": True,
        "obfs_mode": "http",
        "obfs_host": "cdn.example.test",
        "tcp_fast_open": True,
    }:
        raise AssertionError(
            f"sing-box Snell v4 mapping drifted: {enabled_outbounds!r}"
        )
    if enabled_outbounds.get("Snell V5") != {
        "type": "snell",
        "tag": "Snell V5",
        "server": "snell-v5.example.test",
        "server_port": 8443,
        "version": 4,
        "psk": "snell-v5-secret",
        "reuse": False,
        "tcp_fast_open": True,
    }:
        raise AssertionError(
            "non-QUIC Snell v5 was not normalized to v4 exactly: "
            f"{enabled_outbounds!r}"
        )
    if enabled_outbounds.get("Snell V6") != {
        "type": "snell",
        "tag": "Snell V6",
        "server": "snell-v6.example.test",
        "server_port": 9443,
        "version": 6,
        "psk": "123456789012",
        "reuse": True,
        "mode": "unshaped",
        "tcp_fast_open": True,
    }:
        raise AssertionError(
            f"sing-box Snell v6 mapping drifted: {enabled_outbounds!r}"
        )

    native_source = data_url(
        json.dumps(
            {
                "outbounds": [
                    {
                        "type": "snell",
                        "tag": "Native Snell V4",
                        "server": "native-v4.example.test",
                        "server_port": 443,
                        "version": 4,
                        "psk": "native-v4-secret",
                        "userkey": "native-user-key",
                        "reuse": True,
                        "network": "udp",
                        "obfs_mode": "http",
                        "obfs_host": "native-cdn.example.test",
                        "tcp_fast_open": True,
                    },
                    {
                        "type": "snell",
                        "tag": "Native Snell V6",
                        "server": "2001:db8::66",
                        "server_port": 9443,
                        "version": 6,
                        "psk": "abcdefghijkl",
                        "network": ["tcp", "udp"],
                        "mode": "unsafe-raw",
                    },
                ]
            },
            separators=(",", ":"),
        ),
        "application/json",
    )
    native_status, native_payload = convert(enabled_base_url, native_source)
    if native_status != 200 or native_payload is None:
        raise AssertionError(
            f"native sing-box Snell round trip failed: HTTP {native_status}"
        )
    native_outbounds = {
        outbound.get("tag"): outbound
        for outbound in native_payload.get("outbounds", [])
        if isinstance(outbound, dict)
    }
    expected_native_v4 = {
        "type": "snell",
        "tag": "Native Snell V4",
        "server": "native-v4.example.test",
        "server_port": 443,
        "version": 4,
        "psk": "native-v4-secret",
        "userkey": "native-user-key",
        "reuse": True,
        "network": "udp",
        "obfs_mode": "http",
        "obfs_host": "native-cdn.example.test",
        "tcp_fast_open": True,
    }
    if native_outbounds.get("Native Snell V4") != expected_native_v4:
        raise AssertionError(
            f"native Snell v4 fields were not preserved: {native_outbounds!r}"
        )
    expected_native_v6 = {
        "type": "snell",
        "tag": "Native Snell V6",
        "server": "2001:db8::66",
        "server_port": 9443,
        "version": 6,
        "psk": "abcdefghijkl",
        "mode": "unsafe-raw",
        "tcp_fast_open": True,
    }
    if native_outbounds.get("Native Snell V6") != expected_native_v6:
        raise AssertionError(
            f"native Snell v6 fields were not preserved: {native_outbounds!r}"
        )

    invalid_nodes = (
        {"version": 3, "psk": "legacy-secret"},
        {"version": 5, "psk": "not-an-official-outbound"},
        {"version": 6, "psk": "short"},
        {"version": 6, "psk": "abcdefghijkl", "obfs_mode": "http"},
        {"version": 4, "psk": "secret", "mode": "unshaped"},
        {"version": 4, "psk": "secret", "network": ["tcp", "tcp"]},
        {"version": 4, "psk": "secret", "detour": "hidden-dialer"},
        {"version": "4", "psk": "wrong-type"},
    )
    for index, overrides in enumerate(invalid_nodes):
        node: dict[str, object] = {
            "type": "snell",
            "tag": f"Invalid Snell {index}",
            "server": "invalid.example.test",
            "server_port": 443,
        }
        node.update(overrides)
        source = data_url(
            json.dumps({"outbounds": [node]}, separators=(",", ":")),
            "application/json",
        )
        invalid_status, _ = convert(enabled_base_url, source)
        if invalid_status != 400:
            raise AssertionError(
                f"invalid native Snell outbound was accepted: {node!r}"
            )

    mixed_source = data_url(
        "[Proxy]\n"
        "Safe SS = ss, safe.example.test, 8388, "
        "encrypt-method=aes-128-gcm, password=safe-password\n"
        "Unsupported Snell = snell, old.example.test, 443, "
        "psk=old-secret, version=3\n"
    )
    mixed_status, mixed_payload = convert(enabled_base_url, mixed_source)
    if mixed_status != 200 or mixed_payload is None:
        raise AssertionError(
            f"mixed sing-box output failed: HTTP {mixed_status}"
        )
    mixed_outbounds = mixed_payload.get("outbounds", [])
    if not any(
        isinstance(outbound, dict)
        and outbound.get("tag") == "Safe SS"
        and outbound.get("type") == "shadowsocks"
        for outbound in mixed_outbounds
    ) or any(
        isinstance(outbound, dict) and outbound.get("type") == "snell"
        for outbound in mixed_outbounds
    ):
        raise AssertionError(
            f"mixed output did not skip only unsupported Snell: {mixed_payload!r}"
        )

    surge_source = data_url(
        json.dumps(
            {
                "outbounds": [
                    {
                        "type": "snell",
                        "tag": "Surge Must Reject",
                        "server": "native-v4.example.test",
                        "server_port": 443,
                        "version": 4,
                        "psk": "native-v4-secret",
                        "userkey": "native-user-key",
                        "network": "udp",
                    }
                ]
            },
            separators=(",", ":"),
        ),
        "application/json",
    )
    surge_status, _, _ = request(
        enabled_base_url,
        "/sub",
        {
            "target": "surge",
            "ver": "4",
            "url": surge_source,
            "list": "true",
        },
    )
    if surge_status != 400:
        raise AssertionError(
            "Snell userkey/network were silently discarded by Surge output"
        )


def wireguard_structured_conversion_baseline(
    base_url: str, endpoint_base_url: str
) -> None:
    private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    public_key_one = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
    public_key_two = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
    preshared_key = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD="

    def data_url(content: str) -> str:
        return "data:text/plain;base64," + base64.b64encode(
            content.encode("utf-8")
        ).decode("ascii")

    def convert(
        service: str, target: str, source: str, *, list_mode: bool = False
    ) -> str:
        params = {
            "target": target,
            "url": source,
            "config": DISABLE_RULEGEN_CONFIG,
            "list": str(list_mode).lower(),
        }
        if target == "surge":
            params["ver"] = "4"
        status, body, _ = request(service, "/sub", params)
        if status != 200:
            raise AssertionError(
                f"WireGuard target={target} returned HTTP {status}: {body!r}"
            )
        return body.decode("utf-8").replace("\r\n", "\n")

    surge_source = (
        "[Proxy]\n"
        "WG Structured = wireguard, section-name=structured\n\n"
        "[WireGuard structured]\n"
        f"private-key = {private_key}\n"
        "self-ip = 10.77.0.2\n"
        "self-ip-v6 = 2001:db8:77::2\n"
        "dns-server = 1.1.1.1,2606:4700:4700::1111\n"
        "mtu = 1280\n"
        "peer = ("
        f"public-key = {public_key_one}, "
        "allowed-ips = \"0.0.0.0/0, ::/0\", "
        "endpoint = wg-one.example.test:51820, "
        f"preshared-key = {preshared_key}, keepalive = 25)\n"
        "peer = ("
        f"public-key = {public_key_two}, "
        "allowed-ips = \"10.0.0.0/8, 2001:db8::/32\", "
        "endpoint = [2001:db8::53]:51821, client-id = 1/2/3, "
        "keepalive = 25)\n"
    )
    surge_data = data_url(surge_source)

    surge_output = convert(base_url, "surge", surge_data)
    for expected in (
        "private-key=" + private_key,
        "self-ip=10.77.0.2",
        "self-ip-v6=2001:db8:77::2",
        "public-key = " + public_key_one,
        "public-key = " + public_key_two,
        "endpoint = [2001:db8::53]:51821",
        "preshared-key = " + preshared_key,
        "keepalive = 25",
        "client-id = 1/2/3",
    ):
        if expected not in surge_output:
            raise AssertionError(
                f"Surge WireGuard output lost {expected!r}: {surge_output!r}"
            )
    if surge_output.count("public-key = ") != 2:
        raise AssertionError("Surge output did not preserve both WireGuard peers")

    loon_output = convert(base_url, "loon", surge_data)
    for expected in (
        "wireguard, interface-ip=10.77.0.2",
        "interface-ipV6=2001:db8:77::2",
        "keepalive=25",
        "public-key=\"" + public_key_one + "\"",
        "public-key=\"" + public_key_two + "\"",
        "preshared-key=\"" + preshared_key + "\"",
        "reserved=[1,2,3]",
    ):
        if expected not in loon_output:
            raise AssertionError(
                f"Loon WireGuard output lost {expected!r}: {loon_output!r}"
            )

    old_output_text = convert(base_url, "singbox", surge_data, list_mode=True)
    old_output = json.loads(old_output_text)
    wireguard_outbounds = [
        item
        for item in old_output.get("outbounds", [])
        if isinstance(item, dict) and item.get("type") == "wireguard"
    ]
    if len(wireguard_outbounds) != 1 or old_output.get("endpoints"):
        raise AssertionError(
            f"default sing-box schema no longer emits one legacy outbound: {old_output!r}"
        )
    old_wireguard = wireguard_outbounds[0]
    if (
        old_wireguard.get("private_key") != private_key
        or old_wireguard.get("local_address")
        != ["10.77.0.2/32", "2001:db8:77::2/128"]
        or len(old_wireguard.get("peers", [])) != 2
        or old_wireguard["peers"][0].get("pre_shared_key") != preshared_key
        or old_wireguard["peers"][1].get("reserved") != [1, 2, 3]
    ):
        raise AssertionError(
            f"legacy sing-box WireGuard output is incomplete: {old_wireguard!r}"
        )

    old_roundtrip = convert(
        base_url, "surge", data_url(json.dumps(old_output, separators=(",", ":")))
    )
    if private_key not in old_roundtrip or old_roundtrip.count("public-key = ") != 2:
        raise AssertionError(
            "sing-box outbound import swapped keys or lost structured peers"
        )

    loon_roundtrip = json.loads(
        convert(base_url, "singbox", data_url(loon_output), list_mode=True)
    )
    loon_wireguard = next(
        (
            item
            for item in loon_roundtrip.get("outbounds", [])
            if isinstance(item, dict) and item.get("type") == "wireguard"
        ),
        None,
    )
    if loon_wireguard is None or len(loon_wireguard.get("peers", [])) != 2:
        raise AssertionError("Loon inline WireGuard input lost multi-peer structure")

    endpoint_output = json.loads(
        convert(endpoint_base_url, "singbox", surge_data, list_mode=True)
    )
    endpoint_wireguards = [
        item
        for item in endpoint_output.get("endpoints", [])
        if isinstance(item, dict) and item.get("type") == "wireguard"
    ]
    endpoint_outbounds = [
        item
        for item in endpoint_output.get("outbounds", [])
        if isinstance(item, dict) and item.get("type") == "wireguard"
    ]
    if len(endpoint_wireguards) != 1 or endpoint_outbounds:
        raise AssertionError(
            f"opt-in sing-box endpoint schema is malformed: {endpoint_output!r}"
        )
    endpoint = endpoint_wireguards[0]
    if (
        endpoint.get("private_key") != private_key
        or endpoint.get("address") != ["10.77.0.2/32", "2001:db8:77::2/128"]
        or len(endpoint.get("peers", [])) != 2
        or endpoint["peers"][0].get("persistent_keepalive_interval") != 25
        or endpoint["peers"][1].get("address") != "2001:db8::53"
    ):
        raise AssertionError(f"sing-box endpoint fields are incomplete: {endpoint!r}")

    expanded_endpoint_output = json.loads(json.dumps(endpoint_output))
    expanded_endpoint_output["endpoints"][0]["address"].append(
        "10.77.0.3/32"
    )
    expanded_roundtrip = json.loads(
        convert(
            endpoint_base_url,
            "singbox",
            data_url(
                json.dumps(expanded_endpoint_output, separators=(",", ":"))
            ),
            list_mode=True,
        )
    )
    if expanded_roundtrip["endpoints"][0].get("address") != [
        "10.77.0.2/32",
        "2001:db8:77::2/128",
        "10.77.0.3/32",
    ]:
        raise AssertionError("sing-box endpoint import lost a local address")

    endpoint_roundtrip = convert(
        base_url,
        "loon",
        data_url(json.dumps(endpoint_output, separators=(",", ":"))),
    )
    if private_key not in endpoint_roundtrip or endpoint_roundtrip.count(
        "public-key=\""
    ) != 2:
        raise AssertionError("sing-box endpoint import lost keys or peers")

    clash_source = (
        "proxies:\n"
        "  - name: Clash WG\n"
        "    type: wireguard\n"
        f"    private-key: {private_key}\n"
        "    ip: 10.88.0.2\n"
        "    ipv6: 2001:db8:88::2\n"
        "    peers:\n"
        "      - server: clash-one.example.test\n"
        "        port: 51830\n"
        f"        public-key: {public_key_one}\n"
        "        allowed-ips: [0.0.0.0/0, '::/0']\n"
        "        persistent-keepalive: 30\n"
        "      - server: 2001:db8::54\n"
        "        port: 51831\n"
        f"        public-key: {public_key_two}\n"
        "        reserved: [4, 5, 6]\n"
        "        persistent-keepalive: 30\n"
    )
    clash_to_loon = convert(base_url, "loon", data_url(clash_source))
    if (
        clash_to_loon.count("public-key=\"") != 2
        or "reserved=[4,5,6]" not in clash_to_loon
        or "keepalive=30" not in clash_to_loon
    ):
        raise AssertionError(
            f"Clash multi-peer WireGuard input was not preserved: {clash_to_loon!r}"
        )

    clash_simple_source = (
        "proxies:\n"
        "  - name: Clash WG Simple\n"
        "    type: wireguard\n"
        "    server: simple-wg.example.test\n"
        "    port: 51840\n"
        f"    public-key: {public_key_one}\n"
        f"    private-key: {private_key}\n"
        f"    pre-shared-key: {preshared_key}\n"
        "    ip: 10.99.0.2\n"
        "    allowed-ips: [0.0.0.0/0, '::/0']\n"
        "    reserved: [7, 8, 9]\n"
        "    persistent-keepalive: 35\n"
    )
    clash_simple_output = json.loads(
        convert(
            base_url,
            "singbox",
            data_url(clash_simple_source),
            list_mode=True,
        )
    )["outbounds"][0]
    if (
        clash_simple_output.get("private_key") != private_key
        or clash_simple_output["peers"][0].get("pre_shared_key")
        != preshared_key
        or clash_simple_output["peers"][0].get("reserved") != [7, 8, 9]
    ):
        raise AssertionError(
            f"Mihomo simple WireGuard fields were not imported: {clash_simple_output!r}"
        )


def mieru_legacy_parser_baseline(base_url: str) -> None:
    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "surge",
            "ver": "4",
            "url": MIERU_OFFICIAL_SIMPLE_URI + "|" + SUBSCRIPTION.strip(),
            "list": "true",
            "explain": "true",
        },
    )
    if status != 200:
        raise AssertionError(
            f"official mierus URI did not survive Legacy parsing: HTTP {status} {body!r}"
        )
    report = json.loads(body)
    if (
        report.get("nodes", {}).get("total") != 5
        or report.get("nodes", {}).get("generated") != 1
        or report.get("nodes", {}).get("unsupported") != 4
        or report.get("nodes", {}).get("unsupported_protocols") != ["mieru:4"]
    ):
        raise AssertionError(
            f"official multi-binding mierus URI was not expanded exactly: {report!r}"
        )

    invalid_simple = (
        "mierus://user:pass@example.test?profile=default&port=443&"
        "port=444&protocol=TCP"
    )
    for rejected in (invalid_simple, "mieru://AQIDBA=="):
        rejected_status, rejected_body, _ = request(
            base_url,
            "/sub",
            {
                "target": "surge",
                "ver": "4",
                "url": rejected + "|" + SUBSCRIPTION.strip(),
                "list": "true",
                "explain": "true",
            },
        )
        if rejected_status != 200:
            raise AssertionError(
                "a rejected Mieru link prevented the remaining valid node from "
                f"converting: HTTP {rejected_status} {rejected_body!r}"
            )
        rejected_report = json.loads(rejected_body)
        if (
            rejected_report.get("nodes", {}).get("total") != 1
            or rejected_report.get("nodes", {}).get("generated") != 1
            or rejected_report.get("nodes", {}).get("unsupported") != 0
        ):
            raise AssertionError(
                f"invalid Mieru input did not fail closed: {rejected_report!r}"
            )

    for target, headers in (
        ("clash", {}),
        ("clashr", {}),
        ("auto", {"User-Agent": "clash.meta/1.19.29"}),
        ("auto", {"User-Agent": "ClashForAndroid/1.3.3R2"}),
    ):
        standard_status, standard_body, _ = request(
            base_url,
            "/sub",
            {
                "target": target,
                "url": MIERU_STANDARD_PROTOBUF_URI,
                "list": "true",
            },
            headers=headers,
        )
        standard_text = standard_body.decode("utf-8", errors="replace")
        if (
            standard_status != 200
            or standard_text.count("type: mieru") != 4
            or "server: localhost" not in standard_text
            or "port: 6666" not in standard_text
            or "port-range: 9999-9999" not in standard_text
            or "transport: TCP" not in standard_text
            or "transport: UDP" not in standard_text
            or "multiplexing: MULTIPLEXING_HIGH" not in standard_text
        ):
            raise AssertionError(
                "official standard Mieru URI did not stay on the Mihomo-only "
                f"route for target={target}: HTTP {standard_status} {standard_text!r}"
            )

    clash_status, clash_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": MIERU_OFFICIAL_SIMPLE_URI,
            "list": "true",
        },
    )
    clash_text = clash_body.decode("utf-8", errors="replace")
    if (
        clash_status != 200
        or clash_text.count("type: mieru") != 4
        or "port-range: 9998-9999" not in clash_text
        or "handshake-mode: HANDSHAKE_NO_WAIT" not in clash_text
        or "traffic-pattern: CCoQARoECAEQCiIYCAMQASoIMDAwMTAyMDMqCDA0MDUwNjA3"
        not in clash_text
    ):
        raise AssertionError(
            "Mihomo Mieru parsing changed while calibrating Legacy: "
            f"HTTP {clash_status} {clash_text!r}"
        )


def netch_legacy_parser_baseline(base_url: str) -> None:
    def netch_link(node: dict[str, object]) -> str:
        payload = json.dumps(node, separators=(",", ":")).encode("utf-8")
        return "Netch://" + base64.urlsafe_b64encode(payload).decode(
            "ascii"
        ).rstrip("=")

    def data_url(document: dict[str, object]) -> str:
        payload = json.dumps(document, separators=(",", ":")).encode("utf-8")
        return "data:application/json;base64," + base64.b64encode(
            payload
        ).decode("ascii")

    def convert(source: str) -> list[dict[str, object]]:
        status, body, _ = request(
            base_url,
            "/sub",
            {
                "target": "singbox",
                "url": source,
                "config": DISABLE_RULEGEN_CONFIG,
                "list": "true",
            },
        )
        if status != 200:
            raise AssertionError(
                f"Netch Legacy conversion returned HTTP {status}: {body!r}"
            )
        return json.loads(body).get("outbounds", [])

    private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    public_key = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
    preshared_key = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
    current_nodes: list[dict[str, object]] = [
        {
            "Type": "SOCKS",
            "Group": "Netch",
            "Remark": "Netch Modern SOCKS",
            "Hostname": "socks-netch.example.test",
            "Port": 1080,
            "Username": "netch-user",
            "Password": "netch-pass",
            "Version": "5",
        },
        {
            "Type": "VMess",
            "Group": "Netch",
            "Remark": "Netch Modern VMess",
            "Hostname": "vmess-netch.example.test",
            "Port": 443,
            "UserID": "11111111-1111-1111-1111-111111111111",
            "AlterID": 0,
            "EncryptMethod": "auto",
            "TransferProtocol": "ws",
            "PacketEncoding": "xudp",
            "FakeType": "none",
            "Host": "cdn-netch.example.test",
            "Path": "/vmess",
            "TLSSecureType": "tls",
            "ServerName": "vmess-sni.example.test",
        },
        {
            "Type": "VLESS",
            "Group": "Netch",
            "Remark": "Netch Modern VLESS",
            "Hostname": "vless-netch.example.test",
            "Port": 8443,
            "UserID": "22222222-2222-2222-2222-222222222222",
            "EncryptMethod": "none",
            "TransferProtocol": "grpc",
            "PacketEncoding": "xudp",
            "FakeType": "multi",
            "Path": "netch-service",
            "TLSSecureType": "tls",
            "ServerName": "vless-sni.example.test",
        },
        {
            "Type": "Trojan",
            "Group": "Netch",
            "Remark": "Netch Modern Trojan",
            "Hostname": "trojan-netch.example.test",
            "Port": 443,
            "Password": "netch-trojan-pass",
            "Host": "trojan-sni.example.test",
            "TLSSecureType": "tls",
        },
        {
            "Type": "WireGuard",
            "Group": "Netch",
            "Remark": "Netch Modern WireGuard",
            "Hostname": "wireguard-netch.example.test",
            "Port": 51820,
            "LocalAddresses": "10.66.0.2,2001:db8:66::2",
            "PeerPublicKey": public_key,
            "PrivateKey": private_key,
            "PreSharedKey": preshared_key,
            "MTU": 1280,
        },
        {
            "Type": "SSH",
            "Remark": "Netch Unsupported SSH",
            "Hostname": "ssh-netch.example.test",
            "Port": 22,
            "User": "root",
            "Password": "not-a-proxy-protocol",
        },
    ]

    direct = convert(netch_link(current_nodes[0]))
    if len(direct) != 1 or any(
        direct[0].get(key) != value
        for key, value in {
            "type": "socks",
            "tag": "Netch Modern SOCKS",
            "server": "socks-netch.example.test",
            "server_port": 1080,
            "version": "5",
            "username": "netch-user",
            "password": "netch-pass",
        }.items()
    ):
        raise AssertionError(f"current Netch SOCKS link drifted: {direct!r}")

    outbounds = {
        item.get("tag"): item for item in convert(data_url({"Server": current_nodes}))
    }
    if set(outbounds) != {
        "Netch Modern SOCKS",
        "Netch Modern VMess",
        "Netch Modern VLESS",
        "Netch Modern Trojan",
        "Netch Modern WireGuard",
    }:
        raise AssertionError(
            f"current Netch settings.json node set drifted: {outbounds!r}"
        )

    vmess = outbounds["Netch Modern VMess"]
    if (
        vmess.get("packet_encoding") != "xudp"
        or vmess.get("transport")
        != {
            "type": "ws",
            "path": "/vmess",
            "headers": {"Host": "cdn-netch.example.test"},
        }
        or vmess.get("tls", {}).get("server_name")
        != "vmess-sni.example.test"
    ):
        raise AssertionError(f"current Netch VMess fields drifted: {vmess!r}")

    vless = outbounds["Netch Modern VLESS"]
    if (
        vless.get("packet_encoding") != "xudp"
        or vless.get("transport")
        != {"type": "grpc", "service_name": "netch-service"}
        or vless.get("tls", {}).get("server_name")
        != "vless-sni.example.test"
    ):
        raise AssertionError(f"current Netch VLESS fields drifted: {vless!r}")

    trojan = outbounds["Netch Modern Trojan"]
    if (
        "transport" in trojan
        or trojan.get("tls", {}).get("server_name")
        != "trojan-sni.example.test"
    ):
        raise AssertionError(f"current Netch Trojan fields drifted: {trojan!r}")

    wireguard = outbounds["Netch Modern WireGuard"]
    if (
        wireguard.get("local_address") != ["10.66.0.2/32", "2001:db8:66::2/128"]
        or wireguard.get("private_key") != private_key
        or len(wireguard.get("peers", [])) != 1
        or wireguard["peers"][0].get("public_key") != public_key
        or wireguard["peers"][0].get("pre_shared_key") != preshared_key
        or wireguard.get("mtu") != 1280
    ):
        raise AssertionError(
            f"current Netch WireGuard fields drifted: {wireguard!r}"
        )

    legacy_nodes = [
        {
            "Type": "Socks5",
            "Remark": "Netch Legacy Socks5",
            "Hostname": "legacy-socks.example.test",
            "Port": "1081",
            "Username": "legacy-user",
            "Password": "legacy-pass",
        },
        {
            "Type": "VMess",
            "Remark": "Netch Legacy VMess",
            "Hostname": "legacy-vmess.example.test",
            "Port": "443",
            "UserID": "33333333-3333-3333-3333-333333333333",
            "AlterID": "0",
            "EncryptMethod": "auto",
            "TransferProtocol": "ws",
            "Host": "legacy-cdn.example.test",
            "Path": "/legacy",
            "TLSSecure": True,
        },
    ]
    legacy = {
        item.get("tag"): item
        for item in convert(
            data_url({"ModeFileNameType": 0, "Server": legacy_nodes})
        )
    }
    if (
        set(legacy) != {"Netch Legacy Socks5", "Netch Legacy VMess"}
        or legacy["Netch Legacy VMess"].get("tls", {}).get("enabled") is not True
    ):
        raise AssertionError(f"legacy Netch fields no longer convert: {legacy!r}")

    packet_vless = {
        **current_nodes[2],
        "Remark": "Netch VLESS Packet",
        "PacketEncoding": "packet",
    }
    status, packet_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "vless",
            "url": netch_link(packet_vless),
            "config": DISABLE_RULEGEN_CONFIG,
            "list": "true",
        },
    )
    packet_output = packet_body.decode("utf-8", errors="replace")
    if status != 200 or "packet-encoding=packet" not in packet_output:
        raise AssertionError(
            f"Netch VLESS packet encoding was not preserved: {packet_output!r}"
        )
    packet_singbox = convert(
        data_url({"Server": [current_nodes[0], packet_vless]})
    )
    if (
        len(packet_singbox) != 1
        or packet_singbox[0].get("tag") != "Netch Modern SOCKS"
    ):
        raise AssertionError(
            "sing-box did not isolate unsupported packet encoding: "
            f"{packet_singbox!r}"
        )

    invalid_nodes = [
        current_nodes[0],
        {**current_nodes[0], "Remark": "Netch SOCKS4", "Version": "4"},
        {**current_nodes[1], "Remark": "Netch Invalid UUID", "UserID": "bad"},
        {
            **current_nodes[4],
            "Remark": "Netch Incomplete WireGuard",
            "PeerPublicKey": "",
        },
        current_nodes[5],
    ]
    accepted = convert(data_url({"Server": invalid_nodes}))
    if len(accepted) != 1 or accepted[0].get("tag") != "Netch Modern SOCKS":
        raise AssertionError(
            f"unsupported or invalid Netch nodes did not fail closed: {accepted!r}"
        )

    for source in (
        "Netch://not-base64",
        data_url({"Server": "not-an-array"}),
    ):
        status, _, _ = request(
            base_url,
            "/sub",
            {
                "target": "singbox",
                "url": source,
                "config": DISABLE_RULEGEN_CONFIG,
                "list": "true",
            },
        )
        if status != 400:
            raise AssertionError(f"invalid Netch input was accepted: {source!r}")

    clash_status, _, _ = request(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": netch_link(current_nodes[0]),
            "config": DISABLE_RULEGEN_CONFIG,
            "list": "true",
        },
    )
    if clash_status != 400:
        raise AssertionError(
            "Mihomo route changed while calibrating the Legacy Netch parser"
        )


def target_generation_stats_baseline(base_url: str) -> None:
    supported_sources = {
        "mellow": SUBSCRIPTION.strip(),
        "sssub": SUBSCRIPTION.strip(),
        "ss": SUBSCRIPTION.strip(),
        "ssr": SSR_IPV6_URI,
        "v2ray": VMESS_QR_URI,
        "v2rayn": VMESS_QR_URI,
        "v2rayng": VMESS_QR_URI,
        "trojan": TROJAN_WS_URI,
        "vless": VLESS_URI,
        "hysteria2": HYSTERIA2_URI,
        "mixed": SUBSCRIPTION.strip(),
        "quan": SUBSCRIPTION.strip(),
        "quanx": SUBSCRIPTION.strip(),
        "ssd": SUBSCRIPTION.strip(),
        "singbox": SUBSCRIPTION.strip(),
        "surge": SUBSCRIPTION.strip(),
        "surfboard": SUBSCRIPTION.strip(),
        "loon": SUBSCRIPTION.strip(),
    }
    for target, supported in supported_sources.items():
        params = {
            "target": target,
            "url": MIERU_OFFICIAL_SIMPLE_URI + "|" + supported,
            "list": "true",
            "explain": "true",
        }
        if target == "surge":
            params["ver"] = "4"
        status, body, _ = request(base_url, "/sub", params)
        if status != 200:
            raise AssertionError(
                f"target={target} mixed supported/unsupported generation "
                f"failed: HTTP {status} {body!r}"
            )
        report = json.loads(body)
        nodes = report.get("nodes", {})
        if (
            nodes.get("total") != 5
            or nodes.get("generated") != 1
            or nodes.get("unsupported") != 4
            or nodes.get("unsupported_protocols") != ["mieru:4"]
        ):
            raise AssertionError(
                f"target={target} generation statistics drifted: {report!r}"
            )

        unsupported_params = {
            "target": target,
            "url": MIERU_OFFICIAL_SIMPLE_URI,
            "list": "true",
        }
        if target == "surge":
            unsupported_params["ver"] = "4"
        unsupported_status, _, _ = request(
            base_url, "/sub", unsupported_params
        )
        if unsupported_status != 400:
            raise AssertionError(
                f"target={target} accepted an all-unsupported node set: "
                f"HTTP {unsupported_status}"
            )


def v2ray_client_target_baseline(base_url: str) -> None:
    def decode_profiles(body: bytes, *, outer_base64: bool = False) -> list[tuple[str, dict]]:
        raw = base64.b64decode(body) if outer_base64 else body
        result: list[tuple[str, dict]] = []
        for line in raw.decode("utf-8").splitlines():
            prefix = "v2rayn://"
            if not line.startswith(prefix) or "/" not in line[len(prefix) :]:
                raise AssertionError(f"invalid v2rayN internal link: {line!r}")
            scheme, encoded = line[len(prefix) :].split("/", 1)
            padded = encoded + "=" * (-len(encoded) % 4)
            profile = json.loads(base64.urlsafe_b64decode(padded))
            if profile.get("ConfigVersion") != 4:
                raise AssertionError(f"invalid ProfileItem version: {profile!r}")
            result.append((scheme, profile))
        return result

    common_sources = (
        VMESS_QR_URI,
        SUBSCRIPTION.strip(),
        SOCKS_CURRENT_URI,
        VLESS_XHTTP_URI,
        TROJAN_WS_URI,
        HYSTERIA2_MODERN_URI,
        WIREGUARD_URI,
        HTTP_LEGACY_URI,
    )
    desktop_sources = common_sources + (
        TUIC_V2RAYN_URI,
        ANYTLS_V2RAYN_URI,
        NAIVE_HTTPS_URI,
        NAIVE_QUIC_URI,
        HYSTERIA2_REALM_V2RAYN_URI,
    )

    def convert(target: str, sources: tuple[str, ...], **extra: str) -> tuple[int, bytes, dict[str, str]]:
        params = {
            "target": target,
            "url": "|".join(sources),
            "list": "true",
            "config": DISABLE_RULEGEN_CONFIG,
        }
        params.update(extra)
        return request(base_url, "/sub", params)

    desktop_status, desktop_body, _ = convert("v2rayn", desktop_sources)
    if desktop_status != 200:
        raise AssertionError(
            f"v2rayN current protocol matrix failed: HTTP {desktop_status} "
            f"{desktop_body!r}"
        )
    desktop = decode_profiles(desktop_body)
    desktop_schemes = [scheme for scheme, _ in desktop]
    if desktop_schemes != [
        "vmess",
        "shadowsocks",
        "socks",
        "vless",
        "trojan",
        "hysteria2",
        "wireguard",
        "http",
        "tuic",
        "anytls",
        "naive",
        "naive",
        "hysteria2",
    ]:
        raise AssertionError(f"v2rayN internal schemes drifted: {desktop!r}")
    desktop_types = [profile["ConfigType"] for _, profile in desktop]
    if desktop_types != [1, 3, 4, 5, 6, 7, 9, 10, 8, 11, 12, 12, 7]:
        raise AssertionError(f"v2rayN protocol matrix drifted: {desktop!r}")

    desktop_by_type: dict[int, list[dict]] = {}
    for _, profile in desktop:
        desktop_by_type.setdefault(profile["ConfigType"], []).append(profile)
    vmess = desktop_by_type[1][0]
    if (
        vmess.get("Network") != "grpc"
        or vmess.get("ProtoExtraObj", {}).get("AlterId") != "0"
        or vmess.get("ProtoExtraObj", {}).get("VmessSecurity")
        != "chacha20-poly1305"
        or vmess.get("TransportExtraObj", {}).get("GrpcServiceName")
        != "grpc-service"
    ):
        raise AssertionError(f"v2rayN VMess profile drifted: {vmess!r}")
    shadowsocks = desktop_by_type[3][0]
    if (
        shadowsocks.get("CoreType") != 24
        or shadowsocks.get("ProtoExtraObj", {}).get("SsMethod")
        != "aes-128-gcm"
    ):
        raise AssertionError(f"v2rayN Shadowsocks profile drifted: {shadowsocks!r}")
    vless = desktop_by_type[5][0]
    if (
        vless.get("Network") != "xhttp"
        or vless.get("StreamSecurity") != "reality"
        or vless.get("PublicKey")
        != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        or vless.get("ShortId") != "00112233"
        or vless.get("TransportExtraObj", {}).get("XhttpMode")
        != "stream-one"
    ):
        raise AssertionError(f"v2rayN VLESS/XHTTP profile drifted: {vless!r}")
    socks = desktop_by_type[4][0]
    if (
        socks.get("Username") != "current-user"
        or socks.get("Password") != "p@ss+word:tail"
    ):
        raise AssertionError(f"v2rayN SOCKS profile drifted: {socks!r}")
    trojan = desktop_by_type[6][0]
    if (
        trojan.get("Password") != "p@ss+word/token"
        or trojan.get("Network") != "ws"
        or trojan.get("Sni") != "trojan-tls.example.test"
        or trojan.get("TransportExtraObj", {}).get("Host")
        != "ws.example.test"
    ):
        raise AssertionError(f"v2rayN Trojan profile drifted: {trojan!r}")
    hysteria2 = desktop_by_type[7][0]
    if (
        hysteria2.get("ProtoExtraObj", {}).get("SalamanderPass")
        != "obfs+secret"
        or hysteria2.get("ProtoExtraObj", {}).get("Ports")
        != "8443,12000-12002"
        or hysteria2.get("Sni") != "hy2-tls.example.test"
    ):
        raise AssertionError(f"v2rayN Hysteria2 profile drifted: {hysteria2!r}")
    realm = desktop_by_type[7][1]
    realm_extra = realm.get("ProtoExtraObj", {})
    if (
        realm.get("Password") != "realm-password"
        or realm.get("CoreType") != 24
        or realm_extra.get("Hy2RealmUrl")
        != (
            "realm://realm-token@rendezvous.example.test:8443/realm-id"
            "?stun=stun.example.test%3A3478"
        )
        or realm_extra.get("SalamanderPass") != "realm-obfs"
        or realm_extra.get("GeckoMinPacketSize") != "600"
        or realm_extra.get("GeckoMaxPacketSize") != "1300"
    ):
        raise AssertionError(f"v2rayN Hysteria2 Realm/Gecko drifted: {realm!r}")
    wireguard = desktop_by_type[9][0]
    if (
        wireguard.get("Password") != "private+key/value="
        or wireguard.get("Address") != "wg.example.test"
        or wireguard.get("ProtoExtraObj", {}).get("WgPublicKey")
        != "public+key/value="
        or wireguard.get("ProtoExtraObj", {}).get("WgPresharedKey")
        != "preshared+key/value="
        or wireguard.get("ProtoExtraObj", {}).get("WgReserved") != "1,2,3"
        or wireguard.get("ProtoExtraObj", {}).get("WgMtu") != 1420
    ):
        raise AssertionError(f"v2rayN WireGuard profile drifted: {wireguard!r}")
    http = desktop_by_type[10][0]
    if (
        http.get("Username") != "http-user"
        or http.get("Password") != "http-pass"
        or http.get("Address") != "2001:db8::28"
    ):
        raise AssertionError(f"v2rayN HTTP profile drifted: {http!r}")
    tuic = desktop_by_type[8][0]
    if (
        tuic.get("Username") != "99999999-9999-4999-8999-999999999999"
        or tuic.get("Password") != "tuic-password"
        or tuic.get("ProtoExtraObj", {}).get("CongestionControl") != "bbr"
        or tuic.get("Alpn") != "h3"
    ):
        raise AssertionError(f"v2rayN TUIC profile drifted: {tuic!r}")
    anytls = desktop_by_type[11][0]
    if (
        anytls.get("Password") != "anytls-password"
        or anytls.get("StreamSecurity") != "tls"
        or anytls.get("Sni") != "anytls-v2rayn-tls.example.test"
    ):
        raise AssertionError(f"v2rayN AnyTLS profile drifted: {anytls!r}")
    for config_type in (8, 11, 12):
        if any(item.get("CoreType") != 24 for item in desktop_by_type[config_type]):
            raise AssertionError(
                f"v2rayN sing-box-only core selection drifted: "
                f"{desktop_by_type[config_type]!r}"
            )
    naive_profiles = desktop_by_type[12]
    if (
        [item.get("ProtoExtraObj", {}).get("NaiveQuic") for item in naive_profiles]
        != [False, True]
        or naive_profiles[0].get("Username") != "naive-user"
        or naive_profiles[0].get("Password") != "naive+password"
        or naive_profiles[0].get("ProtoExtraObj", {}).get("InsecureConcurrency")
        != 4
    ):
        raise AssertionError(
            f"v2rayN Naive HTTPS/QUIC mapping drifted: {naive_profiles!r}"
        )

    android_status, android_body, _ = convert("v2rayng", common_sources)
    if android_status != 200:
        raise AssertionError(
            f"v2rayNG current protocol matrix failed: HTTP {android_status} "
            f"{android_body!r}"
        )
    android = decode_profiles(android_body)
    android_schemes = [scheme for scheme, _ in android]
    if android_schemes != [
        "vmess",
        "shadowsocks",
        "socks",
        "vless",
        "trojan",
        "hysteria2",
        "wireguard",
        "http",
    ]:
        raise AssertionError(f"v2rayNG internal schemes drifted: {android!r}")
    android_types = [profile["ConfigType"] for _, profile in android]
    if android_types != [1, 3, 4, 5, 6, 7, 9, 10]:
        raise AssertionError(f"v2rayNG protocol matrix drifted: {android!r}")
    android_vmess = android[0][1]
    if (
        android_vmess.get("ProtoExtraObj", {}).get("AlterId") != 0
        or android_vmess.get("Network") != "grpc"
    ):
        raise AssertionError(f"v2rayNG VMess internal mapping drifted: {android_vmess!r}")
    android_wireguard = next(
        profile for _, profile in android if profile.get("ConfigType") == 9
    )
    if (
        android_wireguard.get("PublicKey") != "public+key/value="
        or android_wireguard.get("ProtoExtraObj", {}).get("WgPublicKey")
        != "public+key/value="
    ):
        raise AssertionError(
            f"v2rayNG WireGuard public-key compatibility drifted: "
            f"{android_wireguard!r}"
        )

    for unsupported in (
        TUIC_V2RAYN_URI,
        ANYTLS_V2RAYN_URI,
        NAIVE_HTTPS_URI,
        HYSTERIA2_REALM_V2RAYN_URI,
    ):
        unsupported_status, _, _ = convert("v2rayng", (unsupported,))
        if unsupported_status != 400:
            raise AssertionError(
                "v2rayNG accepted a desktop-only protocol: "
                f"{unsupported!r} HTTP {unsupported_status}"
            )
    invalid_gecko_status, _, _ = convert(
        "v2rayn",
        (
            HYSTERIA2_REALM_V2RAYN_URI.replace(
                "maxPacketSize=1300", "maxPacketSize=4096"
            ),
        ),
    )
    if invalid_gecko_status != 400:
        raise AssertionError(
            "v2rayN accepted Gecko packet sizes that the client would silently "
            f"reset: HTTP {invalid_gecko_status}"
        )
    for target in ("v2rayn", "v2rayng"):
        for unsupported in (
            VMESS_QR_QUIC_URI,
            VMESS_QR_UNSUPPORTED_SECURITY_URI,
            VLESS_UNSUPPORTED_FLOW_URI,
            HTTPS_LEGACY_URI,
        ):
            unsupported_status, _, _ = convert(target, (unsupported,))
            if unsupported_status != 400:
                raise AssertionError(
                    f"target={target} downgraded an unsupported node: "
                    f"{unsupported!r} HTTP {unsupported_status}"
                )

    encoded_status, encoded_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "v2rayn",
            "url": VMESS_QR_URI,
            "config": DISABLE_RULEGEN_CONFIG,
        },
    )
    if encoded_status != 200 or len(decode_profiles(encoded_body, outer_base64=True)) != 1:
        raise AssertionError(
            f"v2rayN encoded subscription contract failed: "
            f"HTTP {encoded_status} {encoded_body!r}"
        )

    for user_agent, expected_target in (
        ("v2rayNG/1.10.29", "v2rayng"),
        ("V2RayN/7.14.3", "v2rayn"),
    ):
        status, body, headers = request(
            base_url,
            "/sub",
            {
                "target": "auto",
                "url": VMESS_QR_URI,
                "list": "true",
                "config": DISABLE_RULEGEN_CONFIG,
            },
            {"User-Agent": user_agent},
        )
        if status != 200 or len(decode_profiles(body)) != 1:
            raise AssertionError(
                f"auto target for {user_agent} did not select {expected_target}: "
                f"HTTP {status} {body!r}"
            )
        assert_vary_header(headers, "User-Agent", f"auto {expected_target}")

    legacy_status, legacy_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "v2ray",
            "url": VMESS_QR_URI,
            "list": "true",
            "config": DISABLE_RULEGEN_CONFIG,
        },
    )
    if (
        legacy_status != 200
        or not legacy_body.decode("utf-8").startswith("vmess://")
        or b"v2rayn://" in legacy_body
    ):
        raise AssertionError(
            f"historical target=v2ray output contract changed: "
            f"HTTP {legacy_status} {legacy_body!r}"
        )


def shadowrocket_target_baseline(base_url: str) -> None:
    sources = (
        SUBSCRIPTION.strip(),
        SSR_IPV6_URI,
        VMESS_QR_URI,
        VLESS_URI,
        TROJAN_WS_URI,
        HYSTERIA2_URI,
        HYSTERIA_SHADOWROCKET_URI,
        ANYTLS_SHADOWROCKET_URI,
        MIERU_OFFICIAL_SIMPLE_URI,
    )
    params = {
        "target": "shadowrocket",
        "url": "|".join(sources),
        "list": "true",
        "config": DISABLE_RULEGEN_CONFIG,
    }
    status, body, _ = request(base_url, "/sub", params)
    if status != 200:
        raise AssertionError(
            f"Shadowrocket standard-link target failed: HTTP {status} {body!r}"
        )
    raw_output = body.decode("utf-8")
    schemes = [line.split("://", 1)[0] for line in raw_output.splitlines()]
    if schemes != [
        "ss",
        "ssr",
        "vmess",
        "vless",
        "trojan",
        "hysteria2",
        "hysteria",
        "anytls",
        "mierus",
    ]:
        raise AssertionError(
            f"Shadowrocket stage-two protocol matrix drifted: {raw_output!r}"
        )

    output_lines = raw_output.splitlines()
    legacy_sources = "|".join(sources[:6])
    legacy_shadowrocket_status, legacy_shadowrocket_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "shadowrocket",
            "url": legacy_sources,
            "list": "true",
            "config": DISABLE_RULEGEN_CONFIG,
        },
    )
    legacy_mixed_status, legacy_mixed_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "mixed",
            "url": legacy_sources,
            "list": "true",
            "config": DISABLE_RULEGEN_CONFIG,
        },
    )
    if (
        legacy_shadowrocket_status != 200
        or legacy_mixed_status != 200
        or legacy_shadowrocket_body != legacy_mixed_body
        or legacy_shadowrocket_body.decode("utf-8")
        != "\n".join(output_lines[:6]) + "\n"
        or hashlib.sha256(legacy_mixed_body).hexdigest()
        != SHADOWROCKET_STAGE_ONE_MIXED_SHA256
    ):
        raise AssertionError(
            "Shadowrocket changed the published six-protocol mixed contract: "
            f"shadowrocket={legacy_shadowrocket_body!r} mixed={legacy_mixed_body!r}"
        )
    hysteria_parts = urllib.parse.urlsplit(output_lines[6])
    hysteria_query = urllib.parse.parse_qs(
        hysteria_parts.query, keep_blank_values=True
    )
    if (
        hysteria_parts.hostname != "2001:db8::14"
        or hysteria_parts.port != 36712
        or hysteria_query
        != {
            "protocol": ["udp"],
            "auth": ["p@ss+word"],
            "peer": ["hy1-tls.example.test"],
            "insecure": ["1"],
            "upmbps": ["100"],
            "downmbps": ["200"],
            "alpn": ["hysteria"],
            "obfs": ["xplus"],
            "obfsParam": ["obfs+secret"],
        }
        or urllib.parse.unquote(hysteria_parts.fragment)
        != "Hysteria V1+Literal"
    ):
        raise AssertionError(
            f"Shadowrocket Hysteria v1 URI drifted: {output_lines[6]!r}"
        )

    anytls_parts = urllib.parse.urlsplit(output_lines[7])
    anytls_query = urllib.parse.parse_qs(
        anytls_parts.query, keep_blank_values=True
    )
    if (
        urllib.parse.unquote(anytls_parts.username or "") != "p@ss+word"
        or anytls_parts.hostname != "2001:db8::16"
        or anytls_parts.port != 443
        or anytls_query
        != {"sni": ["anytls-shadowrocket.example.test"], "insecure": ["1"]}
        or urllib.parse.unquote(anytls_parts.fragment) != "AnyTLS Shadowrocket"
    ):
        raise AssertionError(
            f"Shadowrocket AnyTLS URI drifted: {output_lines[7]!r}"
        )

    mieru_parts = urllib.parse.urlsplit(output_lines[8])
    mieru_query = urllib.parse.parse_qs(
        mieru_parts.query, keep_blank_values=True
    )
    if (
        urllib.parse.unquote(mieru_parts.username or "") != "baozi"
        or urllib.parse.unquote(mieru_parts.password or "")
        != "manlianpenfen"
        or mieru_parts.hostname != "1.2.3.4"
        or mieru_query
        != {
            "profile": ["default"],
            "mtu": ["1400"],
            "multiplexing": ["MULTIPLEXING_HIGH"],
            "handshake-mode": ["HANDSHAKE_NO_WAIT"],
            "traffic-pattern": [
                "CCoQARoECAEQCiIYCAMQASoIMDAwMTAyMDMqCDA0MDUwNjA3"
            ],
            "port": ["6666", "9998-9999", "6489", "4896"],
            "protocol": ["TCP", "TCP", "UDP", "UDP"],
        }
        or mieru_parts.fragment
    ):
        raise AssertionError(
            f"Shadowrocket Mieru URI drifted: {output_lines[8]!r}"
        )

    encoded_status, encoded_body, _ = request(
        base_url,
        "/sub",
        {**params, "list": "false"},
    )
    try:
        decoded_output = base64.b64decode(encoded_body, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as error:
        raise AssertionError(
            f"Shadowrocket encoded subscription is invalid: {encoded_body!r}"
        ) from error
    if encoded_status != 200 or decoded_output != raw_output:
        raise AssertionError(
            "Shadowrocket encoded and raw subscriptions diverged: "
            f"HTTP {encoded_status} {decoded_output!r} != {raw_output!r}"
        )

    default_params = dict(params)
    default_params.pop("list")
    default_status, default_body, _ = request(base_url, "/sub", default_params)
    try:
        default_output = base64.b64decode(default_body, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as error:
        raise AssertionError(
            f"Shadowrocket default subscription is invalid: {default_body!r}"
        ) from error
    if default_status != 200 or default_output != raw_output:
        raise AssertionError(
            "Shadowrocket default list mode changed: "
            f"HTTP {default_status} {default_output!r} != {raw_output!r}"
        )

    mixed_status, mixed_body, _ = request(
        base_url,
        "/sub",
        {**params, "target": "mixed"},
    )
    expected_mixed = "\n".join(output_lines[:6]) + "\n"
    if (
        mixed_status != 200
        or mixed_body.decode("utf-8") != expected_mixed
        or "hysteria://" in mixed_body.decode("utf-8")
        or "anytls://" in mixed_body.decode("utf-8")
    ):
        raise AssertionError(
            "introducing target=shadowrocket changed the historical mixed output: "
            f"HTTP {mixed_status} {mixed_body!r} != {expected_mixed!r}"
        )

    isolated_legacy_targets = {
        "ss": SUBSCRIPTION.strip(),
        "ssr": SSR_IPV6_URI,
        "v2ray": VMESS_QR_URI,
        "trojan": TROJAN_WS_URI,
        "vless": VLESS_URI,
        "hysteria2": HYSTERIA2_URI,
        "mixed": SUBSCRIPTION.strip(),
    }
    shadowrocket_only_sources = "|".join(
        (
            HYSTERIA_SHADOWROCKET_URI,
            ANYTLS_SHADOWROCKET_URI,
            MIERU_OFFICIAL_SIMPLE_URI,
        )
    )
    for target, supported_source in isolated_legacy_targets.items():
        isolation_status, isolation_body, _ = request(
            base_url,
            "/sub",
            {
                "target": target,
                "url": supported_source + "|" + shadowrocket_only_sources,
                "list": "true",
                "explain": "true",
                "config": DISABLE_RULEGEN_CONFIG,
            },
        )
        isolation_report = (
            json.loads(isolation_body) if isolation_status == 200 else {}
        )
        isolation_nodes = isolation_report.get("nodes", {})
        if (
            isolation_status != 200
            or isolation_nodes.get("total") != 7
            or isolation_nodes.get("generated") != 1
            or isolation_nodes.get("unsupported") != 6
            or set(isolation_nodes.get("unsupported_protocols", []))
            != {"hysteria:1", "anytls:1", "mieru:4"}
        ):
            raise AssertionError(
                "Shadowrocket-only protocols leaked into the historical "
                f"target={target} capability matrix: HTTP {isolation_status} "
                f"{isolation_report!r}"
            )

        unsupported_status, unsupported_body, _ = request(
            base_url,
            "/sub",
            {
                "target": target,
                "url": shadowrocket_only_sources,
                "list": "true",
                "config": DISABLE_RULEGEN_CONFIG,
            },
        )
        if unsupported_status != 400:
            raise AssertionError(
                "Shadowrocket-only protocols were accepted by the historical "
                f"target={target}: HTTP {unsupported_status} "
                f"{unsupported_body!r}"
            )

    auto_status, auto_body, auto_headers = request(
        base_url,
        "/sub",
        {
            **params,
            "target": "auto",
            "explain": "true",
        },
        {"User-Agent": "Shadowrocket/2.2.60"},
    )
    if auto_status != 200:
        raise AssertionError(
            f"Shadowrocket auto target failed: HTTP {auto_status} {auto_body!r}"
        )
    assert_vary_header(auto_headers, "User-Agent", "auto Shadowrocket")
    report = json.loads(auto_body)
    if (
        report.get("target") != "shadowrocket"
        or report.get("mode", {}).get("simple_subscription") is not True
        or report.get("mode", {}).get("remote_subscription_backend")
        != "server-side-parse"
        or report.get("nodes", {}).get("total") != 12
        or report.get("nodes", {}).get("generated") != 12
        or report.get("nodes", {}).get("unsupported") != 0
    ):
        raise AssertionError(
            f"Shadowrocket auto route diagnostics drifted: {report!r}"
        )

    unsupported_status, _, _ = request(
        base_url,
        "/sub",
        {
            "target": "shadowrocket",
            "url": MIERU_STANDARD_PROTOBUF_URI,
            "list": "true",
            "config": DISABLE_RULEGEN_CONFIG,
        },
    )
    if unsupported_status != 400:
        raise AssertionError(
            "Shadowrocket routed the protobuf mieru:// link through Legacy: "
            f"HTTP {unsupported_status}"
        )

    unknown_mieru_status, unknown_mieru_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "shadowrocket",
            "url": (
                "mierus://user:pass@example.test?profile=default&port=443"
                "&protocol=TCP&future-option=must-not-disappear"
            ),
            "list": "true",
            "config": DISABLE_RULEGEN_CONFIG,
        },
    )
    if unknown_mieru_status != 400 or b"mierus://" in unknown_mieru_body:
        raise AssertionError(
            "Shadowrocket silently discarded an unknown Mieru parameter: "
            f"HTTP {unknown_mieru_status} {unknown_mieru_body!r}"
        )

    remote_mieru_subscription = base64.b64encode(
        (MIERU_OFFICIAL_SIMPLE_URI + "\n").encode("utf-8")
    ).decode("ascii")
    remote_mieru_source = (
        "data:text/plain;base64,"
        + base64.b64encode(remote_mieru_subscription.encode("ascii")).decode(
            "ascii"
        )
    )
    filtered_mieru_status, filtered_mieru_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "shadowrocket",
            "url": remote_mieru_source,
            "include": "9998-9999",
            "list": "true",
            "config": DISABLE_RULEGEN_CONFIG,
        },
    )
    filtered_mieru_lines = filtered_mieru_body.decode("utf-8").splitlines()
    filtered_mieru_query = (
        urllib.parse.parse_qs(
            urllib.parse.urlsplit(filtered_mieru_lines[0]).query,
            keep_blank_values=True,
        )
        if len(filtered_mieru_lines) == 1
        else {}
    )
    if (
        filtered_mieru_status != 200
        or filtered_mieru_query.get("port") != ["9998-9999"]
        or filtered_mieru_query.get("protocol") != ["TCP"]
    ):
        raise AssertionError(
            "Shadowrocket did not preserve the filtered Mieru binding set: "
            f"HTTP {filtered_mieru_status} {filtered_mieru_body!r}"
        )

    remote_mieru_status, remote_mieru_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "shadowrocket",
            "url": remote_mieru_source,
            "list": "true",
            "config": DISABLE_RULEGEN_CONFIG,
        },
    )
    if remote_mieru_status != 200 or remote_mieru_body.decode("utf-8") != (
        output_lines[8] + "\n"
    ):
        raise AssertionError(
            "Shadowrocket remote subscription and direct Mieru paths diverged: "
            f"HTTP {remote_mieru_status} {remote_mieru_body!r}"
        )

    lossy_status, lossy_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "shadowrocket",
            "url": ANYTLS_MODERN_URI,
            "list": "true",
            "config": DISABLE_RULEGEN_CONFIG,
        },
    )
    if lossy_status != 400 or b"anytls://" in lossy_body:
        raise AssertionError(
            "Shadowrocket emitted non-portable AnyTLS extensions: "
            f"HTTP {lossy_status} {lossy_body!r}"
        )

    multi_alpn_hysteria = HYSTERIA_V1_URI
    multi_alpn_status, multi_alpn_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "shadowrocket",
            "url": multi_alpn_hysteria,
            "list": "true",
            "config": DISABLE_RULEGEN_CONFIG,
        },
    )
    if multi_alpn_status != 400 or b"hysteria://" in multi_alpn_body:
        raise AssertionError(
            "Shadowrocket emitted Hysteria v1 with a non-standard ALPN list: "
            f"HTTP {multi_alpn_status} {multi_alpn_body!r}"
        )

    portable_native_hysteria = HYSTERIA_V1_CLASH_CONFIG.replace(
        "    ports: 443,10000-10002\n", ""
    ).replace("    alpn: [h3, hysteria]", "    alpn: [hysteria]")
    portable_native_hysteria_url = (
        "data:text/plain;base64,"
        + base64.b64encode(portable_native_hysteria.encode("utf-8")).decode(
            "ascii"
        )
    )
    portable_native_status, portable_native_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "shadowrocket",
            "url": portable_native_hysteria_url,
            "list": "true",
            "config": DISABLE_RULEGEN_CONFIG,
        },
    )
    if portable_native_status != 200:
        raise AssertionError(
            "Shadowrocket rejected portable native Hysteria v1 input: "
            f"HTTP {portable_native_status} {portable_native_body!r}"
        )
    portable_native_parts = urllib.parse.urlsplit(
        portable_native_body.decode("utf-8").strip()
    )
    portable_native_query = urllib.parse.parse_qs(
        portable_native_parts.query, keep_blank_values=True
    )
    if portable_native_query != {
        "protocol": ["udp"],
        "auth": ["clash-auth"],
        "peer": ["clash-hy1.example.test"],
        "insecure": ["1"],
        "upmbps": ["30"],
        "downmbps": ["200"],
        "alpn": ["hysteria"],
        "obfs": ["xplus"],
        "obfsParam": ["clash-obfs"],
    }:
        raise AssertionError(
            "Shadowrocket native Hysteria v1 projection drifted: "
            f"{portable_native_body!r}"
        )

    nonportable_native_hysteria_url = (
        "data:text/plain;base64,"
        + base64.b64encode(HYSTERIA_V1_CLASH_CONFIG.encode("utf-8")).decode(
            "ascii"
        )
    )
    native_hysteria_status, native_hysteria_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "shadowrocket",
            "url": nonportable_native_hysteria_url,
            "list": "true",
            "config": DISABLE_RULEGEN_CONFIG,
        },
    )
    if native_hysteria_status != 400 or b"hysteria://" in native_hysteria_body:
        raise AssertionError(
            "Shadowrocket silently discarded native Hysteria v1 ports or ALPN: "
            f"HTTP {native_hysteria_status} {native_hysteria_body!r}"
        )

    mixed_lossy_status, mixed_lossy_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "shadowrocket",
            "url": SUBSCRIPTION.strip() + "|" + ANYTLS_MODERN_URI,
            "list": "true",
            "explain": "true",
            "config": DISABLE_RULEGEN_CONFIG,
        },
    )
    mixed_lossy_report = (
        json.loads(mixed_lossy_body) if mixed_lossy_status == 200 else {}
    )
    mixed_lossy_nodes = mixed_lossy_report.get("nodes", {})
    if (
        mixed_lossy_status != 200
        or mixed_lossy_nodes.get("total") != 2
        or mixed_lossy_nodes.get("generated") != 1
        or mixed_lossy_nodes.get("unsupported") != 1
        or mixed_lossy_nodes.get("unsupported_protocols") != ["anytls:1"]
    ):
        raise AssertionError(
            "Shadowrocket did not fail closed per node for mixed portable and "
            f"non-portable links: HTTP {mixed_lossy_status} {mixed_lossy_report!r}"
        )


def _yaml_named_mapping_block(text: str, section: str, name: str) -> str:
    lines = text.splitlines()
    try:
        section_index = lines.index(f"{section}:")
    except ValueError as exc:
        raise AssertionError(f"missing YAML section {section!r}") from exc
    entry_prefix = f"  {name}:"
    entry_index = None
    for index in range(section_index + 1, len(lines)):
        line = lines[index]
        if line and not line.startswith(" "):
            break
        if line == entry_prefix:
            entry_index = index
            break
    if entry_index is None:
        raise AssertionError(
            f"missing YAML mapping entry {section}.{name}"
        )
    end = entry_index + 1
    while end < len(lines):
        line = lines[end]
        if line and len(line) - len(line.lstrip(" ")) <= 2:
            break
        end += 1
    return "\n".join(lines[entry_index:end])


def stash_target_baseline(base_url: str, fixture_base: str) -> None:
    provider_source = (
        "https://127.0.0.1:1/stash-provider.yaml?token=stash-provider-secret"
    )
    status, body, headers = request(
        base_url,
        "/sub",
        {
            "target": "stash",
            "url": f"provider:Airport,interval:7200,{provider_source}",
            "provider_headers": "X-Stash-Key",
        },
        {"X-Stash-Key": "stash-header-secret"},
    )
    text = body.decode("utf-8", errors="replace")
    if status != 200:
        raise AssertionError(
            f"Stash provider route returned HTTP {status}: {text[-1200:]!r}"
        )
    assert_vary_header(headers, "X-Stash-Key", "Stash provider response")
    required_fragments = (
        "default-nameserver:",
        "- 223.5.5.5",
        "- 1.12.12.12",
        "- doh3://223.5.5.5/dns-query",
        "- https://1.12.12.12/dns-query",
        "skip-cert-verify: false",
        "follow-rule: false",
        "proxy-providers:",
        "Airport:",
        f"url: {provider_source}",
        "path: ./providers/Airport.yaml",
        "interval: 7200",
        "headers:",
        "X-Stash-Key: stash-header-secret",
        "use:",
        "- Airport",
    )
    if any(fragment not in text for fragment in required_fragments):
        raise AssertionError(f"Stash provider schema mismatch: {text!r}")
    provider_block = text.split("Airport:", 1)[1].split("proxy-groups:", 1)[0]
    forbidden_provider_fields = (
        "type:",
        "proxy:",
        "header:",
        "health-check:",
        "override:",
        "exclude-filter:",
    )
    if any(field in provider_block for field in forbidden_provider_fields):
        raise AssertionError(
            f"Stash provider leaked Mihomo-only fields: {provider_block!r}"
        )

    explain_status, explain_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "stash",
            "url": f"provider:Airport,{provider_source}",
            "explain": "true",
        },
    )
    report = json.loads(explain_body)
    if (
        explain_status != 200
        or report.get("target") != "stash"
        or report.get("mode", {}).get("remote_subscription_backend")
        != "stash-proxy-provider"
        or report.get("resources", {}).get("remote_subscription_count") != 1
        or report.get("output", {}).get("provider_count") != 1
        or report.get("mode", {}).get("proxy_provider") is not True
        or len(report.get("providers", [])) != 1
        or report.get("providers", [{}])[0].get("backend") != "stash-client"
        or report.get("nodes", {}).get("generated") != 0
    ):
        raise AssertionError(f"Stash explain contract mismatch: {report!r}")
    if "stash-provider-secret" in explain_body.decode("utf-8", errors="replace"):
        raise AssertionError("Stash explain leaked its provider source token")

    FixtureHandler.stash_rule_source_count = 0
    rules_config = fixture_base + "/external-stash-rules.ini"
    rules_status, rules_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "stash",
            "url": SUBSCRIPTION.strip(),
            "config": rules_config,
        },
    )
    rules_text = rules_body.decode("utf-8", errors="replace")
    if rules_status != 200:
        raise AssertionError(
            f"Stash native rule-provider conversion failed: "
            f"HTTP {rules_status} {rules_text!r}"
        )
    native_rule_fragments = (
        "rule-providers:",
    )
    if any(fragment not in rules_text for fragment in native_rule_fragments):
        raise AssertionError(
            f"Stash native rule-provider schema mismatch: {rules_text!r}"
        )
    expected_rule_lines = {
        "  - RULE-SET,stash-domain,RuleGroup",
        "  - RULE-SET,stash-domain-yaml,RuleGroup",
        "  - RULE-SET,stash-domain-text,RuleGroup",
        "  - RULE-SET,stash-domain-api,RuleGroup",
        "  - RULE-SET,stash-ip,RuleGroup,no-resolve",
        "  - RULE-SET,stash-ip-yaml,RuleGroup",
        "  - RULE-SET,stash-ip-text,RuleGroup",
        "  - RULE-SET,stash-classical,RuleGroup",
        "  - RULE-SET,stash-classical-yaml,RuleGroup",
        "  - GEOSITE,telegram,RuleGroup",
        "  - GEOIP,CN,RuleGroup",
    }
    missing_rule_lines = expected_rule_lines.difference(rules_text.splitlines())
    if missing_rule_lines:
        raise AssertionError(
            f"Stash native rule references drifted: {sorted(missing_rule_lines)!r}"
        )
    provider_contracts = {
        "stash-domain": (
            "    behavior: domain",
            "    format: mrs",
            f"    url: {fixture_base}/stash-domain.mrs?token=stash-domain-token",
            "    path: ./rules/stash-domain.mrs",
            "    interval: 3600",
        ),
        "stash-domain-yaml": (
            "    behavior: domain",
            "    format: yaml",
            f"    url: {fixture_base}/stash-domain-yaml.yaml?token=stash-domain-yaml-token",
            "    path: ./rules/stash-domain-yaml.yaml",
            "    interval: 3601",
        ),
        "stash-domain-text": (
            "    behavior: domain",
            "    format: text",
            f"    url: {fixture_base}/stash-domain-text.list?token=stash-domain-text-token",
            "    path: ./rules/stash-domain-text.txt",
            "    interval: 3602",
        ),
        "stash-domain-api": (
            "    behavior: domain",
            "    format: yaml",
            f"    url: {fixture_base}/stash-domain-api?token=stash-domain-api-token",
            "    path: ./rules/stash-domain-api.yaml",
            "    interval: 3603",
        ),
        "stash-ip": (
            "    behavior: ipcidr",
            "    format: mrs",
            f"    url: {fixture_base}/stash-ip.mrs?token=stash-ip-token",
            "    path: ./rules/stash-ip.mrs",
            "    interval: 7200",
        ),
        "stash-ip-yaml": (
            "    behavior: ipcidr",
            "    format: yaml",
            f"    url: {fixture_base}/stash-ip-yaml.yml?token=stash-ip-yaml-token",
            "    path: ./rules/stash-ip-yaml.yaml",
            "    interval: 7201",
        ),
        "stash-ip-text": (
            "    behavior: ipcidr",
            "    format: text",
            f"    url: {fixture_base}/stash-ip-text.txt?token=stash-ip-text-token",
            "    path: ./rules/stash-ip-text.txt",
            "    interval: 7202",
        ),
        "stash-classical": (
            "    behavior: classical",
            "    format: text",
            f"    url: {fixture_base}/stash-classical.txt?token=stash-classical-token",
            "    path: ./rules/stash-classical.txt",
            "    interval: 1800",
        ),
        "stash-classical-yaml": (
            "    behavior: classical",
            "    format: yaml",
            f"    url: {fixture_base}/stash-classical-yaml.yaml?token=stash-classical-yaml-token",
            "    path: ./rules/stash-classical-yaml.yaml",
            "    interval: 1801",
        ),
    }
    for provider_name, expected_fields in provider_contracts.items():
        block = _yaml_named_mapping_block(
            rules_text, "rule-providers", provider_name
        )
        block_lines = set(block.splitlines())
        if any(field not in block_lines for field in expected_fields):
            raise AssertionError(
                f"Stash rule-provider {provider_name!r} drifted: {block!r}"
            )
    rule_provider_block = rules_text.split("rule-providers:", 1)[1].split(
        "proxy-groups:", 1
    )[0]
    if "type:" in rule_provider_block or rules_text.count("no-resolve") != 1:
        raise AssertionError(
            f"Stash rule-provider leaked Mihomo fields or misplaced no-resolve: "
            f"{rules_text!r}"
        )
    if FixtureHandler.stash_rule_source_count != 0:
        raise AssertionError(
            "Stash rule-provider sources were fetched by the conversion server: "
            f"count={FixtureHandler.stash_rule_source_count}"
        )

    rules_explain_status, rules_explain_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "stash",
            "url": SUBSCRIPTION.strip(),
            "config": rules_config,
            "explain": "true",
        },
    )
    rules_report = json.loads(rules_explain_body)
    resources = rules_report.get("resources", {})
    if (
        rules_explain_status != 200
        or resources.get("ruleset_count") != 11
        or resources.get("rule_provider_count") != 9
        or resources.get("inline_rule_source_count") != 2
        or resources.get("expanded_rule_source_count") != 0
        or resources.get("unsupported_ruleset_count") != 0
    ):
        raise AssertionError(
            f"Stash native rule Explain statistics drifted: {rules_report!r}"
        )
    if (
        FixtureHandler.stash_rule_source_count != 0
        or any(
            token in rules_explain_body.decode("utf-8", errors="replace")
            for token in (
                "stash-domain-token",
                "stash-domain-yaml-token",
                "stash-domain-text-token",
                "stash-domain-api-token",
                "stash-ip-token",
                "stash-ip-yaml-token",
                "stash-ip-text-token",
                "stash-classical-token",
                "stash-classical-yaml-token",
            )
        )
    ):
        raise AssertionError(
            "Stash native rule Explain fetched a source or leaked its token"
        )

    invalid_rule_cases = {
        "classical-mrs": "unsupported format or unsafe value",
        "unknown-format": "could not be fetched or was empty",
        "src-port": "unsupported or invalid rule",
        "non-country-geoip": "unsupported or invalid rule",
        "existing-policy": "unsupported or invalid rule",
        "conflicting-format": "unsupported format or unsafe value",
    }
    for case, expected_error in invalid_rule_cases.items():
        invalid_rule_status, invalid_rule_body, _ = request(
            base_url,
            "/sub",
            {
                "target": "stash",
                "url": SUBSCRIPTION.strip(),
                "config": (
                    fixture_base
                    + "/external-stash-rules-invalid.ini?case="
                    + urllib.parse.quote(case, safe="")
                ),
            },
        )
        invalid_rule_text = invalid_rule_body.decode("utf-8", errors="replace")
        if invalid_rule_status != 400 or expected_error not in invalid_rule_text:
            raise AssertionError(
                f"Stash accepted or misclassified invalid ruleset {case}: "
                f"HTTP {invalid_rule_status} {invalid_rule_text!r}"
            )
        if case == "existing-policy" and "rule-providers:" in invalid_rule_text:
            raise AssertionError(
                "Stash returned partial YAML after a later invalid ruleset"
            )
    if FixtureHandler.stash_rule_source_count != 0:
        raise AssertionError(
            "Stash fetched a native rule-provider while rejecting invalid input"
        )

    legacy_text_status, legacy_text_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "stash",
            "url": SUBSCRIPTION.strip(),
            "config": fixture_base + "/external-stash-rules-legacy-text.ini",
        },
    )
    legacy_text = legacy_text_body.decode("utf-8", errors="replace")
    if (
        legacy_text_status != 200
        or "  - DOMAIN,legacy-text.example,RuleGroup" not in legacy_text.splitlines()
        or "stash-legacy-domain:" in legacy_text
        or FixtureHandler.stash_legacy_text_fetch_count != 1
    ):
        raise AssertionError(
            "Stash did not preserve server-side handling for ambiguous .txt "
            f"rulesets: HTTP {legacy_text_status} {legacy_text!r} "
            f"fetches={FixtureHandler.stash_legacy_text_fetch_count}"
        )
    clash_control_status, clash_control_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "clash",
            "url": SUBSCRIPTION.strip(),
            "config": fixture_base + "/external-stash-rules-legacy-text.ini",
        },
    )
    clash_control_text = clash_control_body.decode("utf-8", errors="replace")
    if clash_control_status != 200:
        raise AssertionError(
            "Stash rule-provider work changed the Clash ruleset path: "
            f"HTTP {clash_control_status} {clash_control_text!r}"
        )
    clash_control_provider = _yaml_named_mapping_block(
        clash_control_text, "rule-providers", "stash-legacy-domain"
    )
    clash_control_provider_lines = set(clash_control_provider.splitlines())
    clash_control_expected_lines = {
        "    type: http",
        "    behavior: domain",
        f"    url: {fixture_base}/stash-legacy-domain.txt",
        "    format: text",
        "    interval: 3600",
    }
    if (
        not clash_control_expected_lines.issubset(clash_control_provider_lines)
        or "  - RULE-SET,stash-legacy-domain,RuleGroup"
        not in clash_control_text.splitlines()
        or "DOMAIN,legacy-text.example,RuleGroup" in clash_control_text
        or "stash-format" in clash_control_text
        or FixtureHandler.stash_legacy_text_fetch_count != 1
    ):
        raise AssertionError(
            "Stash rule-provider work changed the Clash ruleset path: "
            f"HTTP {clash_control_status} {clash_control_text!r}"
        )

    merge_status, merge_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "stash",
            "url": SUBSCRIPTION.strip(),
            "config": fixture_base + "/external-stash-rules-merge.ini?case=merge",
        },
    )
    merge_text = merge_body.decode("utf-8", errors="replace")
    if merge_status != 200:
        raise AssertionError(
            f"Stash failed to preserve existing rules/providers: {merge_text!r}"
        )
    merge_fragments = (
        "stash-domain:",
        "path: ./rules/existing-domain.txt",
        "stash-domain_2:",
        "path: ./rules/stash-domain_2.mrs",
        "RULE-SET,stash-domain,RuleGroup",
        "DOMAIN,base.example,RuleGroup",
        "RULE-SET,stash-domain_2,RuleGroup",
        "MATCH,Proxy",
    )
    if any(fragment not in merge_text for fragment in merge_fragments):
        raise AssertionError(
            f"Stash existing rule/provider merge drifted: {merge_text!r}"
        )
    if not (
        merge_text.index("DOMAIN,base.example,RuleGroup")
        < merge_text.index("RULE-SET,stash-domain_2,RuleGroup")
        < merge_text.index("MATCH,Proxy")
    ):
        raise AssertionError(
            "Stash appended generated rules after an existing final MATCH"
        )
    merge_explain_status, merge_explain_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "stash",
            "url": SUBSCRIPTION.strip(),
            "config": fixture_base + "/external-stash-rules-merge.ini?case=merge",
            "explain": "true",
        },
    )
    merge_report = json.loads(merge_explain_body)
    if (
        merge_explain_status != 200
        or merge_report.get("resources", {}).get("rule_provider_count") != 2
    ):
        raise AssertionError(
            f"Stash merged rule-provider Explain count drifted: {merge_report!r}"
        )

    collision_status, collision_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "stash",
            "url": SUBSCRIPTION.strip(),
            "config": (
                fixture_base
                + "/external-stash-rules-merge.ini?case=path-collision"
            ),
        },
    )
    collision_text = collision_body.decode("utf-8", errors="replace")
    if collision_status != 400 or "paths conflict" not in collision_text:
        raise AssertionError(
            "Stash did not fail closed on a rule-provider path collision: "
            f"HTTP {collision_status} {collision_text!r}"
        )

    direct_status, direct_body, _ = request(
        base_url,
        "/sub",
        {"target": "stash", "url": SUBSCRIPTION.strip(), "list": "true"},
    )
    direct_text = direct_body.decode("utf-8", errors="replace")
    if (
        direct_status != 200
        or "type: ss" not in direct_text
        or "server: example.com" not in direct_text
        or "cipher: aes-128-gcm" not in direct_text
        or "password: password" not in direct_text
    ):
        raise AssertionError(f"Stash direct-node projection mismatch: {direct_text!r}")
    direct_group = direct_text.split("proxy-groups:", 1)[1].split("rules:", 1)[0]
    if "- Smoke" not in direct_group:
        raise AssertionError(
            f"Stash default Proxy group did not reference the direct node: {direct_group!r}"
        )

    stash_mieru_uri = (
        "mierus://stash-user:stash-password@mieru-stash.example.test?"
        "profile=default&port=9998-9999&protocol=TCP"
    )
    stash_xhttp_uri = (
        "vless://99999999-9999-4999-8999-999999999998@"
        "xhttp-stash.example.test:443?encryption=none&security=reality"
        "&type=xhttp&host=xhttp-host.example.test&path=%2Fsplit"
        "&mode=stream-one&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "&sid=00112233&fp=chrome&sni=xhttp-sni.example.test#StashXHTTP"
    )
    protocol_status, protocol_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "stash",
            "url": "|".join(
                (
                    VMESS_STANDARD_URI.replace("&fp=chrome", ""),
                    VLESS_DEFAULT_TCP_URI,
                    stash_xhttp_uri,
                    ANYTLS_V2RAYN_URI,
                    HYSTERIA2_URI,
                    stash_mieru_uri,
                    WIREGUARD_URI,
                )
            ),
            "list": "true",
        },
    )
    protocol_text = protocol_body.decode("utf-8", errors="replace")
    protocol_fragments = (
        "type: vless",
        "type: vmess",
        "servername: tls.example.test",
        "sni: vless-tls.example.test",
        "network: xhttp",
        "mode: stream-one",
        "type: anytls",
        "type: hysteria2",
        "type: mieru",
        "port-range: 9998-9999",
        "transport: tcp",
        "type: wireguard",
        "reserved:",
        "- 1",
        "- 2",
        "- 3",
    )
    if protocol_status != 200 or any(
        fragment not in protocol_text for fragment in protocol_fragments
    ):
        raise AssertionError(
            "Stash current-protocol projection drifted: "
            f"HTTP {protocol_status} {protocol_text!r}"
        )

    for unsupported_option in ("tls13=true", "tfo=true"):
        unsupported_flag_status, _, _ = request(
            base_url,
            "/sub",
            {
                "target": "stash",
                "url": SUBSCRIPTION.strip(),
                "list": "true",
                **dict(item.split("=", 1) for item in (unsupported_option,)),
            },
        )
        if unsupported_flag_status != 400:
            raise AssertionError(
                "Stash silently ignored an unsupported node option override: "
                f"{unsupported_option} -> HTTP {unsupported_flag_status}"
            )

    invalid_stash_bases = {
        "dangling MATCH policy": (
            "mode: rule\nproxies: []\nproxy-providers: {}\n"
            "proxy-groups:\n  - name: Proxy\n    type: select\n"
            "    proxies: [DIRECT]\nrules: ['MATCH,MissingPolicy']\n",
            "final Stash configuration contains a dangling or cyclic "
            "policy reference",
        ),
        "nested dangling RULE-SET": (
            "mode: rule\nproxies: []\nproxy-providers: {}\n"
            "proxy-groups:\n  - name: Proxy\n    type: select\n"
            "    proxies: [DIRECT]\n"
            "rules: ['AND,((RULE-SET,missing),(NETWORK,TCP)),Proxy']\n",
            "final Stash configuration contains a dangling or cyclic "
            "policy reference",
        ),
        "reserved PASS proxy name": (
            "mode: rule\nproxies:\n  - name: PASS\n    type: direct\n"
            "proxy-providers: {}\nproxy-groups:\n"
            "  - name: Proxy\n    type: select\n    proxies: [DIRECT]\n"
            "rules: ['MATCH,Proxy']\n",
            "selected Stash base has an invalid 'proxies.name' entry",
        ),
        "proxy and group namespace collision": (
            "mode: rule\nproxies:\n  - name: Proxy\n    type: direct\n"
            "proxy-providers: {}\nproxy-groups:\n"
            "  - name: Proxy\n    type: select\n    proxies: [DIRECT]\n"
            "rules: ['MATCH,Proxy']\n",
            "selected Stash base has an invalid 'proxy-groups.name' entry",
        ),
    }
    FixtureHandler.stash_invalid_bases = {
        description: invalid_base
        for description, (invalid_base, _) in invalid_stash_bases.items()
    }
    for description, (_, expected_error) in invalid_stash_bases.items():
        invalid_status, invalid_body, _ = request(
            base_url,
            "/sub",
            {
                "target": "stash",
                "url": SUBSCRIPTION.strip(),
                "config": (
                    fixture_base
                    + "/external-stash-invalid.ini?case="
                    + urllib.parse.quote(description, safe="")
                ),
            },
        )
        invalid_text = invalid_body.decode("utf-8", errors="replace")
        if invalid_status != 400 or expected_error not in invalid_text:
            raise AssertionError(
                f"Stash accepted or misclassified a custom base with {description}: "
                f"HTTP {invalid_status} {invalid_text!r}"
            )

    unsupported_status, unsupported_body, _ = request(
        base_url,
        "/sub",
        {"target": "stash", "url": NAIVE_HTTPS_URI, "list": "true"},
    )
    if (
        unsupported_status != 400
        or b"none of the parsed proxy nodes" not in unsupported_body
    ):
        raise AssertionError(
            "Stash unsupported-only request did not fail closed: "
            f"HTTP {unsupported_status}: {unsupported_body!r}"
        )

    interval_status, _, _ = request(
        base_url,
        "/sub",
        {"target": "stash", "url": f"interval:0,{provider_source}"},
    )
    direct_proxy_status, _, _ = request(
        base_url,
        "/sub",
        {"target": "stash", "url": f"proxy_direct:true,{provider_source}"},
    )
    if interval_status != 400 or direct_proxy_status != 400:
        raise AssertionError(
            "Stash accepted an invalid interval or Mihomo-only proxy_direct"
        )


def stash_rule_limit_baseline(base_url: str, fixture_base: str) -> None:
    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "stash",
            "url": SUBSCRIPTION.strip(),
            "config": fixture_base + "/external-stash-rules.ini",
        },
    )
    text = body.decode("utf-8", errors="replace")
    if status != 400 or "max_allowed_rules" not in text:
        raise AssertionError(
            "Stash did not enforce max_allowed_rules on the final rule set: "
            f"HTTP {status} {text!r}"
        )


def singbox_import_fidelity_baseline(base_url: str, fixture_base: str) -> None:
    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "singbox",
            "url": fixture_base + "/singbox-transport-fidelity.json",
            "list": "true",
        },
    )
    if status != 200:
        raise AssertionError(
            f"sing-box transport import failed: HTTP {status} {body!r}"
        )
    payload = json.loads(body)
    outbounds = {
        item.get("tag"): item
        for item in payload.get("outbounds", [])
        if isinstance(item, dict)
    }
    if "Unsupported Transport" in outbounds:
        raise AssertionError(f"unknown sing-box transport was downgraded: {outbounds!r}")
    vmess = outbounds.get("Singbox WS Edge", {})
    if (
        vmess.get("transport", {}).get("headers", {}).get("Edge") != "edge-1"
        or vmess.get("tls", {}).get("utls", {}).get("fingerprint") != "firefox"
    ):
        raise AssertionError(f"sing-box VMess Edge/uTLS was lost: {vmess!r}")
    vless = outbounds.get("Singbox HTTPUpgrade", {})
    if vless.get("transport") != {
        "type": "httpupgrade",
        "host": "upgrade-import.example.test",
        "path": "/upgrade",
    }:
        raise AssertionError(f"sing-box HTTPUpgrade was lost: {vless!r}")
    trojan = outbounds.get("Singbox Trojan gRPC", {})
    if (
        trojan.get("transport")
        != {"type": "grpc", "service_name": "trojan/service"}
        or trojan.get("tls", {}).get("utls", {}).get("fingerprint") != "safari"
    ):
        raise AssertionError(f"sing-box Trojan gRPC/uTLS was lost: {trojan!r}")


def loon_current_node_output_baseline(base_url: str) -> None:
    def vmess_qr(name: str, network: str, host: str = "", path: str = "/") -> str:
        payload = {
            "v": "2",
            "ps": name,
            "add": "vmess-loon.example.test",
            "port": "443",
            "id": "12121212-1212-4212-8212-121212121212",
            "aid": "0",
            "scy": "auto",
            "net": network,
            "type": "none",
            "path": path,
            "host": host,
            "tls": "tls",
            "sni": "vmess-sni.example.test",
        }
        return "vmess://" + _urlsafe_b64(
            json.dumps(payload, separators=(",", ":"))
        )

    supported = (
        vmess_qr("Loon VMess TCP", "tcp"),
        vmess_qr("Loon VMess WS", "ws", "vmess-ws-host.example.test", "/ws"),
        vmess_qr("Loon VMess HTTP", "http", "vmess-host.example.test", "/http"),
        "vless://15151515-1515-4515-8515-151515151515@vless-tcp-loon.example.test:443"
        "?encryption=none&security=tls&type=tcp"
        "&sni=vless-tcp-sni.example.test#Loon%20VLESS%20TCP",
        "vless://16161616-1616-4616-8616-161616161616@vless-ws-loon.example.test:443"
        "?encryption=none&security=tls&type=ws&host=vless-ws-host.example.test"
        "&path=%2Fws&sni=vless-ws-sni.example.test#Loon%20VLESS%20WS",
        "vless://13131313-1313-4313-8313-131313131313@vless-loon.example.test:443"
        "?encryption=none&security=tls&type=http&host=vless-host.example.test"
        "&path=%2Fhttp&sni=vless-sni.example.test#Loon%20VLESS%20HTTP",
        "vless://14141414-1414-4414-8414-141414141414@reality-loon.example.test:443"
        "?encryption=none&security=reality&type=tcp&flow=xtls-rprx-vision"
        "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=00112233"
        "&sni=reality-sni.example.test&fp=chrome#Loon%20VLESS%20Reality",
        "trojan://trojan-password@trojan-loon.example.test:443?security=tls"
        "&type=ws&host=trojan-host.example.test&path=%2Fws"
        "&sni=trojan-sni.example.test&alpn=http%2F1.1#Loon%20Trojan%20WS",
        "trojan://trojan-http@trojan-http.example.test:443?security=tls"
        "&type=http&host=trojan-http-host.example.test&path=%2Fhttp"
        "&sni=trojan-http-sni.example.test#Loon%20Trojan%20HTTP",
        "trojan://pass%2Cword@trojan-comma.example.test:443?security=tls"
        "&sni=trojan-comma-sni.example.test#Loon%2CComma",
        "anytls://anytls-password@anytls-loon.example.test:8443"
        "?sni=anytls-sni.example.test&fp=chrome#Loon%20AnyTLS",
        "hysteria2://hy2-password@hy2-loon.example.test:8443/"
        "?down=200&obfs=salamander&obfs-password=hy2-obfs"
        "&sni=hy2-sni.example.test#Loon%20Hysteria2",
    )
    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "loon",
            "url": "|".join(supported),
            "list": "true",
            "udp": "true",
            "tfo": "false",
        },
    )
    output = body.decode("utf-8", errors="replace")
    if status != 200:
        raise AssertionError(f"current Loon node conversion failed: HTTP {status} {output!r}")
    expected_fragments = (
        "transport=http,alterId=0,path=/http,host=vmess-host.example.test,over-tls=true,sni=vmess-sni.example.test",
        "transport=http,path=/http,host=vless-host.example.test,over-tls=true,sni=vless-sni.example.test",
        "transport=tcp,flow=xtls-rprx-vision,public-key=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",short-id=00112233,over-tls=true,sni=reality-sni.example.test,tls-profile=chrome",
        "transport=ws,path=/ws,host=trojan-host.example.test,alpn=http/1.1,sni=trojan-sni.example.test",
        "transport=http,path=/http,host=trojan-http-host.example.test,sni=trojan-http-sni.example.test",
        "AnyTLS,anytls-loon.example.test,8443,\"anytls-password\",sni=anytls-sni.example.test,tls-profile=chrome,skip-cert-verify=false,block-quic=false",
        "Hysteria2,hy2-loon.example.test,8443,\"hy2-password\",sni=hy2-sni.example.test,download-bandwidth=200,salamander-password=\"hy2-obfs\"",
    )
    for expected in expected_fragments:
        if expected not in output:
            raise AssertionError(f"Loon output lost {expected!r}: {output!r}")
    if "download-bandwidth=100" in output:
        raise AssertionError(f"Loon Hysteria2 restored the fabricated bandwidth: {output!r}")

    loon_profile = "[Proxy]\n" + output
    loon_data_url = "data:text/plain;base64," + base64.b64encode(
        loon_profile.encode("utf-8")
    ).decode("ascii")
    roundtrip_status, roundtrip_body, _ = request(
        base_url,
        "/sub",
        {"target": "singbox", "url": loon_data_url, "list": "true"},
    )
    if roundtrip_status != 200:
        raise AssertionError(
            "generated Loon profile could not be imported: "
            f"HTTP {roundtrip_status} {roundtrip_body!r}"
        )
    roundtrip_payload = json.loads(roundtrip_body)
    outbounds = {
        item.get("tag"): item
        for item in roundtrip_payload.get("outbounds", [])
        if isinstance(item, dict)
    }
    vmess = outbounds.get("Loon VMess HTTP", {})
    if (
        vmess.get("transport")
        != {
            "type": "http",
            "host": ["vmess-host.example.test"],
            "path": "/http",
        }
        or vmess.get("tls", {}).get("server_name") != "vmess-sni.example.test"
        or vmess.get("alter_id") != 0
    ):
        raise AssertionError(f"Loon VMess roundtrip drifted: {vmess!r}")
    vmess_tcp = outbounds.get("Loon VMess TCP", {})
    if (
        vmess_tcp.get("transport") is not None
        or vmess_tcp.get("tls", {}).get("server_name")
        != "vmess-sni.example.test"
    ):
        raise AssertionError(f"Loon VMess TCP roundtrip drifted: {vmess_tcp!r}")
    vmess_ws = outbounds.get("Loon VMess WS", {})
    if vmess_ws.get("transport") != {
        "type": "ws",
        "path": "/ws",
        "headers": {"Host": "vmess-ws-host.example.test"},
    }:
        raise AssertionError(f"Loon VMess WS roundtrip drifted: {vmess_ws!r}")
    vless_tcp = outbounds.get("Loon VLESS TCP", {})
    if (
        vless_tcp.get("transport") is not None
        or vless_tcp.get("tls", {}).get("server_name")
        != "vless-tcp-sni.example.test"
    ):
        raise AssertionError(f"Loon VLESS TCP roundtrip drifted: {vless_tcp!r}")
    vless_ws = outbounds.get("Loon VLESS WS", {})
    if vless_ws.get("transport") != {
        "type": "ws",
        "path": "/ws",
        "headers": {"Host": "vless-ws-host.example.test"},
    }:
        raise AssertionError(f"Loon VLESS WS roundtrip drifted: {vless_ws!r}")
    vless_http = outbounds.get("Loon VLESS HTTP", {})
    if vless_http.get("transport") != {
        "type": "http",
        "host": ["vless-host.example.test"],
        "path": "/http",
    }:
        raise AssertionError(f"Loon VLESS HTTP roundtrip drifted: {vless_http!r}")
    vless = outbounds.get("Loon VLESS Reality", {})
    if (
        vless.get("flow") != "xtls-rprx-vision"
        or vless.get("tls", {}).get("reality", {}).get("public_key")
        != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        or vless.get("tls", {}).get("reality", {}).get("short_id") != "00112233"
    ):
        raise AssertionError(f"Loon VLESS Reality roundtrip drifted: {vless!r}")
    trojan = outbounds.get("Loon Trojan WS", {})
    if (
        trojan.get("transport", {}).get("type") != "ws"
        or trojan.get("transport", {}).get("headers", {}).get("Host")
        != "trojan-host.example.test"
        or trojan.get("transport", {}).get("path") != "/ws"
    ):
        raise AssertionError(f"Loon Trojan WS roundtrip drifted: {trojan!r}")
    trojan_http = outbounds.get("Loon Trojan HTTP", {})
    if trojan_http.get("transport") != {
        "type": "http",
        "host": ["trojan-http-host.example.test"],
        "path": "/http",
    }:
        raise AssertionError(
            f"Loon Trojan HTTP roundtrip drifted: {trojan_http!r}"
        )
    comma_trojan = outbounds.get("Loon,Comma", {})
    if comma_trojan.get("password") != "pass,word":
        raise AssertionError(
            f"Loon quoted comma credential/remark drifted: {comma_trojan!r}"
        )
    anytls = outbounds.get("Loon AnyTLS", {})
    if (
        anytls.get("type") != "anytls"
        or anytls.get("tls", {}).get("server_name") != "anytls-sni.example.test"
    ):
        raise AssertionError(f"Loon AnyTLS roundtrip drifted: {anytls!r}")
    hysteria2 = outbounds.get("Loon Hysteria2", {})
    if (
        hysteria2.get("down_mbps") != 200
        or hysteria2.get("obfs")
        != {"type": "salamander", "password": "hy2-obfs"}
    ):
        raise AssertionError(f"Loon Hysteria2 roundtrip drifted: {hysteria2!r}")

    invalid_profiles = (
        '[Proxy]\nBad = Trojan,bad.example.test,443,"password",sni=a.example,tls-name=b.example',
        '[Proxy]\nBad = AnyTLS,bad.example.test,443,"password",block-quic=true',
        '[Proxy]\nBad = Hysteria2,bad.example.test,443,"password",salamander-password=unquoted',
        '[Proxy]\nBad = VMess,bad.example.test,443,auto,"12121212-1212-4212-8212-121212121212,transport=tcp,alterId=0,over-tls=false',
        '[Proxy]\nBad = VMess,bad.example.test,443,auto,"12121212-1212-4212-8212-121212121212",transport=tcp,alterId=0,path=/bad,over-tls=false',
        '[Proxy]\nBad = VLESS,bad.example.test,443,"13131313-1313-4313-8313-131313131313",transport=tcp,over-tls=false,tls-profile=chrome',
        '[Proxy]\nBad = Trojan,bad.example.test,443,"password",transport=tcp,path=/bad',
        '[Proxy]\nBad = Hysteria2,bad.example.test,443,"password",tls-cert-sha256=001122,skip-cert-verify=true',
    )
    for invalid_profile in invalid_profiles:
        invalid_url = "data:text/plain;base64," + base64.b64encode(
            invalid_profile.encode("utf-8")
        ).decode("ascii")
        invalid_status, _, _ = request(
            base_url,
            "/sub",
            {"target": "singbox", "url": invalid_url, "list": "true"},
        )
        if invalid_status != 400:
            raise AssertionError(
                "invalid Loon positional profile did not fail closed: "
                f"HTTP {invalid_status} {invalid_profile!r}"
            )

    unsupported = (
        VMESS_QR_URI,
        VLESS_HTTPUPGRADE_URI,
        TROJAN_WS_URI,
        ANYTLS_MODERN_URI,
        "hysteria2://password@hy2.example.test:443/?up=10&down=200#HY2Up",
        "trojan://password@trojan.example.test:443?type=ws&host=bad%2Chost#BadScalar",
    )
    for source in unsupported:
        rejected_status, _, _ = request(
            base_url,
            "/sub",
            {"target": "loon", "url": source, "list": "true"},
        )
        if rejected_status != 400:
            raise AssertionError(
                f"Loon accepted a lossy or unsafe node: HTTP {rejected_status} {source!r}"
            )


def quanx_current_node_output_baseline(base_url: str, fixture_base: str) -> None:
    vmess_reality = (
        "vmess://15151515-1515-4515-8515-151515151515@vmess-reality.example.test:443"
        "?encryption=none&security=reality&type=tcp&sni=reality.example.test"
        "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=00112233"
        "&fp=chrome#QuanX%20VMess%20Reality"
    )
    vless_http = (
        "vless://17171717-1717-4717-8717-171717171717@vless-http.example.test:80"
        "?encryption=none&security=none&type=tcp&headerType=http"
        "&host=http.example.test&path=%2Fheader#QuanX%20VLESS%20HTTP"
    )
    trojan_wss = (
        "trojan://trojan-password@trojan-wss.example.test:443?security=tls"
        "&type=ws&host=trojan-host.example.test&sni=trojan-host.example.test"
        "&path=%2Fws&alpn=h2%2Chttp%2F1.1&insecure=1#QuanX%20Trojan%20WSS"
    )
    sources = (
        VMESS_STANDARD_URI,
        vmess_reality,
        VLESS_DEFAULT_TCP_URI,
        vless_http,
        VLESS_REALITY_WITH_NUMERIC_SID_URI,
        trojan_wss,
        ANYTLS_MODERN_URI,
    )
    status, body, _ = request(
        base_url,
        "/sub",
        {
            "target": "quanx",
            "url": "|".join(sources),
            "list": "true",
            "udp": "true",
            "tfo": "true",
        },
    )
    output = body.decode("utf-8", errors="replace")
    if status != 200:
        raise AssertionError(
            f"current Quantumult X node conversion failed: HTTP {status} {output!r}"
        )
    expected = (
        "vmess = vmess.example.test:443, method=none, password=22222222-2222-2222-2222-222222222222, obfs=over-tls, obfs-host=tls.example.test, tls-alpn=02683208687474702f312e31",
        "vmess = vmess-reality.example.test:443, method=none, password=15151515-1515-4515-8515-151515151515, obfs=over-tls, obfs-host=reality.example.test, reality-base64-pubkey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, reality-hex-shortid=00112233, fast-open=false",
        "vless = [2001:db8::1]:443, method=none, password=44444444-4444-4444-4444-444444444444, obfs=over-tls, obfs-host=vless-tls.example.test, tls-alpn=02683208687474702f312e31",
        "vless = vless-http.example.test:80, method=none, password=17171717-1717-4717-8717-171717171717, obfs=http, obfs-host=http.example.test, obfs-uri=/header",
        "reality-hex-shortid=00112233, vless-flow=xtls-rprx-vision, fast-open=false",
        "trojan = trojan-wss.example.test:443, password=trojan-password, obfs=wss, obfs-host=trojan-host.example.test, obfs-uri=/ws, tls-alpn=02683208687474702f312e31",
        "anytls = [2001:db8::12]:443, password=p@ss+word, over-tls=true, tls-host=anytls-tls.example.test, tls-alpn=02683208687474702f312e31",
    )
    for fragment in expected:
        if fragment not in output:
            raise AssertionError(
                f"Quantumult X output lost {fragment!r}: {output!r}"
            )
    if "tls13=" in output or "udp-over-tcp=" in output:
        raise AssertionError(f"Quantumult X emitted invalid legacy fields: {output!r}")
    wss_line = next(
        line for line in output.splitlines() if "tag=QuanX Trojan WSS" in line
    )
    if "over-tls=" in wss_line or "tls-host=" in wss_line:
        raise AssertionError(f"Trojan WSS used TCP TLS syntax: {wss_line!r}")

    FixtureHandler.quanx_roundtrip_config = "[server_local]\n" + output
    roundtrip_status, roundtrip_body, _ = request(
        base_url,
        "/sub",
        {
            "target": "singbox",
            "url": fixture_base + "/quanx-roundtrip.conf",
            "list": "true",
        },
    )
    roundtrip_text = roundtrip_body.decode("utf-8", errors="replace")
    if roundtrip_status != 200:
        raise AssertionError(
            "Quantumult X generator->parser roundtrip failed: "
            f"HTTP {roundtrip_status} {roundtrip_text!r}"
        )
    roundtrip = json.loads(roundtrip_text)
    outbounds = {
        item.get("tag"): item
        for item in roundtrip.get("outbounds", [])
        if isinstance(item, dict) and isinstance(item.get("tag"), str)
    }
    expected_tags = {
        "VMessStandard",
        "QuanX VMess Reality",
        "VLESSDefaultTCP",
        "QuanX VLESS HTTP",
        "RealityNumericSid",
        "QuanX Trojan WSS",
        "AnyTLS Modern",
    }
    if set(outbounds) != expected_tags:
        raise AssertionError(
            f"Quantumult X roundtrip node set drifted: {outbounds!r}"
        )
    vmess = outbounds["VMessStandard"]
    if (
        vmess.get("server") != "vmess.example.test"
        or vmess.get("tls", {}).get("server_name") != "tls.example.test"
        or vmess.get("tls", {}).get("alpn") != ["h2", "http/1.1"]
    ):
        raise AssertionError(f"Quantumult X VMess roundtrip drifted: {vmess!r}")
    vmess_reality_out = outbounds["QuanX VMess Reality"]
    if (
        vmess_reality_out.get("tls", {}).get("reality", {}).get("public_key")
        != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        or vmess_reality_out.get("tls", {}).get("reality", {}).get("short_id")
        != "00112233"
        or vmess_reality_out.get("tls", {}).get("server_name")
        != "reality.example.test"
    ):
        raise AssertionError(
            f"Quantumult X VMess Reality roundtrip drifted: {vmess_reality_out!r}"
        )
    vless_ipv6 = outbounds["VLESSDefaultTCP"]
    if (
        vless_ipv6.get("server") != "2001:db8::1"
        or vless_ipv6.get("tls", {}).get("alpn") != ["h2", "http/1.1"]
    ):
        raise AssertionError(
            f"Quantumult X IPv6/ALPN roundtrip drifted: {vless_ipv6!r}"
        )
    vless_http_out = outbounds["QuanX VLESS HTTP"]
    if (
        vless_http_out.get("transport", {}).get("type") != "http"
        or vless_http_out.get("transport", {}).get("host")
        != ["http.example.test"]
        or vless_http_out.get("transport", {}).get("path") != "/header"
    ):
        raise AssertionError(
            f"Quantumult X VLESS HTTP roundtrip drifted: {vless_http_out!r}"
        )
    vless_reality = outbounds["RealityNumericSid"]
    if (
        vless_reality.get("flow") != "xtls-rprx-vision"
        or vless_reality.get("tls", {}).get("reality", {}).get("short_id")
        != "00112233"
    ):
        raise AssertionError(
            f"Quantumult X VLESS Reality/Vision roundtrip drifted: {vless_reality!r}"
        )
    trojan = outbounds["QuanX Trojan WSS"]
    if (
        trojan.get("transport", {}).get("type") != "ws"
        or trojan.get("transport", {}).get("path") != "/ws"
        or trojan.get("transport", {}).get("headers", {}).get("Host")
        != "trojan-host.example.test"
        or trojan.get("tls", {}).get("alpn") != ["h2", "http/1.1"]
    ):
        raise AssertionError(f"Quantumult X Trojan WSS roundtrip drifted: {trojan!r}")
    anytls = outbounds["AnyTLS Modern"]
    if (
        anytls.get("server") != "2001:db8::12"
        or anytls.get("password") != "p@ss+word"
        or anytls.get("tls", {}).get("server_name")
        != "anytls-tls.example.test"
        or anytls.get("tls", {}).get("alpn") != ["h2", "http/1.1"]
    ):
        raise AssertionError(f"Quantumult X AnyTLS roundtrip drifted: {anytls!r}")

    invalid_quanx_lines = (
        "vmess = vmess.example.test:443, method=none, "
        "password=22222222-2222-2222-2222-222222222222, obfs=over-tls, "
        "obfs-host=tls.example.test, tls-alpn=0, tag=Bad ALPN",
        "vless = reality.example.test:443, method=none, "
        "password=33333333-3333-4333-8333-333333333333, obfs=over-tls, "
        "obfs-host=reality.example.test, "
        "reality-base64-pubkey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, "
        "reality-hex-shortid=xyz, vless-flow=xtls-rprx-vision, "
        "tag=Bad Reality",
        "trojan = trojan.example.test:443, password=secret, obfs=wss, "
        "obfs-host=trojan.example.test, over-tls=true, tag=Conflicting TLS",
        "anytls = anytls.example.test:443, password=secret, over-tls=true, "
        "fast-open=maybe, tag=Bad Boolean",
        "anytls = anytls.example.test:443, password=secret, over-tls=true, "
        "unsupported-option=value, tag=Unknown Field",
    )
    for invalid_index, invalid_line in enumerate(invalid_quanx_lines):
        FixtureHandler.quanx_roundtrip_config = (
            "[server_local]\n" + invalid_line + "\n"
        )
        invalid_status, _, _ = request(
            base_url,
            "/sub",
            {
                "target": "singbox",
                "url": fixture_base
                + f"/quanx-roundtrip.conf?case=invalid-{invalid_index}",
                "list": "true",
            },
        )
        if invalid_status != 400:
            raise AssertionError(
                "invalid or conflicting Quantumult X node did not fail closed: "
                f"HTTP {invalid_status} {invalid_line!r}"
            )

    for source in (
        VLESS_HTTPUPGRADE_URI,
        VLESS_TCP_HTTP_URI,
        TROJAN_WS_URI,
        TROJAN_KCP_URI,
        "trojan://bad%2Cpassword@trojan.example.test:443?security=tls#BadScalar",
    ):
        rejected_status, _, _ = request(
            base_url, "/sub", {"target": "quanx", "url": source, "list": "true"}
        )
        if rejected_status != 400:
            raise AssertionError(
                "Quantumult X accepted a lossy or unsafe node: "
                f"HTTP {rejected_status} {source!r}"
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


def shadowrocket_upload_path_compatibility_baseline(
    binary: Path, fixture_base: str
) -> None:
    with FixtureHandler.counter_lock:
        uploaded_path_offset = len(FixtureHandler.gist_uploaded_paths)

    params = {
        "target": "shadowrocket",
        "url": SUBSCRIPTION.strip(),
        "config": DISABLE_RULEGEN_CONFIG,
        "list": "true",
        "upload": "true",
    }
    with running_service(
        binary,
        security_profile="lan",
        gist_api_base=fixture_base,
    ) as base_url:
        explicit_status, explicit_body, _ = request(base_url, "/sub", params)
        auto_status, auto_body, auto_headers = request(
            base_url,
            "/sub",
            {**params, "target": "auto"},
            {"User-Agent": "Shadowrocket/2.2.60"},
        )

    with FixtureHandler.counter_lock:
        uploaded_paths = FixtureHandler.gist_uploaded_paths[uploaded_path_offset:]
    if (
        explicit_status != 200
        or auto_status != 200
        or explicit_body != auto_body
        or uploaded_paths != ["shadowrocket", "sub"]
    ):
        raise AssertionError(
            "Shadowrocket upload path compatibility drifted: "
            f"explicit=HTTP {explicit_status}, auto=HTTP {auto_status}, "
            f"body_equal={explicit_body == auto_body}, paths={uploaded_paths!r}"
        )
    assert_vary_header(auto_headers, "User-Agent", "auto Shadowrocket upload")


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


def settings_singbox_wireguard_endpoint_baseline(helper: Path) -> None:
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
            legacy = load_settings_snapshot(helper, original)
            if legacy["singbox"]["wireguard_endpoint"] is not False:
                raise AssertionError(
                    f"{original.suffix} legacy WireGuard schema default changed"
                )
            if legacy["singbox"]["snell_outbound"] is not False:
                raise AssertionError(
                    f"{original.suffix} legacy Snell outbound default changed"
                )
            content = original.read_text(encoding="utf-8")
            if original.suffix == ".yml":
                content += (
                    "\nsingbox:\n"
                    "  wireguard_endpoint: true\n"
                    "  snell_outbound: true\n"
                )
            elif original.suffix == ".toml":
                content += (
                    "\n[singbox]\n"
                    "wireguard_endpoint = true\n"
                    "snell_outbound = true\n"
                )
            else:
                content += (
                    "\n[singbox]\n"
                    "wireguard_endpoint=true\n"
                    "snell_outbound=true\n"
                )
            configured = temporary_path / fixture_name
            configured.write_text(content, encoding="utf-8", newline="\n")
            enabled = load_settings_snapshot(helper, configured)
            if enabled["singbox"]["wireguard_endpoint"] is not True:
                raise AssertionError(
                    f"{original.suffix} did not enable WireGuard endpoint output"
                )
            if enabled["singbox"]["snell_outbound"] is not True:
                raise AssertionError(
                    f"{original.suffix} did not enable Snell outbound output"
                )
            reloaded = reload_settings_snapshot(helper, configured, original)
            if reloaded["singbox"]["wireguard_endpoint"] is not False:
                raise AssertionError(
                    f"{original.suffix} hot reload retained a removed endpoint switch"
                )
            if reloaded["singbox"]["snell_outbound"] is not False:
                raise AssertionError(
                    f"{original.suffix} hot reload retained a removed Snell switch"
                )


def common_scalar_binding_compatibility_baseline(helper: Path) -> None:
    configured_values: dict[str, str | bool] = {
        "prepend_insert_url": False,
        "base_path": "stage-c-base",
        "clash_rule_base": "stage-c/clash.tpl",
        "surge_rule_base": "stage-c/surge.tpl",
        "surfboard_rule_base": "stage-c/surfboard.tpl",
        "stash_rule_base": "stage-c/stash.tpl",
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
        if any(
            snapshot["common"]["rule_bases"].get("stash") != "base/stash.yaml"
            for snapshot in legacy_snapshots
        ):
            raise AssertionError(
                "legacy preferences without stash_rule_base did not use "
                "base/stash.yaml"
            )
        common = configured_snapshots[0]["common"]
        proxies = configured_snapshots[0]["proxies"]
        expected_rule_bases = {
            name: f"stage-c/{name}.tpl"
            for name in (
                "clash",
                "surge",
                "surfboard",
                "stash",
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
            if reloaded["common"]["rule_bases"].get("stash") != "base/stash.yaml":
                raise AssertionError(
                    f"{suffix} removal did not restore the default stash_rule_base"
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
        # Persisting this synthetic canary is the subject of the diagnostic
        # non-leakage test below, not storage of a real credential.
        # codeql[py/clear-text-storage-sensitive-data]
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


def ruleset_executor_capacity_baseline(binary: Path, fixture_base: str) -> None:
    logs: list[str] = []
    FixtureHandler.slow_ruleset_started.clear()
    FixtureHandler.slow_ruleset_release.clear()
    slow_sources = "|".join(
        (
            fixture_base + "/slow-generation-rules.list?parent=one-a",
            fixture_base + "/slow-generation-rules.list?parent=one-b",
        )
    )
    second_sources = "|".join(
        (
            fixture_base + "/slow-generation-rules.list?parent=two-a",
            fixture_base + "/slow-generation-rules.list?parent=two-b",
        )
    )
    first_params = {
        "url": base64.urlsafe_b64encode(slow_sources.encode()).decode(),
        "type": "6",
    }
    second_params = {
        "url": base64.urlsafe_b64encode(second_sources.encode()).decode(),
        "type": "6",
    }
    first_result: list[tuple[int, bytes, dict[str, str]]] = []
    first_error: list[BaseException] = []
    with running_service(
        binary,
        log_capture=logs,
        config_replacements=(
            ("async_fetch_ruleset = false", "async_fetch_ruleset = true"),
        ),
        environment={
            "SUBCONVERTER_RULESET_EXECUTOR_WORKERS": "1",
            "SUBCONVERTER_RULESET_EXECUTOR_QUEUE_CAPACITY": "1",
        },
    ) as base_url:
        def run_first_parent() -> None:
            try:
                first_result.append(request(base_url, "/getruleset", first_params))
            except BaseException as error:
                first_error.append(error)

        first = threading.Thread(target=run_first_parent)
        first.start()
        if not FixtureHandler.slow_ruleset_started.wait(timeout=10):
            FixtureHandler.slow_ruleset_release.set()
            first.join(timeout=5)
            raise AssertionError("first ruleset parent did not occupy the executor")
        status, body, headers = request(base_url, "/getruleset", second_params)
        if status != 503 or headers.get("retry-after") != "1":
            FixtureHandler.slow_ruleset_release.set()
            first.join(timeout=5)
            raise AssertionError(
                "ruleset queue saturation did not return deterministic "
                f"capacity status: HTTP {status}, headers={headers!r}, "
                f"body={body!r}"
            )
        if b"capacity" not in body.lower():
            raise AssertionError("ruleset capacity response lost its reason")
        FixtureHandler.slow_ruleset_release.set()
        first.join(timeout=20)
        if first.is_alive() or first_error:
            raise AssertionError(
                f"first ruleset parent did not drain: {first_error!r}"
            )
        if len(first_result) != 1 or first_result[0][0] != 200:
            raise AssertionError(
                f"first ruleset parent changed result: {first_result!r}"
            )
    diagnostics = "".join(logs)
    if "path=/getruleset status=500" in diagnostics:
        raise AssertionError("ruleset executor saturation escaped as HTTP 500")


def conversion_cost_classification_baseline(
    binary: Path, fixture_base: str
) -> None:
    logs: list[str] = []
    with running_service(
        binary,
        log_capture=logs,
        log_level="debug",
    ) as base_url:
        cases = (
            (
                "provider",
                {
                    "target": "clash",
                    "url": fixture_base + "/subscription.txt",
                },
            ),
            (
                "filter",
                {
                    "target": "clash",
                    "url": fixture_base + "/subscription.txt",
                    "include": "Smoke",
                },
            ),
            (
                "rename",
                {
                    "target": "clash",
                    "url": fixture_base + "/subscription.txt",
                    "rename": "Smoke@Renamed",
                },
            ),
            (
                "default-config",
                {
                    "target": "clash",
                    "url": SUBSCRIPTION.strip(),
                },
            ),
            (
                "multiple",
                {
                    "target": "clash",
                    "url": fixture_base
                    + "/subscription.txt|"
                    + SUBSCRIPTION.strip(),
                },
            ),
            (
                "rules",
                {
                    "target": "clash",
                    "url": SUBSCRIPTION.strip(),
                    "ruleprepend": "DOMAIN,cost.test,Proxy",
                },
            ),
        )
        for label, params in cases:
            status, body, _ = request(base_url, "/sub", params)
            if status != 200:
                raise AssertionError(
                    f"{label} cost probe failed: HTTP {status}: {body!r}"
                )
    costs = re.findall(r"CONVERSION_ADMISSION cost=(low|medium|high)", "".join(logs))
    if len(costs) < len(cases):
        raise AssertionError(f"conversion cost diagnostics are incomplete: {costs!r}")
    observed = costs[-len(cases):]
    if observed[0] == "low" or observed[3] == "low":
        raise AssertionError(
            f"unproven provider/default conversion was classified Low: {observed!r}"
        )
    if any(observed[index] != "high" for index in (1, 2, 4, 5)):
        raise AssertionError(
            f"filter/rename/multiple/rules conversion was not High: {observed!r}"
        )


def resource_control_execution_path_baseline(binary: Path) -> None:
    dashboard_headers = {
        "Authorization": "Basic "
        + base64.b64encode(
            b"fixture-admin:fixture-dashboard-secret"
        ).decode()
    }
    with running_service(
        binary,
        statistics=True,
        environment={"SUBCONVERTER_RESOURCE_CONTROL": "compat"},
    ) as base_url:
        status, body, _ = request(
            base_url,
            "/sub",
            {
                "target": "mixed",
                "url": SUBSCRIPTION.strip(),
                "config": DISABLE_RULEGEN_CONFIG,
                "list": "true",
            },
        )
        if status != 200 or not body:
            raise AssertionError(
                f"compat execution probe failed: HTTP {status}: {body!r}"
            )
        status, body, _ = request(
            base_url, "/dashboard/data", headers=dashboard_headers
        )
        if status != 200:
            raise AssertionError(
                f"compat execution dashboard returned HTTP {status}"
            )
        dashboard = json.loads(body)
        resources = dashboard["resource_control"]
        conversion = dashboard["conversion_scheduler"]
        flow = dashboard["legacy_request_flow"]
        cache_admission = dashboard["subscription_cache_admission"]
        if (
            resources["effective_mode"] != "compat"
            or conversion["accepted"] < 1
            or flow["accepted"] != 0
            or cache_admission["enabled"] is not False
        ):
            raise AssertionError(
                "compat request did not stay on the bounded synchronous path: "
                f"resources={resources!r} conversion={conversion!r} flow={flow!r}"
            )


def force_max_controller_runtime_baseline(binary: Path) -> None:
    dashboard_headers = {
        "Authorization": "Basic "
        + base64.b64encode(
            b"fixture-admin:fixture-dashboard-secret"
        ).decode()
    }
    with running_service(
        binary,
        statistics=True,
        environment={"SUBCONVERTER_RESOURCE_CONTROL": "force_max"},
    ) as base_url:
        request_status, request_body, _ = request(
            base_url,
            "/sub",
            {
                "target": "mixed",
                "url": SUBSCRIPTION.strip(),
                "config": DISABLE_RULEGEN_CONFIG,
                "list": "true",
            },
        )
        if request_status != 200 or not request_body:
            raise AssertionError(
                "force_max execution probe failed: "
                f"HTTP {request_status}: {request_body!r}"
            )
        time.sleep(2.2)
        status, body, _ = request(
            base_url, "/dashboard/data", headers=dashboard_headers
        )
        if status != 200:
            raise AssertionError(
                f"force_max controller dashboard returned HTTP {status}"
            )
        dashboard = json.loads(body)
        resources = dashboard["resource_control"]
        permits = dashboard["cpu_permits"]
        conversion = dashboard["conversion_scheduler"]
        flow = dashboard["legacy_request_flow"]
        singleflight = dashboard["subscription_singleflight"]
        backend = os.environ.get("SUBCONVERTER_HTTP_BACKEND", "beast").lower()
        execution_path_ok = (
            conversion["accepted"] >= 1 and flow["accepted"] == 0
            if backend == "httplib"
            else conversion["accepted"] == 0 and flow["accepted"] >= 1
        )
        if (
            resources["controller_state"] != "max_ready"
            or resources["sample_count"] < 1
            or resources["suggested_cpu_permits"]
            != resources["max_cpu_permits"]
            or permits["limit"] != resources["max_cpu_permits"]
            or not execution_path_ok
            or singleflight["active_owners"] != 0
            or singleflight["waiting_followers"] != 0
            or (backend != "httplib" and
                singleflight["owners_created_total"] < 1)
        ):
            raise AssertionError(
                "idle force_max did not hold the hardware CPU limit: "
                f"resources={resources!r} permits={permits!r} "
                f"conversion={conversion!r} flow={flow!r}"
            )


def force_max_subscription_cache_admission_baseline(
    binary: Path, fixture_base: str
) -> None:
    dashboard_headers = {
        "Authorization": "Basic "
        + base64.b64encode(
            b"fixture-admin:fixture-dashboard-secret"
        ).decode()
    }
    with running_service(
        binary,
        statistics=True,
        environment={
            "SUBCONVERTER_RESOURCE_CONTROL": "force_max",
            "SUBCONVERTER_RESPONSE_CACHE_TTL": "0",
        },
    ) as base_url:
        status, body, _ = request(
            base_url, "/dashboard/data", headers=dashboard_headers
        )
        before = json.loads(body)
        admission_before = before["subscription_cache_admission"]
        params = {
            "target": "mixed",
            "url": fixture_base + "/subscription.txt?cache-admission=repeat",
            "config": DISABLE_RULEGEN_CONFIG,
            "list": "true",
        }
        with FixtureHandler.counter_lock:
            upstream_before = FixtureHandler.subscription_request_count
        responses = [request(base_url, "/sub", params) for _ in range(3)]
        if any(status != 200 or b"Smoke" not in content
               for status, content, _ in responses):
            raise AssertionError(
                f"force_max cache admission responses failed: {responses!r}"
            )
        with FixtureHandler.counter_lock:
            repeated_upstream = (
                FixtureHandler.subscription_request_count - upstream_before
            )
        if repeated_upstream != 2:
            raise AssertionError(
                "two-hit cache admission did not bypass once then persist: "
                f"upstream={repeated_upstream}"
            )

        for index in range(8):
            unique = dict(params)
            unique["url"] = (
                fixture_base
                + f"/subscription.txt?cache-admission=unique-{index}"
            )
            status, content, _ = request(base_url, "/sub", unique)
            if status != 200 or b"Smoke" not in content:
                raise AssertionError(
                    f"unique cache admission request {index} failed"
                )
        with FixtureHandler.counter_lock:
            total_upstream = (
                FixtureHandler.subscription_request_count - upstream_before
            )
        if total_upstream != 10:
            raise AssertionError(
                f"unique cache admission changed upstream count: {total_upstream}"
            )

        FixtureHandler.slow_subscription_started.clear()
        FixtureHandler.slow_subscription_release.clear()
        concurrent_params = dict(params)
        concurrent_params["url"] = (
            fixture_base
            + "/slow-subscription.txt?cache-admission=concurrent-reuse"
        )
        concurrent_responses: list[tuple[int, bytes, dict[str, str]]] = []

        def run_concurrent_cache_request(
            request_params: dict[str, str]
        ) -> None:
            concurrent_responses.append(
                request(base_url, "/sub", request_params)
            )

        with FixtureHandler.counter_lock:
            slow_upstream_before = FixtureHandler.slow_subscription_request_count
        follower_params = dict(concurrent_params)
        follower_params["emoji"] = "true"
        owner = threading.Thread(
            target=run_concurrent_cache_request, args=(concurrent_params,)
        )
        follower = threading.Thread(
            target=run_concurrent_cache_request, args=(follower_params,)
        )
        try:
            owner.start()
            if not FixtureHandler.slow_subscription_started.wait(timeout=10):
                raise AssertionError(
                    "cache admission owner did not reach slow upstream"
                )
            follower.start()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                _, dashboard_body, _ = request(
                    base_url, "/dashboard/data", headers=dashboard_headers
                )
                current = json.loads(dashboard_body)[
                    "subscription_cache_admission"
                ]
                if (
                    int(current["reuse_admitted_total"])
                    - int(admission_before["reuse_admitted_total"])
                    >= 2
                ):
                    break
                time.sleep(0.02)
            else:
                raise AssertionError(
                    "concurrent follower did not request cache persistence"
                )
        finally:
            FixtureHandler.slow_subscription_release.set()
            owner.join(timeout=15)
            follower.join(timeout=15)
        if owner.is_alive() or follower.is_alive():
            raise AssertionError("concurrent cache admission requests hung")
        cached_response = request(base_url, "/sub", concurrent_params)
        concurrent_responses.append(cached_response)
        if any(
            response_status != 200 or b"Smoke" not in response_body
            for response_status, response_body, _ in concurrent_responses
        ):
            raise AssertionError(
                "concurrent cache persistence responses failed: "
                f"{concurrent_responses!r}"
            )
        with FixtureHandler.counter_lock:
            concurrent_upstream = (
                FixtureHandler.slow_subscription_request_count
                - slow_upstream_before
            )
        if concurrent_upstream != 1:
            raise AssertionError(
                "admitted follower did not persist the shared fetch: "
                f"upstream={concurrent_upstream}"
            )

        time.sleep(1.1)
        status, body, _ = request(
            base_url, "/dashboard/data", headers=dashboard_headers
        )
        after = json.loads(body)
        admission = after["subscription_cache_admission"]
        outbound = after["outbound_fetch"]
        if (
            status != 200
            or admission["enabled"] is not True
            or int(admission["first_seen_bypassed_total"])
            - int(admission_before["first_seen_bypassed_total"])
            != 10
            or int(admission["reuse_admitted_total"])
            - int(admission_before["reuse_admitted_total"])
            != 2
            or int(after["retained_response_bytes"]["used"]) != 0
            or int(outbound["active"]) != 0
            or int(outbound["running"]) != 0
            or int(outbound["handle_window"])
            != int(outbound["active_connection_limit"])
            or int(outbound["open_connection_limit"])
            < int(outbound["active_connection_limit"])
            or int(outbound["connection_cache_limit"])
            > int(outbound["open_connection_limit"])
            or int(outbound["recoverable_retry_limit"]) != 3
        ):
            raise AssertionError(
                "force_max subscription cache admission counters changed: "
                f"{admission!r}"
            )

    compat_params = {
        "target": "mixed",
        "url": fixture_base + "/subscription.txt?cache-admission=compat",
        "config": DISABLE_RULEGEN_CONFIG,
        "list": "true",
    }
    with running_service(
        binary,
        statistics=True,
        environment={
            "SUBCONVERTER_RESOURCE_CONTROL": "compat",
            "SUBCONVERTER_RESPONSE_CACHE_TTL": "0",
        },
    ) as base_url:
        with FixtureHandler.counter_lock:
            upstream_before = FixtureHandler.subscription_request_count
        responses = [request(base_url, "/sub", compat_params) for _ in range(2)]
        with FixtureHandler.counter_lock:
            upstream_delta = (
                FixtureHandler.subscription_request_count - upstream_before
            )
        _, dashboard_body, _ = request(
            base_url, "/dashboard/data", headers=dashboard_headers
        )
        dashboard = json.loads(dashboard_body)
        admission = dashboard["subscription_cache_admission"]
        outbound = dashboard["outbound_fetch"]
        if (
            upstream_delta != 1
            or any(status != 200 for status, _, _ in responses)
            or admission != {
                "enabled": False,
                "entries": 0,
                "first_seen_bypassed_total": 0,
                "reuse_admitted_total": 0,
            }
            or int(outbound["handle_window"]) != 0
            or int(outbound["active_connection_limit"]) != 64
            or int(outbound["open_connection_limit"]) != 64
            or int(outbound["connection_cache_limit"]) != 64
            or int(outbound["recoverable_retry_limit"]) != 1
        ):
            raise AssertionError(
                "compat cache persistence or isolation changed: "
                f"upstream={upstream_delta} admission={admission!r}"
            )

    adaptive_params = dict(compat_params)
    adaptive_params["url"] = (
        fixture_base + "/subscription.txt?cache-admission=adaptive"
    )
    with running_service(
        binary,
        statistics=True,
        environment={
            "SUBCONVERTER_RESOURCE_CONTROL": "adaptive",
            "SUBCONVERTER_RESPONSE_CACHE_TTL": "0",
        },
    ) as base_url:
        with FixtureHandler.counter_lock:
            upstream_before = FixtureHandler.subscription_request_count
        responses = [
            request(base_url, "/sub", adaptive_params) for _ in range(3)
        ]
        with FixtureHandler.counter_lock:
            upstream_delta = (
                FixtureHandler.subscription_request_count - upstream_before
            )
        _, dashboard_body, _ = request(
            base_url, "/dashboard/data", headers=dashboard_headers
        )
        dashboard = json.loads(dashboard_body)
        admission = dashboard["subscription_cache_admission"]
        outbound = dashboard["outbound_fetch"]
        if (
            upstream_delta != 2
            or any(
                status != 200 or b"Smoke" not in content
                for status, content, _ in responses
            )
            or admission["enabled"] is not True
            or int(admission["first_seen_bypassed_total"]) != 1
            or int(admission["reuse_admitted_total"]) != 1
            or int(outbound["handle_window"])
            != int(outbound["active_connection_limit"])
            or int(outbound["open_connection_limit"])
            < int(outbound["active_connection_limit"])
            or int(outbound["connection_cache_limit"])
            > int(outbound["open_connection_limit"])
            or int(outbound["recoverable_retry_limit"]) != 3
        ):
            raise AssertionError(
                "adaptive cache admission did not match force_max: "
                f"upstream={upstream_delta} admission={admission!r}"
            )


def recoverable_fetch_retry_baseline(binary: Path, fixture_base: str) -> None:
    cases = (
        ("force_max", "multi", 200, 4),
        ("adaptive", "multi", 200, 4),
        ("force_max", "sync", 200, 4),
        ("compat", "multi", 400, 2),
    )
    for mode, engine, expected_status, expected_attempts in cases:
        with FixtureHandler.counter_lock:
            FixtureHandler.recoverable_retry_request_count = 0
            FixtureHandler.recoverable_retry_failures = 3
        try:
            with running_service(
                binary,
                environment={
                    "SUBCONVERTER_RESOURCE_CONTROL": mode,
                    "SUBCONVERTER_FETCH_ENGINE": engine,
                    "SUBCONVERTER_RESPONSE_CACHE_TTL": "0",
                },
                config_replacements=(
                    ("cache_subscription = 60", "cache_subscription = 0"),
                ),
            ) as base_url:
                status, content, _ = request(
                    base_url,
                    "/sub",
                    {
                        "target": "mixed",
                        "url": fixture_base
                        + "/recoverable-retry-subscription.txt"
                        + f"?mode={mode}&engine={engine}",
                        "config": DISABLE_RULEGEN_CONFIG,
                        "list": "true",
                    },
                )
            with FixtureHandler.counter_lock:
                attempts = FixtureHandler.recoverable_retry_request_count
            if (
                status != expected_status
                or attempts != expected_attempts
                or (expected_status == 200 and b"Smoke" not in content)
            ):
                raise AssertionError(
                    "recoverable retry policy changed: "
                    f"mode={mode} engine={engine} HTTP={status} "
                    f"attempts={attempts} body={content!r}"
                )
        finally:
            with FixtureHandler.counter_lock:
                FixtureHandler.recoverable_retry_failures = 0


def force_max_arrival_singleflight_baseline(
    binary: Path, fixture_base: str
) -> None:
    if os.environ.get("SUBCONVERTER_HTTP_BACKEND", "beast").lower() == "httplib":
        return
    dashboard_headers = {
        "Authorization": "Basic "
        + base64.b64encode(
            b"fixture-admin:fixture-dashboard-secret"
        ).decode()
    }
    logs: list[str] = []
    with running_service(
        binary,
        statistics=True,
        log_capture=logs,
        log_level="debug",
        environment={"SUBCONVERTER_RESOURCE_CONTROL": "force_max"},
    ) as base_url:
        status, body, _ = request(
            base_url, "/dashboard/data", headers=dashboard_headers
        )
        if status != 200:
            raise AssertionError("arrival singleflight setup dashboard failed")
        before = json.loads(body)
        before_flow = int(before["legacy_request_flow"]["accepted"])
        before_owners = int(
            before["subscription_singleflight"]["owners_created_total"]
        )
        before_followers = int(
            before["subscription_singleflight"]["followers_attached_total"]
        )
        before_work_admitted = int(
            before["request_lifecycle"]["work_admitted"]
        )
        before_post_admission_capacity = int(
            before["request_lifecycle"][
                "server_capacity_failure_after_admission"
            ]
        )
        before_subscriptions = int(
            before["windows"]["lifetime"]["subscription_requests"]
        )

        FixtureHandler.slow_subscription_started.clear()
        FixtureHandler.slow_subscription_release.clear()
        with FixtureHandler.counter_lock:
            upstream_before = FixtureHandler.slow_subscription_request_count
        params = {
            "target": "singbox",
            "url": fixture_base + "/slow-subscription.txt?case=arrival-singleflight",
            "config": DISABLE_RULEGEN_CONFIG,
        }
        results: list[tuple[int, bytes, dict[str, str]]] = []
        errors: list[BaseException] = []

        def run_request() -> None:
            try:
                results.append(request(base_url, "/sub", params))
            except BaseException as error:
                errors.append(error)

        workers = [threading.Thread(target=run_request) for _ in range(16)]
        workers[0].start()
        if not FixtureHandler.slow_subscription_started.wait(timeout=10):
            FixtureHandler.slow_subscription_release.set()
            workers[0].join(timeout=5)
            raise AssertionError("arrival owner did not reach the slow fixture")
        for worker in workers[1:]:
            worker.start()

        observed = None
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            status, body, _ = request(
                base_url, "/dashboard/data", headers=dashboard_headers
            )
            if status == 200:
                candidate = json.loads(body)
                singleflight = candidate["subscription_singleflight"]
                if int(singleflight["waiting_followers"]) >= 15:
                    observed = candidate
                    break
            time.sleep(0.05)
        if observed is None:
            FixtureHandler.slow_subscription_release.set()
            for worker in workers:
                worker.join(timeout=5)
            raise AssertionError("arrival followers did not attach before scheduling")
        flow = observed["legacy_request_flow"]
        singleflight = observed["subscription_singleflight"]
        admission = observed["request_admission"]
        owner_admission = observed["owner_admission"]
        if (
            int(flow["accepted"]) - before_flow != 1
            or int(flow["active"]) != 1
            or int(flow["queued_entries"]) != 0
            or int(admission["active_entries"]) < 16
            or int(singleflight["active_owners"]) != 1
            or int(singleflight["owners_created_total"]) - before_owners != 1
            or int(singleflight["followers_attached_total"]) - before_followers
            != 15
            or owner_admission["source"] != "legacy_request_flow"
            or int(owner_admission["accepted_total"]) - before_flow != 1
            or int(owner_admission["active"]) != 1
        ):
            FixtureHandler.slow_subscription_release.set()
            for worker in workers:
                worker.join(timeout=5)
            raise AssertionError(
                "arrival followers consumed owner flow capacity: "
                f"flow={flow!r} admission={admission!r} "
                f"singleflight={singleflight!r} "
                f"owner_admission={owner_admission!r}"
            )

        FixtureHandler.slow_subscription_release.set()
        for worker in workers:
            worker.join(timeout=30)
        if any(worker.is_alive() for worker in workers):
            raise AssertionError("arrival singleflight workers did not finish")
        if errors:
            raise errors[0]
        if len(results) != 16:
            raise AssertionError(f"arrival fanout returned {len(results)} results")
        bodies = {hashlib.sha256(body).hexdigest() for status, body, _ in results}
        request_ids = {
            assert_request_id(headers, "arrival singleflight response")
            for _, _, headers in results
        }
        if (
            any(status != 200 or b"Smoke" not in body
                for status, body, _ in results)
            or len(bodies) != 1
            or len(request_ids) != 16
        ):
            raise AssertionError("arrival fanout responses changed semantics")
        with FixtureHandler.counter_lock:
            upstream_requests = (
                FixtureHandler.slow_subscription_request_count - upstream_before
            )
        if upstream_requests != 1:
            raise AssertionError(
                f"arrival fanout started {upstream_requests} upstream requests"
            )
        time.sleep(1.1)
        status, body, _ = request(
            base_url, "/dashboard/data", headers=dashboard_headers
        )
        after = json.loads(body)
        if (
            int(after["subscription_singleflight"]["active_owners"]) != 0
            or int(after["subscription_singleflight"]["waiting_followers"]) != 0
            or int(after["windows"]["lifetime"]["subscription_requests"])
            - before_subscriptions
            != 16
            or int(after["request_lifecycle"]["work_admitted"])
            - before_work_admitted
            != 16
            or int(
                after["request_lifecycle"][
                    "server_capacity_failure_after_admission"
                ]
            )
            != before_post_admission_capacity
        ):
            raise AssertionError(
                "arrival singleflight counters did not return to zero: "
                f"{after['subscription_singleflight']!r}"
            )

        distinct_before_flow = int(after["legacy_request_flow"]["accepted"])
        distinct_before_owners = int(
            after["subscription_singleflight"]["owners_created_total"]
        )
        distinct_before_followers = int(
            after["subscription_singleflight"]["followers_attached_total"]
        )
        distinct_before_work_admitted = int(
            after["request_lifecycle"]["work_admitted"]
        )
        distinct_results: list[tuple[int, bytes, dict[str, str]]] = []
        distinct_errors: list[BaseException] = []

        def run_distinct(index: int) -> None:
            try:
                distinct_results.append(
                    request(
                        base_url,
                        "/sub",
                        {
                            "target": "mixed",
                            "url": SUBSCRIPTION.strip().replace(
                                "#Smoke", f"#Arrival-{index}"
                            ),
                            "config": DISABLE_RULEGEN_CONFIG,
                            "list": "true",
                        },
                    )
                )
            except BaseException as error:
                distinct_errors.append(error)

        distinct_workers = [
            threading.Thread(target=run_distinct, args=(index,))
            for index in range(8)
        ]
        for worker in distinct_workers:
            worker.start()
        for worker in distinct_workers:
            worker.join(timeout=20)
        if any(worker.is_alive() for worker in distinct_workers):
            raise AssertionError("distinct arrival owners did not finish")
        if distinct_errors:
            raise distinct_errors[0]
        if len(distinct_results) != 8 or any(
            status != 200 for status, _, _ in distinct_results
        ):
            raise AssertionError(
                f"distinct arrival owner responses failed: {distinct_results!r}"
            )
        time.sleep(1.1)
        status, body, _ = request(
            base_url, "/dashboard/data", headers=dashboard_headers
        )
        distinct_after = json.loads(body)
        if (
            int(distinct_after["legacy_request_flow"]["accepted"])
            - distinct_before_flow
            != 8
            or int(
                distinct_after["subscription_singleflight"][
                    "owners_created_total"
                ]
            )
            - distinct_before_owners
            != 8
            or int(
                distinct_after["subscription_singleflight"][
                    "followers_attached_total"
                ]
            )
            != distinct_before_followers
            or int(
                distinct_after["windows"]["lifetime"][
                    "subscription_requests"
                ]
            )
            - before_subscriptions
            != 24
            or int(
                distinct_after["request_lifecycle"]["work_admitted"]
            )
            - distinct_before_work_admitted
            != 8
            or int(
                distinct_after["request_lifecycle"][
                    "server_capacity_failure_after_admission"
                ]
            )
            != before_post_admission_capacity
        ):
            raise AssertionError(
                "distinct keys no longer map one-to-one to owner flow tasks: "
                f"{distinct_after!r}"
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
    parser.add_argument("--singbox-stable-binary", type=Path)
    parser.add_argument("--singbox-next-binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    settings_snapshot_helper = args.settings_snapshot_helper.resolve()
    mihomo_binary = (
        args.mihomo_binary.resolve() if args.mihomo_binary is not None else None
    )
    singbox_stable_binary = (
        args.singbox_stable_binary.resolve()
        if args.singbox_stable_binary is not None
        else None
    )
    singbox_next_binary = (
        args.singbox_next_binary.resolve()
        if args.singbox_next_binary is not None
        else None
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
    if singbox_stable_binary is not None and not singbox_stable_binary.is_file():
        parser.error(
            f"stable sing-box binary does not exist: {singbox_stable_binary}"
        )
    if singbox_next_binary is not None and not singbox_next_binary.is_file():
        parser.error(f"next sing-box binary does not exist: {singbox_next_binary}")

    deployment_security_defaults_baseline()
    runtime_cli_isolation_baseline(binary)
    log_redirection_baseline(binary)
    early_log_level_parsing_baseline(settings_snapshot_helper)

    baseline_environment = os.environ.copy()
    for name in (
        "SUBCONVERTER_HTTP_BACKEND",
        "SUBCONVERTER_RESOURCE_CONTROL",
        "SUBCONVERTER_FORCE_MAX_CURVE_FINGERPRINT",
        "SUBCONVERTER_RULESET_EXECUTOR_WORKERS",
        "SUBCONVERTER_RULESET_EXECUTOR_QUEUE_CAPACITY",
    ):
        baseline_environment.pop(name, None)
    snapshots = [
        load_settings_snapshot(
            settings_snapshot_helper,
            COMPAT_FIXTURES / name,
            baseline_environment,
        )
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
    if snapshots[0]["advanced"]["resource_control"] != "compat":
        raise AssertionError("missing resource_control did not default to compat")
    if snapshots[0]["advanced"]["force_max_curve_fingerprint"]:
        raise AssertionError("force_max curve unexpectedly defaulted to valid")
    with tempfile.TemporaryDirectory(prefix="sce-unlimited-download-") as temporary:
        unlimited_pref = Path(temporary) / "pref.toml"
        unlimited_content = (COMPAT_FIXTURES / "legacy-pref.toml").read_text(
            encoding="utf-8"
        ).replace(
            "max_allowed_download_size = 1048576",
            "max_allowed_download_size = 0",
            1,
        )
        unlimited_pref.write_text(unlimited_content, encoding="utf-8", newline="\n")
        unlimited_snapshot = load_settings_snapshot(
            settings_snapshot_helper,
            unlimited_pref,
            baseline_environment,
        )
        if unlimited_snapshot["advanced"]["max_allowed_download_size"] != 0:
            raise AssertionError("max_allowed_download_size=0 lost unlimited semantics")
    resource_env = baseline_environment.copy()
    resource_env["SUBCONVERTER_RESOURCE_CONTROL"] = "adaptive"
    adaptive_snapshot = load_settings_snapshot(
        settings_snapshot_helper,
        COMPAT_FIXTURES / "legacy-pref.toml",
        resource_env,
    )
    if adaptive_snapshot["advanced"]["resource_control"] != "adaptive":
        raise AssertionError("resource_control environment override failed")
    force_env = baseline_environment.copy()
    force_env["SUBCONVERTER_RESOURCE_CONTROL"] = "force_max"
    force_snapshot, force_logs = run_settings_snapshot(
        settings_snapshot_helper,
        COMPAT_FIXTURES / "legacy-pref.toml",
        force_env,
    )
    if (
        force_snapshot["server"]["request_deadline_ms"]
        != snapshots[0]["server"]["request_deadline_ms"]
        or force_snapshot["server"]["max_pending_connections"] < 64
        or force_snapshot["server"]["max_concurrent_threads"] < 1
        or force_snapshot["advanced"]["resource_control_effective"]
        != "force_max"
    ):
        raise AssertionError("automatic force_max did not apply hardware budgets")
    if (
        "effective_mode=force_max" not in force_logs
        or "state=max_ready_static" not in force_logs
        or "hardware_detected=true" not in force_logs
        or "hardware_pin_matched=true" not in force_logs
        or "startup_budget_applied=true" not in force_logs
    ):
        raise AssertionError("automatic force_max did not activate")
    hardware = re.search(r"hardware=([0-9a-f]{16})", force_logs)
    if hardware is None:
        raise AssertionError("force_max hardware fingerprint log is missing")
    force_deadline_env = force_env.copy()
    force_deadline_env["SUBCONVERTER_REQUEST_DEADLINE_MS"] = "4321"
    force_deadline_snapshot = load_settings_snapshot(
        settings_snapshot_helper,
        COMPAT_FIXTURES / "legacy-pref.toml",
        force_deadline_env,
    )
    if force_deadline_snapshot["server"]["request_deadline_ms"] != 4321:
        raise AssertionError("force_max changed the configured finite deadline")
    mismatch_env = force_env.copy()
    mismatch_env["SUBCONVERTER_FORCE_MAX_CURVE_FINGERPRINT"] = "0" * 16
    mismatch_snapshot, mismatch_logs = run_settings_snapshot(
        settings_snapshot_helper,
        COMPAT_FIXTURES / "legacy-pref.toml",
        mismatch_env,
    )
    if (
        mismatch_snapshot["server"] != snapshots[0]["server"]
        or mismatch_snapshot["advanced"]["resource_control_effective"]
        != "compat"
        or any(
            expected not in mismatch_logs
            for expected in (
                "effective_mode=compat",
                "state=safe_fallback",
                "hardware_pin_matched=false",
                "startup_budget_applied=false",
            )
        )
    ):
        raise AssertionError("hardware pin mismatch did not use compat limits")
    calibrated_env = force_env.copy()
    calibrated_env["SUBCONVERTER_FORCE_MAX_CURVE_FINGERPRINT"] = hardware.group(1)
    calibrated_snapshot, calibrated_logs = run_settings_snapshot(
        settings_snapshot_helper,
        COMPAT_FIXTURES / "legacy-pref.toml",
        calibrated_env,
    )
    if any(
        expected not in calibrated_logs
        for expected in (
            "effective_mode=force_max",
            "hardware_pin_matched=true",
            "startup_budget_applied=true",
        )
    ):
        raise AssertionError("matching force_max hardware pin was not applied")
    if calibrated_snapshot["advanced"]["force_max_curve_fingerprint"] != hardware.group(1):
        raise AssertionError("force_max hardware pin was not retained")
    invalid_resource_env = baseline_environment.copy()
    invalid_resource_env["SUBCONVERTER_RESOURCE_CONTROL"] = "automatic"
    invalid_resource = subprocess.run(
        [str(settings_snapshot_helper), str(COMPAT_FIXTURES / "legacy-pref.toml")],
        cwd=REPOSITORY,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=invalid_resource_env,
    )
    if invalid_resource.returncode == 0:
        raise AssertionError("invalid resource_control was accepted")
    security_configuration_matrix_baseline(settings_snapshot_helper)
    settings_reload_compatibility_baseline(settings_snapshot_helper)
    settings_singbox_wireguard_endpoint_baseline(settings_snapshot_helper)
    common_scalar_binding_compatibility_baseline(settings_snapshot_helper)
    settings_parser_diagnostic_redaction_baseline(settings_snapshot_helper)
    settings_provider_interval_compatibility_baseline(settings_snapshot_helper)
    settings_provider_direct_compatibility_baseline(settings_snapshot_helper)
    settings_dashboard_client_ip_baseline(settings_snapshot_helper)
    fetch_shutdown_construction_race_baseline(settings_snapshot_helper)

    with fixture_server() as fixture_base:
        owned_webget_boundary_baseline(settings_snapshot_helper, fixture_base)
        parser_invocation_log_baseline(binary, fixture_base)
        provider_no_fetch_vary_and_route_log_baseline(binary, fixture_base)
        quanx_server_remote_baseline(binary, fixture_base)
        parser_failure_level_and_mixed_request_baseline(binary)
        insert_url_parser_route_baseline(binary, fixture_base)
        vary_cache_and_coalesce_baseline(binary, fixture_base)
        if os.environ.get("SUBCONVERTER_HTTP_BACKEND", "beast").lower() != "httplib":
            vary_cache_and_coalesce_baseline(
                binary, fixture_base, resource_mode="force_max"
            )
        response_microcache_eviction_baseline(binary)
        explain_privacy_and_cache_baseline(binary, fixture_base)
        wireguard_outbound_logs: list[str] = []
        with running_service(
            binary, log_capture=wireguard_outbound_logs
        ) as base_url:
            conversion_baselines(base_url, fixture_base, args.update_golden)
            local_group_matcher_baseline(base_url)
            singbox_modern_full_profile_baseline(
                base_url,
                fixture_base,
                singbox_stable_binary,
                singbox_next_binary,
            )
            parser_route_isolation_baseline(base_url, fixture_base)
            classic_protocol_baseline(base_url, fixture_base)
            legacy_niche_protocol_baseline(base_url, fixture_base)
            wireguard_endpoint_logs: list[str] = []
            with running_service(
                binary,
                log_capture=wireguard_endpoint_logs,
                config_replacements=((
                    "[custom_openclash_rules]",
                    "[singbox]\nwireguard_endpoint = true\n\n"
                    "[custom_openclash_rules]",
                ),),
            ) as endpoint_base_url:
                wireguard_structured_conversion_baseline(
                    base_url, endpoint_base_url
                )
            if not wireguard_endpoint_logs or (
                "SINGBOX_WIREGUARD_GENERATION schema=endpoint nodes=1 peers=2"
                not in wireguard_endpoint_logs[0]
            ):
                raise AssertionError(
                    "sing-box endpoint WireGuard diagnostics are missing"
                )
            snell_logs: list[str] = []
            with running_service(
                binary,
                log_capture=snell_logs,
                config_replacements=(
                    (
                        "[custom_openclash_rules]",
                        "[singbox]\nsnell_outbound = true\n\n"
                        "[custom_openclash_rules]",
                    ),
                    (
                        "udp_flag = false",
                        "# udp_flag intentionally omitted for Snell fidelity",
                    ),
                ),
            ) as snell_base_url:
                singbox_snell_outbound_baseline(base_url, snell_base_url)
            if not snell_logs or (
                "SINGBOX_SNELL_GENERATION enabled=true input=3 emitted=3 "
                "normalized_v5=1 minimum_version=1.14.0"
                not in snell_logs[0]
            ):
                raise AssertionError(
                    "sing-box Snell generation diagnostics are missing"
                )
            netch_legacy_parser_baseline(base_url)
            mieru_legacy_parser_baseline(base_url)
            target_generation_stats_baseline(base_url)
            v2ray_client_target_baseline(base_url)
            shadowrocket_target_baseline(base_url)
            stash_target_baseline(base_url, fixture_base)
            singbox_import_fidelity_baseline(base_url, fixture_base)
            loon_current_node_output_baseline(base_url)
            quanx_current_node_output_baseline(base_url, fixture_base)
            simple_target_protocol_baseline(base_url, fixture_base)
            provider_direct_default_output_baseline(base_url, fixture_base)
            select_health_check_output_baseline(base_url, fixture_base)
        if not wireguard_outbound_logs or (
            "SINGBOX_WIREGUARD_GENERATION schema=outbound nodes=1 peers=2"
            not in wireguard_outbound_logs[0]
        ):
            raise AssertionError(
                "sing-box outbound WireGuard diagnostics are missing"
            )
        if (
            "STASH_RULE_GENERATION input=11 inline=2 expanded=0 providers=9 "
            not in wireguard_outbound_logs[0]
        ):
            raise AssertionError("Stash native rule generation diagnostics are missing")
        for secret in (
            "stash-domain-token",
            "stash-domain-yaml-token",
            "stash-domain-text-token",
            "stash-domain-api-token",
            "stash-ip-token",
            "stash-ip-yaml-token",
            "stash-ip-text-token",
            "stash-classical-token",
            "stash-classical-yaml-token",
            "stash-atomic-token",
        ):
            if secret in wireguard_outbound_logs[0]:
                raise AssertionError("Stash native rule diagnostics leaked a source token")
        with running_service(
            binary,
            config_replacements=((
                "max_allowed_rules = 4096",
                "max_allowed_rules = 1",
            ),),
        ) as stash_rule_limit_url:
            stash_rule_limit_baseline(stash_rule_limit_url, fixture_base)
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
        shadowrocket_upload_path_compatibility_baseline(binary, fixture_base)
        upload_failure_compatibility_baseline(binary, fixture_base)
        external_config_failure_baseline(binary, fixture_base)
        loopback_proxy_route_baseline(binary, fixture_base)
        loopback_redirect_route_baseline(binary, fixture_base)
        conversion_cost_classification_baseline(binary, fixture_base)
        resource_control_execution_path_baseline(binary)
        force_max_controller_runtime_baseline(binary)
        force_max_subscription_cache_admission_baseline(binary, fixture_base)
        recoverable_fetch_retry_baseline(binary, fixture_base)
        force_max_arrival_singleflight_baseline(binary, fixture_base)
        ruleset_executor_capacity_baseline(binary, fixture_base)
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
