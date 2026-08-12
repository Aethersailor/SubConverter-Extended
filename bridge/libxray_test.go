package main

import (
	"encoding/base64"
	"encoding/json"
	"runtime/debug"
	"strings"
	"testing"
)

const xrayTestUUID = "12345678-abcd-abcd-abcd-123456789abc"

func TestLibXrayPinnedModule(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("Go build information unavailable")
	}
	for _, dependency := range info.Deps {
		if dependency.Path == "github.com/xtls/libxray" {
			if dependency.Version != libXrayModuleVersion {
				t.Fatalf("libXray version = %q, want %q", dependency.Version, libXrayModuleVersion)
			}
			return
		}
	}
	t.Fatal("libXray dependency missing from Go build information")
}

func TestConvertXraySubscriptionPreservesCanonicalOutbound(t *testing.T) {
	link := "vless://" + xrayTestUUID +
		"@edge.example:443?encryption=none&security=tls&sni=edge.example&type=ws&path=%2Fws#Edge"
	result := convertXraySubscription(link)
	if result.Error != "" {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if len(result.Nodes) != 1 {
		t.Fatalf("node count = %d, want 1", len(result.Nodes))
	}
	node := result.Nodes[0]
	if node.Name != "Edge" || node.Protocol != "vless" ||
		node.Server != "edge.example" || node.Port != 443 {
		t.Fatalf("unexpected projection: %+v", node)
	}
	var outbound map[string]any
	if err := json.Unmarshal(node.XrayOutbound, &outbound); err != nil {
		t.Fatalf("canonical outbound is invalid JSON: %v", err)
	}
	if outbound["protocol"] != "vless" || outbound["streamSettings"] == nil {
		t.Fatalf("canonical outbound lost Xray fields: %s", node.XrayOutbound)
	}
	if outbound["sendThrough"] != nil {
		t.Fatalf("display-name metadata leaked into executable outbound: %s", node.XrayOutbound)
	}
}

func TestConvertXraySubscriptionAcceptsBase64AndRejectsInvalid(t *testing.T) {
	link := "vless://" + xrayTestUUID + "@127.0.0.1:8443?encryption=none#Base64"
	encoded := base64.StdEncoding.EncodeToString([]byte(link))
	result := convertXraySubscription(encoded)
	if result.Error != "" || len(result.Nodes) != 1 {
		t.Fatalf("base64 parse failed: %+v", result)
	}

	invalid := convertXraySubscription("not a subscription")
	if invalid.Error == "" || len(invalid.Nodes) != 0 {
		t.Fatalf("invalid input did not fail closed: %+v", invalid)
	}
	secret := "decoded-secret-without-separator"
	malformedSocks := "socks://" +
		base64.StdEncoding.EncodeToString([]byte(secret)) +
		"@127.0.0.1:1080"
	malformed := convertXraySubscription(malformedSocks)
	if malformed.Error == "" || strings.Contains(malformed.Error, secret) {
		t.Fatalf("parser error exposed subscription data: %+v", malformed)
	}

	oversized := convertXraySubscription(strings.Repeat("x", maxXrayInputBytes+1))
	if oversized.Error != "subscription exceeds parser input limit" {
		t.Fatalf("oversized error = %q", oversized.Error)
	}
}

func TestConvertXraySubscriptionProjectsSupportedProtocols(t *testing.T) {
	ssUser := base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:password"))
	cases := []struct {
		name     string
		link     string
		protocol string
		server   string
		port     uint16
	}{
		{"shadowsocks", "ss://" + ssUser + "@127.0.0.1:8388#SS", "shadowsocks", "127.0.0.1", 8388},
		{"socks", "socks://127.0.0.1:1080#SOCKS", "socks", "127.0.0.1", 1080},
		{"trojan", "trojan://password@127.0.0.1:443#Trojan", "trojan", "127.0.0.1", 443},
		{"vless", "vless://" + xrayTestUUID + "@127.0.0.1:8443?encryption=none#VLESS", "vless", "127.0.0.1", 8443},
		{"vmess", "vmess://" + xrayTestUUID + "@127.0.0.1:8080?encryption=auto#VMess", "vmess", "127.0.0.1", 8080},
		{"hysteria2", "hy2://auth@hy2.example:443?sni=hy2.example#Hy2", "hysteria", "hy2.example", 443},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			result := convertXraySubscription(testCase.link)
			if result.Error != "" || len(result.Nodes) != 1 {
				t.Fatalf("parse failed: %+v", result)
			}
			node := result.Nodes[0]
			if node.Protocol != testCase.protocol || node.Server != testCase.server || node.Port != testCase.port {
				t.Fatalf("unexpected projection: %+v", node)
			}
		})
	}
}

func TestConvertXraySubscriptionProjectsCanonicalServerArray(t *testing.T) {
	config := `{"outbounds":[{"tag":"JSON SOCKS","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1081}]}}]}`
	result := convertXraySubscription(config)
	if result.Error != "" || len(result.Nodes) != 1 {
		t.Fatalf("Xray JSON parse failed: %+v", result)
	}
	node := result.Nodes[0]
	if node.Name != "JSON SOCKS" || node.Protocol != "socks" || node.Server != "127.0.0.1" || node.Port != 1081 {
		t.Fatalf("unexpected canonical projection: %+v", node)
	}
}
