package main

import (
	"strings"
	"testing"
)

func TestPreprocessLegacyShadowrocketVmess(t *testing.T) {
	input := strings.Join([]string{
		"vmess://YXV0bzowNmNlNzU4Yy1iNTNkLTQ2NzQtOTdhNy01M2U4YmFhOGQwMjlAMjE2LjE0NC4yMjQuNjk6MzMwNg?remarks=%E7%BE%8E%E5%9B%BD%E8%87%AA%E5%BB%BA&path=/&obfs=none&alterId=0",
		"vmess://YXV0bzpmMmJiMmE4ZC02YWM0LTQ3NGYtYjJlYS1lMjJjNzhlYjkwMGZAMTI5LjE1MS4yNS4xOjE4MjU?remarks=US-O&udp=1&alterId=0",
	}, "\n")

	proxies, err := parseSubscriptionWithMihomo(input)
	if err != nil {
		t.Fatalf("convert error: %v", err)
	}
	if len(proxies) != 2 {
		t.Fatalf("got %d proxies: %#v", len(proxies), proxies)
	}

	first := proxies[0]
	if first["type"] != "vmess" {
		t.Fatalf("unexpected first type: %#v", first["type"])
	}
	if first["name"] != "美国自建" {
		t.Fatalf("unexpected first name: %#v", first["name"])
	}
	if first["server"] != "216.144.224.69" {
		t.Fatalf("unexpected first server: %#v", first["server"])
	}
	if first["port"] != "3306" {
		t.Fatalf("unexpected first port: %#v", first["port"])
	}
	if first["uuid"] != "06ce758c-b53d-4674-97a7-53e8baa8d029" {
		t.Fatalf("unexpected first uuid: %#v", first["uuid"])
	}

	second := proxies[1]
	if second["server"] != "129.151.25.1" {
		t.Fatalf("unexpected second server: %#v", second["server"])
	}
	if second["port"] != "1825" {
		t.Fatalf("unexpected second port: %#v", second["port"])
	}
}

func TestPreprocessKeepsStandardVmess(t *testing.T) {
	input := "vmess://uuid@example.com:443?encryption=auto#name"
	if got := preprocessSubscription(input); got != input {
		t.Fatalf("standard vmess changed:\nwant %q\n got %q", input, got)
	}
}

func TestParseNativeMihomoProviderYAML(t *testing.T) {
	input := strings.Join([]string{
		"proxies:",
		"  - name: NativeYAML",
		"    type: ss",
		"    server: yaml.example.com",
		"    port: 8388",
		"    cipher: aes-128-gcm",
		"    password: password",
		"    udp: true",
	}, "\n")

	proxies, err := parseSubscriptionWithMihomo(input)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(proxies) != 1 {
		t.Fatalf("got %d proxies: %#v", len(proxies), proxies)
	}
	if proxies[0]["name"] != "NativeYAML" {
		t.Fatalf("unexpected name: %#v", proxies[0]["name"])
	}
	if proxies[0]["port"] != 8388 {
		t.Fatalf("port type or value was not preserved: %#v", proxies[0]["port"])
	}
	if proxies[0]["udp"] != true {
		t.Fatalf("boolean type or value was not preserved: %#v", proxies[0]["udp"])
	}
}

func TestParseRejectsInvalidNativeMihomoProxy(t *testing.T) {
	input := strings.Join([]string{
		"proxies:",
		"  - name: Invalid",
		"    type: unsupported-protocol",
		"    server: invalid.example.com",
		"    port: 443",
	}, "\n")

	if _, err := parseSubscriptionWithMihomo(input); err == nil {
		t.Fatal("expected Mihomo to reject an unsupported proxy type")
	}
}

func TestParseDeduplicatesNamesLikeMihomoProvider(t *testing.T) {
	input := strings.Join([]string{
		"proxies:",
		"  - name: Duplicate",
		"    type: ss",
		"    server: first.example.com",
		"    port: 8388",
		"    cipher: aes-128-gcm",
		"    password: password",
		"  - name: Duplicate",
		"    type: ss",
		"    server: second.example.com",
		"    port: 8388",
		"    cipher: aes-128-gcm",
		"    password: password",
	}, "\n")

	proxies, err := parseSubscriptionWithMihomo(input)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(proxies) != 1 {
		t.Fatalf("got %d proxies: %#v", len(proxies), proxies)
	}
	if proxies[0]["server"] != "first.example.com" {
		t.Fatalf("unexpected duplicate selection: %#v", proxies[0]["server"])
	}
}
