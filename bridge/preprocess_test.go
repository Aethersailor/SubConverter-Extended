package main

import (
	"strings"
	"testing"

	"github.com/metacubex/mihomo/common/convert"
)

func TestPreprocessLegacyShadowrocketVmess(t *testing.T) {
	input := strings.Join([]string{
		"vmess://YXV0bzowNmNlNzU4Yy1iNTNkLTQ2NzQtOTdhNy01M2U4YmFhOGQwMjlAMjE2LjE0NC4yMjQuNjk6MzMwNg?remarks=%E7%BE%8E%E5%9B%BD%E8%87%AA%E5%BB%BA&path=/&obfs=none&alterId=0",
		"vmess://YXV0bzpmMmJiMmE4ZC02YWM0LTQ3NGYtYjJlYS1lMjJjNzhlYjkwMGZAMTI5LjE1MS4yNS4xOjE4MjU?remarks=US-O&udp=1&alterId=0",
	}, "\n")

	proxies, err := convert.ConvertsV2Ray([]byte(preprocessSubscription(input)))
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
