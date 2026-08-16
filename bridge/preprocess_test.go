package main

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/cipher"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

const officialMieruStandardURL = "mieru://CpsBCgdkZWZhdWx0ElgKBWJhb3ppEg1tYW5saWFucGVuZmVu" +
	"GkA0MGFiYWM0MGY1OWRhNTVkYWQ2YTk5ODMxYTUxMTY1MjJmYmM4MGUzODVi" +
	"YjFhYjE0ZGM1MmRiMzY4ZjczOGE0Gi8SCWxvY2FsaG9zdBoFCIo0EAIaDRAC" +
	"Ggk5OTk5LTk5OTkaBQjZMhABGgUIoCYQASD4CioCCAQSB2RlZmF1bHQYnUYg" +
	"uAgwBTgA"

func mieruStandardURLForTest(t *testing.T, config *mierupb.ClientConfig) string {
	t.Helper()
	payload, err := proto.Marshal(config)
	if err != nil {
		t.Fatalf("marshal Mieru fixture: %v", err)
	}
	return mieruStandardPrefix + base64.StdEncoding.EncodeToString(payload)
}

func validMieruClientConfigForTest() *mierupb.ClientConfig {
	return &mierupb.ClientConfig{
		Profiles: []*mierupb.ClientProfile{
			{
				ProfileName: proto.String("default"),
				User: &mierupb.User{
					Name:     proto.String("user"),
					Password: proto.String("password"),
				},
				Servers: []*mierupb.ServerEndpoint{
					{
						DomainName: proto.String("mieru.example.test"),
						PortBindings: []*mierupb.PortBinding{
							{
								Port:     proto.Int32(443),
								Protocol: mierupb.TransportProtocol_TCP.Enum(),
							},
						},
					},
				},
				Mtu: proto.Int32(1400),
			},
		},
		ActiveProfile: proto.String("default"),
	}
}

func enumContainerDescriptorForTest(t *testing.T) protoreflect.MessageDescriptor {
	t.Helper()
	optional := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	repeated := descriptorpb.FieldDescriptorProto_LABEL_REPEATED
	enumType := descriptorpb.FieldDescriptorProto_TYPE_ENUM
	messageType := descriptorpb.FieldDescriptorProto_TYPE_MESSAGE
	stringType := descriptorpb.FieldDescriptorProto_TYPE_STRING
	mapEntry := true
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Syntax:  proto.String("proto3"),
		Name:    proto.String("mieru_enum_audit.proto"),
		Package: proto.String("mieruaudit"),
		EnumType: []*descriptorpb.EnumDescriptorProto{
			{
				Name: proto.String("Mode"),
				Value: []*descriptorpb.EnumValueDescriptorProto{
					{Name: proto.String("MODE_DEFAULT"), Number: proto.Int32(0)},
					{Name: proto.String("MODE_ENABLED"), Number: proto.Int32(1)},
				},
			},
		},
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: proto.String("EnumContainer"),
				NestedType: []*descriptorpb.DescriptorProto{
					{
						Name:    proto.String("ModesEntry"),
						Options: &descriptorpb.MessageOptions{MapEntry: &mapEntry},
						Field: []*descriptorpb.FieldDescriptorProto{
							{Name: proto.String("key"), Number: proto.Int32(1), Label: &optional, Type: &stringType},
							{Name: proto.String("value"), Number: proto.Int32(2), Label: &optional, Type: &enumType, TypeName: proto.String(".mieruaudit.Mode")},
						},
					},
				},
				Field: []*descriptorpb.FieldDescriptorProto{
					{Name: proto.String("single"), Number: proto.Int32(1), Label: &optional, Type: &enumType, TypeName: proto.String(".mieruaudit.Mode")},
					{Name: proto.String("list"), Number: proto.Int32(2), Label: &repeated, Type: &enumType, TypeName: proto.String(".mieruaudit.Mode")},
					{Name: proto.String("modes"), Number: proto.Int32(3), Label: &repeated, Type: &messageType, TypeName: proto.String(".mieruaudit.EnumContainer.ModesEntry")},
				},
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("construct enum audit descriptor: %v", err)
	}
	return file.Messages().ByName("EnumContainer")
}

func TestMessageHasUnknownFieldsRejectsUnknownEnumValues(t *testing.T) {
	descriptor := enumContainerDescriptorForTest(t)
	singleField := descriptor.Fields().ByName("single")
	listField := descriptor.Fields().ByName("list")
	mapField := descriptor.Fields().ByName("modes")

	tests := map[string]func(protoreflect.Message){
		"singular": func(message protoreflect.Message) {
			message.Set(singleField, protoreflect.ValueOfEnum(99))
		},
		"list": func(message protoreflect.Message) {
			message.Mutable(listField).List().Append(protoreflect.ValueOfEnum(99))
		},
		"map": func(message protoreflect.Message) {
			message.Mutable(mapField).Map().Set(
				protoreflect.ValueOfString("future").MapKey(),
				protoreflect.ValueOfEnum(99),
			)
		},
	}

	for name, populate := range tests {
		t.Run(name, func(t *testing.T) {
			message := dynamicpb.NewMessage(descriptor).ProtoReflect()
			populate(message)
			if !messageHasUnknownFields(message) {
				t.Fatal("unknown enum value was accepted")
			}
		})
	}

	known := dynamicpb.NewMessage(descriptor).ProtoReflect()
	known.Set(singleField, protoreflect.ValueOfEnum(1))
	known.Mutable(listField).List().Append(protoreflect.ValueOfEnum(1))
	known.Mutable(mapField).Map().Set(
		protoreflect.ValueOfString("known").MapKey(),
		protoreflect.ValueOfEnum(1),
	)
	if messageHasUnknownFields(known) {
		t.Fatal("known enum values were rejected")
	}
}

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

func TestParseRealityWithoutShortIDKeepsEmptyScalar(t *testing.T) {
	input := "vless://22222222-2222-4222-8222-222222222222@reality.example.test:443" +
		"?encryption=none&security=reality&flow=xtls-rprx-vision&type=tcp" +
		"&sni=www.amazon.nl" +
		"&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
		"&fp=chrome#RealityWithoutSid"

	proxies, err := parseSubscriptionWithMihomo(input)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(proxies) != 1 {
		t.Fatalf("got %d proxies: %#v", len(proxies), proxies)
	}
	realityOptions, ok := proxies[0]["reality-opts"].(map[string]any)
	if !ok {
		t.Fatalf("Reality options lost their object type: %#v", proxies[0]["reality-opts"])
	}
	shortID, ok := realityOptions["short-id"].(string)
	if !ok || shortID != "" {
		t.Fatalf("empty Reality short-id was not preserved: %#v", realityOptions["short-id"])
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

func TestParseRejectsMissingRequiredNativeMihomoField(t *testing.T) {
	input := strings.Join([]string{
		"proxies:",
		"  - name: MissingServer",
		"    type: ss",
		"    port: 8388",
		"    cipher: aes-128-gcm",
		"    password: password",
	}, "\n")

	if _, err := parseSubscriptionWithMihomo(input); err == nil ||
		!strings.Contains(err.Error(), "missing server") {
		t.Fatalf("expected missing server error, got %v", err)
	}
}

func TestParseRejectsInvalidNativeMihomoFieldType(t *testing.T) {
	input := strings.Join([]string{
		"proxies:",
		"  - name: InvalidPort",
		"    type: ss",
		"    server: invalid.example.com",
		"    port: not-a-port",
		"    cipher: aes-128-gcm",
		"    password: password",
	}, "\n")

	if _, err := parseSubscriptionWithMihomo(input); err == nil ||
		!strings.Contains(err.Error(), "port must be int") {
		t.Fatalf("expected invalid port type error, got %v", err)
	}
}

func TestParseAllowsOmittedZeroValueOptions(t *testing.T) {
	input := strings.Join([]string{
		"proxies:",
		"  - name: MinimalVMess",
		"    type: vmess",
		"    server: example.com",
		"    port: 443",
		"    uuid: 00000000-0000-0000-0000-000000000001",
	}, "\n")

	proxies, err := parseSubscriptionWithMihomo(input)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(proxies) != 1 || proxies[0]["name"] != "MinimalVMess" {
		t.Fatalf("unexpected proxies: %#v", proxies)
	}
}

func TestGeneratedProxyRulesCoverRepresentativeProtocols(t *testing.T) {
	for _, proxyType := range []string{
		"ss", "vmess", "vless", "trojan", "hysteria2", "tuic", "wireguard",
	} {
		if _, ok := generatedProxyRules[proxyType]; !ok {
			t.Fatalf("generated rules do not contain %q", proxyType)
		}
	}

	wireGuardRules := generatedProxyRules["wireguard"]
	if wireGuardRules["server"].required || wireGuardRules["port"].required {
		t.Fatal("wireguard peer mode must not require top-level server or port")
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

func TestParseOfficialMieruStandardURL(t *testing.T) {
	proxies, err := parseSubscriptionWithMihomo(officialMieruStandardURL)
	if err != nil {
		t.Fatalf("parse official standard Mieru URL: %v", err)
	}
	if len(proxies) != 4 {
		t.Fatalf("got %d Mieru proxies, want 4: %#v", len(proxies), proxies)
	}

	expected := []struct {
		name      string
		port      any
		portRange any
		transport string
	}{
		{name: "default-1:6666/TCP", port: 6666, transport: "TCP"},
		{name: "default-1:9999-9999/TCP", portRange: "9999-9999", transport: "TCP"},
		{name: "default-1:6489/UDP", port: 6489, transport: "UDP"},
		{name: "default-1:4896/UDP", port: 4896, transport: "UDP"},
	}
	for i, want := range expected {
		proxy := proxies[i]
		if proxy["name"] != want.name || proxy["type"] != "mieru" ||
			proxy["server"] != "localhost" || proxy["transport"] != want.transport ||
			proxy["username"] != "baozi" || proxy["password"] != "manlianpenfen" ||
			proxy["multiplexing"] != "MULTIPLEXING_HIGH" {
			t.Fatalf("Mieru proxy %d drifted: %#v", i, proxy)
		}
		if want.port != nil && proxy["port"] != want.port {
			t.Fatalf("Mieru proxy %d port = %#v, want %#v", i, proxy["port"], want.port)
		}
		if want.portRange != nil && proxy["port-range"] != want.portRange {
			t.Fatalf("Mieru proxy %d port-range = %#v, want %#v", i, proxy["port-range"], want.portRange)
		}
	}
}

func TestMieruStandardProjectsAllProfilesServersAndBindings(t *testing.T) {
	config := validMieruClientConfigForTest()
	config.Profiles[0].User.Name = proto.String("user+name@example.test")
	config.Profiles[0].User.Password = proto.String("p+#@/?%word")
	config.Profiles[0].Multiplexing = &mierupb.MultiplexingConfig{
		Level: mierupb.MultiplexingLevel_MULTIPLEXING_DEFAULT.Enum(),
	}
	config.Profiles[0].HandshakeMode = mierupb.HandshakeMode_HANDSHAKE_DEFAULT.Enum()
	config.Profiles[0].Servers = append(config.Profiles[0].Servers,
		&mierupb.ServerEndpoint{
			IpAddress: proto.String("2001:db8::20"),
			PortBindings: []*mierupb.PortBinding{
				{
					PortRange: proto.String("8000-8002"),
					Protocol:  mierupb.TransportProtocol_UDP.Enum(),
				},
			},
		})
	config.Profiles = append(config.Profiles, &mierupb.ClientProfile{
		ProfileName: proto.String("backup"),
		User: &mierupb.User{
			Name:     proto.String("backup-user"),
			Password: proto.String("backup-password"),
		},
		Servers: []*mierupb.ServerEndpoint{
			{
				IpAddress:  proto.String("192.0.2.20"),
				DomainName: proto.String("preferred.example.test"),
				PortBindings: []*mierupb.PortBinding{
					{
						Port:     proto.Int32(8443),
						Protocol: mierupb.TransportProtocol_TCP.Enum(),
					},
				},
			},
		},
	})

	proxies, err := parseSubscriptionWithMihomo(mieruStandardURLForTest(t, config))
	if err != nil {
		t.Fatalf("parse multi-profile standard Mieru URL: %v", err)
	}
	if len(proxies) != 3 {
		t.Fatalf("got %d Mieru proxies, want 3: %#v", len(proxies), proxies)
	}
	if proxies[0]["multiplexing"] != "MULTIPLEXING_DEFAULT" ||
		proxies[0]["handshake-mode"] != "HANDSHAKE_DEFAULT" ||
		proxies[0]["username"] != "user+name@example.test" ||
		proxies[0]["password"] != "p+#@/?%word" {
		t.Fatalf("explicit official defaults were not preserved: %#v", proxies[0])
	}
	if proxies[1]["server"] != "2001:db8::20" || proxies[1]["port-range"] != "8000-8002" {
		t.Fatalf("IPv6/range Mieru endpoint drifted: %#v", proxies[1])
	}
	if proxies[2]["server"] != "preferred.example.test" {
		t.Fatalf("Mieru domain did not take precedence over IP: %#v", proxies[2])
	}
}

func TestMieruStandardInsideBase64Subscription(t *testing.T) {
	wrapped := base64.StdEncoding.EncodeToString([]byte(mieruStandardURLForTest(t, validMieruClientConfigForTest()) + "\r\n"))
	proxies, err := parseSubscriptionWithMihomo(wrapped)
	if err != nil {
		t.Fatalf("parse Base64-wrapped standard Mieru URL: %v", err)
	}
	if len(proxies) != 1 {
		t.Fatalf("got %d Base64-wrapped Mieru proxies, want 1: %#v", len(proxies), proxies)
	}
}

func TestMieruStandardBase64PlusSurvivesPreprocess(t *testing.T) {
	config := validMieruClientConfigForTest()
	link := ""
	password := ""
	for r := rune(0x80); r < 0x1000; r++ {
		password = "password-" + string(r)
		config.Profiles[0].User.Password = proto.String(password)
		candidate := mieruStandardURLForTest(t, config)
		if strings.Contains(strings.TrimPrefix(candidate, mieruStandardPrefix), "+") {
			link = candidate
			break
		}
	}
	if link == "" {
		t.Fatal("failed to construct a canonical Mieru protobuf Base64 payload containing '+'")
	}

	proxies, err := parseSubscriptionWithMihomo(link)
	if err != nil {
		t.Fatalf("parse standard Mieru URL containing '+': %v", err)
	}
	if len(proxies) != 1 || proxies[0]["password"] != password {
		t.Fatalf("Base64 '+' or decoded password was changed: %#v", proxies)
	}
}

func TestMieruStandardRejectsUnsupportedConfigAtomically(t *testing.T) {
	tests := map[string]func(*mierupb.ClientConfig){
		"non-default MTU": func(config *mierupb.ClientConfig) {
			config.Profiles[0].Mtu = proto.Int32(1280)
		},
		"profile dialer": func(config *mierupb.ClientConfig) {
			config.Profiles[0].Dialer = &mierupb.ClientDialer{
				Protocol: mierupb.ProxyProtocol_SOCKS5_PROXY_PROTOCOL.Enum(),
				Host:     proto.String("dialer.example.test"),
				Port:     proto.Int32(1080),
			}
		},
		"hashed password only": func(config *mierupb.ClientConfig) {
			config.Profiles[0].User.Password = nil
			config.Profiles[0].User.HashedPassword = proto.String(strings.Repeat("0", 64))
		},
		"mismatched plaintext and hashed password": func(config *mierupb.ClientConfig) {
			config.Profiles[0].User.HashedPassword = proto.String(strings.Repeat("0", 64))
		},
		"malformed hashed password": func(config *mierupb.ClientConfig) {
			config.Profiles[0].User.HashedPassword = proto.String("not-hex")
		},
		"invalid traffic pattern": func(config *mierupb.ClientConfig) {
			config.Profiles[0].TrafficPattern = &mierupb.TrafficPattern{
				TcpFragment: &mierupb.TCPFragment{MaxSleepMs: proto.Int32(101)},
			}
		},
		"future traffic pattern field": func(config *mierupb.ClientConfig) {
			config.Profiles[0].TrafficPattern = &mierupb.TrafficPattern{}
			// Field 6 became the supported lowEntropy option in mieru v3.35.0.
			// Keep exercising fail-closed handling with an unassigned field number.
			config.Profiles[0].TrafficPattern.ProtoReflect().SetUnknown([]byte{0xFA, 0x07, 0x02, 0x08, 0x01})
		},
		"unknown traffic pattern enum": func(config *mierupb.ClientConfig) {
			config.Profiles[0].TrafficPattern = &mierupb.TrafficPattern{
				Nonce: &mierupb.NoncePattern{Type: mierupb.NonceType(99).Enum()},
			}
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := validMieruClientConfigForTest()
			mutate(config)
			link := mieruStandardURLForTest(t, config)
			if links, err := expandMieruStandardURL(link); err == nil || len(links) != 0 {
				t.Fatalf("unsupported standard Mieru config expanded: links=%q err=%v", links, err)
			}
		})
	}
}

func TestMieruStandardAcceptsEquivalentPlaintextAndHash(t *testing.T) {
	config := validMieruClientConfigForTest()
	user := config.Profiles[0].User
	user.HashedPassword = proto.String(hex.EncodeToString(cipher.HashPassword([]byte(user.GetPassword()), []byte(user.GetName()))))
	if links, err := expandMieruStandardURL(mieruStandardURLForTest(t, config)); err != nil || len(links) != 1 {
		t.Fatalf("equivalent Mieru plaintext/hash rejected: links=%q err=%v", links, err)
	}
}

func TestMieruStandardInvalidLinkDoesNotPoisonMixedSubscription(t *testing.T) {
	input := strings.Join([]string{
		"mieru://AQIDBA==",
		"ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:8388#ValidSS",
	}, "\n")
	proxies, err := parseSubscriptionWithMihomo(input)
	if err != nil {
		t.Fatalf("mixed subscription failed: %v", err)
	}
	if len(proxies) != 1 || proxies[0]["name"] != "ValidSS" || proxies[0]["type"] != "ss" {
		t.Fatalf("invalid Mieru URI affected the independent node: %#v", proxies)
	}
}

func TestMieruExpansionLeavesUnrelatedInputByteForByte(t *testing.T) {
	input := "proxies:\r\n  - name: untouched  \r\n"
	if got := expandMieruStandardSubscription(input); got != input {
		t.Fatalf("unrelated input changed:\nwant %q\n got %q", input, got)
	}
}
