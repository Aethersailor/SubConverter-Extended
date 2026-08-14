package main

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/enfein/mieru/v3/apis/trafficpattern"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/cipher"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	mieruStandardPrefix       = "mieru://"
	maxMieruStandardEncoded   = 1 << 20
	maxMieruStandardDecoded   = 768 << 10
	maxMieruProfiles          = 256
	maxMieruServersPerProfile = 256
	maxMieruBindingsPerServer = 256
	maxMieruExpandedLinks     = 16384
)

// expandMieruStandardSubscription replaces official binary mieru:// links
// with the official simple-link projection already understood by Mihomo. It
// deliberately returns the input byte-for-byte when no complete mieru:// line
// is present.
func expandMieruStandardSubscription(subscription string) string {
	if !containsMieruStandardLine(subscription) {
		if decoded, ok := decodeLooseBase64(subscription); ok && containsMieruStandardLine(decoded) {
			subscription = decoded
		} else {
			return subscription
		}
	}

	lines := strings.Split(subscription, "\n")
	expanded := make([]string, 0, len(lines))
	for _, line := range lines {
		candidate := strings.TrimRight(line, " \r")
		if !strings.HasPrefix(candidate, mieruStandardPrefix) {
			expanded = append(expanded, line)
			continue
		}

		links, err := expandMieruStandardURL(candidate)
		if err != nil {
			// A standard URI is atomic: never retain a partially decoded profile.
			// Mihomo skips malformed individual links, so omit only this link while
			// preserving independent entries in a mixed subscription.
			continue
		}
		expanded = append(expanded, links...)
	}
	return strings.Join(expanded, "\n")
}

func containsMieruStandardLine(subscription string) bool {
	for _, line := range strings.Split(subscription, "\n") {
		if strings.HasPrefix(line, mieruStandardPrefix) {
			return true
		}
	}
	return false
}

func expandMieruStandardURL(link string) ([]string, error) {
	if !strings.HasPrefix(link, mieruStandardPrefix) {
		return nil, errors.New("not a standard Mieru URI")
	}
	encoded := strings.TrimPrefix(link, mieruStandardPrefix)
	if encoded == "" || len(encoded) > maxMieruStandardEncoded {
		return nil, errors.New("invalid standard Mieru payload size")
	}

	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) == 0 || len(decoded) > maxMieruStandardDecoded {
		return nil, errors.New("invalid standard Mieru payload")
	}

	config := &mierupb.ClientConfig{}
	if err := proto.Unmarshal(decoded, config); err != nil {
		return nil, errors.New("invalid standard Mieru protobuf")
	}
	if messageHasUnknownFields(config.ProtoReflect()) {
		return nil, errors.New("unsupported standard Mieru protobuf fields")
	}
	return projectMieruClientConfig(config)
}

func projectMieruClientConfig(config *mierupb.ClientConfig) ([]string, error) {
	profiles := config.GetProfiles()
	if len(profiles) == 0 || len(profiles) > maxMieruProfiles {
		return nil, errors.New("invalid Mieru profile count")
	}
	if !knownLoggingLevel(config.GetLoggingLevel()) {
		return nil, errors.New("unsupported Mieru logging level")
	}

	profileNames := make(map[string]struct{}, len(profiles))
	projected := make([]string, 0, len(profiles))
	expandedEndpoints := 0
	for _, profile := range profiles {
		links, endpoints, err := projectMieruProfile(profile, profileNames)
		if err != nil {
			return nil, err
		}
		if expandedEndpoints > maxMieruExpandedLinks-endpoints {
			return nil, errors.New("too many expanded Mieru endpoints")
		}
		expandedEndpoints += endpoints
		projected = append(projected, links...)
	}

	if active := config.GetActiveProfile(); active != "" {
		if _, found := profileNames[active]; !found {
			return nil, errors.New("Mieru active profile is unavailable")
		}
	}
	if len(projected) == 0 {
		return nil, errors.New("standard Mieru URI has no endpoint")
	}
	return projected, nil
}

func projectMieruProfile(profile *mierupb.ClientProfile, profileNames map[string]struct{}) ([]string, int, error) {
	if profile == nil || profile.GetProfileName() == "" || !utf8.ValidString(profile.GetProfileName()) || hasControlCharacter(profile.GetProfileName()) || len(profile.GetProfileName()) > 256 {
		return nil, 0, errors.New("invalid Mieru profile name")
	}
	if _, exists := profileNames[profile.GetProfileName()]; exists {
		return nil, 0, errors.New("duplicate Mieru profile name")
	}
	profileNames[profile.GetProfileName()] = struct{}{}

	user := profile.GetUser()
	if user == nil || user.GetName() == "" || user.GetPassword() == "" || len(user.GetName()) > 64 || len(user.GetPassword()) > 64 || !utf8.ValidString(user.GetName()) || !utf8.ValidString(user.GetPassword()) || hasControlCharacter(user.GetName()) || hasControlCharacter(user.GetPassword()) {
		return nil, 0, errors.New("invalid Mieru profile credentials")
	}
	if encodedHash := user.GetHashedPassword(); encodedHash != "" {
		storedHash, err := hex.DecodeString(encodedHash)
		if err != nil || len(storedHash) != 32 {
			return nil, 0, errors.New("invalid Mieru hashed password")
		}
		derivedHash := cipher.HashPassword([]byte(user.GetPassword()), []byte(user.GetName()))
		if subtle.ConstantTimeCompare(storedHash, derivedHash) != 1 {
			return nil, 0, errors.New("Mieru hashed password does not match plaintext credentials")
		}
	}
	if len(user.GetQuotas()) != 0 {
		return nil, 0, errors.New("unsupported Mieru client quota")
	}
	if profile.GetDialer() != nil {
		return nil, 0, errors.New("unsupported Mieru profile dialer")
	}
	if profile.Mtu != nil && profile.GetMtu() != 0 && profile.GetMtu() != 1400 {
		return nil, 0, errors.New("unsupported Mieru MTU")
	}

	multiplexing := ""
	if profile.GetMultiplexing() != nil && profile.GetMultiplexing().Level != nil {
		if !knownMieruMultiplexing(profile.GetMultiplexing().GetLevel()) {
			return nil, 0, errors.New("unsupported Mieru multiplexing level")
		}
		multiplexing = profile.GetMultiplexing().GetLevel().String()
	}
	handshakeMode := ""
	if profile.HandshakeMode != nil {
		if !knownMieruHandshakeMode(profile.GetHandshakeMode()) {
			return nil, 0, errors.New("unsupported Mieru handshake mode")
		}
		handshakeMode = profile.GetHandshakeMode().String()
	}

	trafficPattern := ""
	if pattern := profile.GetTrafficPattern(); pattern != nil {
		if err := trafficpattern.Validate(pattern); err != nil {
			return nil, 0, errors.New("invalid Mieru traffic pattern")
		}
		encoded, err := proto.Marshal(pattern)
		if err != nil {
			return nil, 0, errors.New("failed to encode Mieru traffic pattern")
		}
		if len(encoded) != 0 {
			trafficPattern = base64.StdEncoding.EncodeToString(encoded)
		}
	}

	servers := profile.GetServers()
	if len(servers) == 0 || len(servers) > maxMieruServersPerProfile {
		return nil, 0, errors.New("invalid Mieru server count")
	}
	links := make([]string, 0, len(servers))
	expandedEndpoints := 0
	for serverIndex, server := range servers {
		link, err := projectMieruServer(profile.GetProfileName(), serverIndex, user.GetName(), user.GetPassword(), multiplexing, handshakeMode, trafficPattern, server)
		if err != nil {
			return nil, 0, err
		}
		expandedEndpoints += len(server.GetPortBindings())
		links = append(links, link)
	}
	return links, expandedEndpoints, nil
}

func projectMieruServer(profileName string, serverIndex int, username, password, multiplexing, handshakeMode, trafficPattern string, server *mierupb.ServerEndpoint) (string, error) {
	if server == nil {
		return "", errors.New("invalid Mieru server")
	}
	if server.GetIpAddress() != "" && net.ParseIP(server.GetIpAddress()) == nil {
		return "", errors.New("invalid Mieru server IP address")
	}
	host := server.GetDomainName()
	if host != "" {
		if !validMieruDomain(host) {
			return "", errors.New("invalid Mieru server domain")
		}
	} else {
		host = server.GetIpAddress()
		if net.ParseIP(host) == nil {
			return "", errors.New("invalid Mieru server IP address")
		}
	}

	bindings := server.GetPortBindings()
	if len(bindings) == 0 || len(bindings) > maxMieruBindingsPerServer {
		return "", errors.New("invalid Mieru port binding count")
	}
	query := url.Values{}
	query.Add("profile", profileName)
	if multiplexing != "" {
		query.Add("multiplexing", multiplexing)
	}
	if handshakeMode != "" {
		query.Add("handshake-mode", handshakeMode)
	}
	if trafficPattern != "" {
		query.Add("traffic-pattern", trafficPattern)
	}
	for _, binding := range bindings {
		port, protocol, err := projectMieruPortBinding(binding)
		if err != nil {
			return "", err
		}
		query.Add("port", port)
		query.Add("protocol", protocol)
	}

	uriHost := host
	if net.ParseIP(host) != nil && strings.Contains(host, ":") {
		uriHost = "[" + host + "]"
	}
	u := &url.URL{
		Scheme:   "mierus",
		User:     url.UserPassword(username, password),
		Host:     uriHost,
		RawQuery: query.Encode(),
		Fragment: profileName + "-" + strconv.Itoa(serverIndex+1),
	}
	return u.String(), nil
}

func projectMieruPortBinding(binding *mierupb.PortBinding) (string, string, error) {
	if binding == nil || binding.Protocol == nil || !knownMieruTransport(binding.GetProtocol()) {
		return "", "", errors.New("invalid Mieru transport protocol")
	}
	if (binding.Port == nil) == (binding.PortRange == nil) {
		return "", "", errors.New("invalid Mieru port binding")
	}
	if binding.Port != nil {
		port := binding.GetPort()
		if port < 1 || port > 65535 {
			return "", "", errors.New("invalid Mieru port")
		}
		return strconv.Itoa(int(port)), binding.GetProtocol().String(), nil
	}

	parts := strings.Split(binding.GetPortRange(), "-")
	if len(parts) != 2 {
		return "", "", errors.New("invalid Mieru port range")
	}
	first, err1 := strconv.Atoi(parts[0])
	last, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || first < 1 || last > 65535 || first > last {
		return "", "", errors.New("invalid Mieru port range")
	}
	return strconv.Itoa(first) + "-" + strconv.Itoa(last), binding.GetProtocol().String(), nil
}

func validMieruDomain(host string) bool {
	if host == "" || len(host) > 253 || !utf8.ValidString(host) || net.ParseIP(host) != nil {
		return false
	}
	for _, r := range host {
		if r <= 0x20 || r == 0x7f || strings.ContainsRune("/?#@[]:", r) {
			return false
		}
	}
	return true
}

func hasControlCharacter(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func messageHasUnknownFields(message protoreflect.Message) bool {
	if !message.IsValid() || len(message.GetUnknown()) != 0 {
		return true
	}
	hasUnknown := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.IsMap() {
			value.Map().Range(func(_ protoreflect.MapKey, mapValue protoreflect.Value) bool {
				if protobufValueHasUnknownFields(field.MapValue(), mapValue) {
					hasUnknown = true
					return false
				}
				return true
			})
			return !hasUnknown
		}
		if field.IsList() {
			list := value.List()
			for i := 0; i < list.Len(); i++ {
				if protobufValueHasUnknownFields(field, list.Get(i)) {
					hasUnknown = true
					return false
				}
			}
			return !hasUnknown
		}
		hasUnknown = protobufValueHasUnknownFields(field, value)
		return !hasUnknown
	})
	return hasUnknown
}

func protobufValueHasUnknownFields(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
	switch field.Kind() {
	case protoreflect.EnumKind:
		return field.Enum().Values().ByNumber(value.Enum()) == nil
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return messageHasUnknownFields(value.Message())
	default:
		return false
	}
}

func knownMieruMultiplexing(value mierupb.MultiplexingLevel) bool {
	_, ok := mierupb.MultiplexingLevel_name[int32(value)]
	return ok
}

func knownMieruHandshakeMode(value mierupb.HandshakeMode) bool {
	_, ok := mierupb.HandshakeMode_name[int32(value)]
	return ok
}

func knownMieruTransport(value mierupb.TransportProtocol) bool {
	return value == mierupb.TransportProtocol_TCP || value == mierupb.TransportProtocol_UDP
}

func knownLoggingLevel(value mierupb.LoggingLevel) bool {
	_, ok := mierupb.LoggingLevel_name[int32(value)]
	return ok
}
