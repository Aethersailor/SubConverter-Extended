package main

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

// preprocessSubscription fixes URL encoding issues and legacy share links before
// the subscription is handed to mihomo's parser.
func preprocessSubscription(subscription string) string {
	lines := strings.Split(subscription, "\n")
	result := make([]string, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimRight(line, " \r")
		if line == "" {
			result = append(result, line)
			continue
		}
		// Only unwrap a fully URL-encoded link. Ordinary URIs must retain
		// their '+', escaped credentials and query delimiters for Mihomo.
		if !strings.Contains(line, "://") {
			if decoded, err := url.QueryUnescape(line); err == nil && strings.Contains(decoded, "://") {
				line = decoded
			}
		}

		line = normalizeSubscriptionUserinfo(line)
		line = normalizeLegacyShadowrocketVMess(line)
		result = append(result, line)
	}

	return strings.Join(result, "\n")
}

// Normalize only userinfo. URI queries and escaped plaintext passwords must
// remain untouched, and failed Base64 decodes must never supply partial secrets.
func normalizeSubscriptionUserinfo(line string) string {
	scheme, body, found := strings.Cut(line, "://")
	if !found || (!strings.EqualFold(scheme, "ss") && !strings.EqualFold(scheme, "tuic")) {
		return line
	}
	authority := body
	if end := strings.IndexAny(authority, "?#"); end >= 0 {
		authority = authority[:end]
	}
	at := strings.LastIndexByte(authority, '@')
	if at < 0 {
		return line
	}
	userinfo := authority[:at]
	if strings.Contains(userinfo, ":") {
		return line
	}
	if strings.Contains(userinfo, "%") {
		colon := strings.Index(strings.ToLower(userinfo), "%3a")
		if colon >= 0 {
			return scheme + "://" + userinfo[:colon] + ":" + userinfo[colon+3:] + body[at:]
		}
		var err error
		userinfo, err = url.PathUnescape(userinfo)
		if err != nil {
			return ""
		}
	}
	if !strings.EqualFold(scheme, "ss") {
		return line
	}
	// Validate the grammar once. Keep the forms Mihomo already decodes
	// correctly on its normal path, without decoding them twice.
	standardAlphabet, urlsafeAlphabet, padding := false, false, 0
	for i := 0; i < len(userinfo); i++ {
		ch := userinfo[i]
		if ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' ||
			ch >= '0' && ch <= '9' {
			continue
		}
		switch ch {
		case '+', '/':
			standardAlphabet = true
		case '-', '_':
			urlsafeAlphabet = true
		case '=':
			padding = len(userinfo) - i
			if padding > 2 || len(userinfo)%4 != 0 || strings.Trim(userinfo[i:], "=") != "" {
				return ""
			}
		default:
			return ""
		}
		if padding > 0 {
			break
		}
	}
	if standardAlphabet && urlsafeAlphabet || padding == 0 && len(userinfo)%4 == 1 {
		return ""
	}
	if !standardAlphabet && padding == 0 || !urlsafeAlphabet && padding > 0 {
		return line
	}
	encoding := base64.RawURLEncoding
	if strings.ContainsAny(userinfo, "+/") {
		encoding = base64.RawStdEncoding
	}
	if strings.HasSuffix(userinfo, "=") {
		encoding = encoding.WithPadding(base64.StdPadding)
	}
	decoded, err := encoding.DecodeString(userinfo)
	cipher, password, ok := strings.Cut(string(decoded), ":")
	if err != nil || !ok {
		return ""
	}
	return scheme + "://" + url.UserPassword(cipher, password).String() + body[at:]
}

func normalizeLegacyShadowrocketVMess(line string) string {
	const prefix = "vmess://"
	if !strings.HasPrefix(line, prefix) {
		return line
	}

	body := strings.TrimPrefix(line, prefix)
	queryStart := strings.IndexAny(body, "?-_")
	if queryStart < 0 {
		return line
	}
	if body[queryStart] != '?' {
		// Mihomo expects standard Base64 for VMess JSON payloads. Standard
		// payloads retain the fast path above; only URL-safe ones are decoded.
		if decoded, ok := decodeLooseBase64(body); ok && json.Valid([]byte(decoded)) {
			return prefix + base64.StdEncoding.EncodeToString([]byte(decoded))
		}
		queryStart = strings.IndexByte(body, '?')
		if queryStart < 0 {
			return line
		}
	}

	encoded := body[:queryStart]
	rawQuery := body[queryStart+1:]
	if encoded == "" || rawQuery == "" {
		return line
	}

	decoded, ok := decodeLooseBase64(encoded)
	if !ok {
		return line
	}

	cipher, remainder, ok := strings.Cut(decoded, ":")
	if !ok {
		return line
	}
	uuid, serverPort, ok := strings.Cut(remainder, "@")
	if !ok {
		return line
	}
	server, port, ok := splitHostPortLoose(serverPort)
	if !ok || uuid == "" || server == "" || port == "" {
		return line
	}
	if _, err := strconv.Atoi(port); err != nil {
		return line
	}

	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return line
	}

	aid := firstQueryValue(query, "aid", "alterId")
	if aid == "" {
		aid = "0"
	}

	network := "tcp"
	headerType := "none"
	host := ""
	path := ""
	obfs := strings.ToLower(firstQueryValue(query, "obfs"))
	switch obfs {
	case "websocket", "ws":
		network = "ws"
		host = firstQueryValue(query, "obfsParam", "host", "wsHost")
		path = firstQueryValue(query, "path", "wspath")
	case "":
		if value := firstQueryValue(query, "network", "net", "type"); value != "" {
			network = strings.ToLower(value)
		}
		host = firstQueryValue(query, "wsHost", "host")
		path = firstQueryValue(query, "wspath", "path")
		if value := firstQueryValue(query, "headerType"); value != "" {
			headerType = value
		}
	case "none":
		headerType = "none"
	default:
		headerType = obfs
	}

	tls := ""
	switch strings.ToLower(firstQueryValue(query, "tls", "security")) {
	case "1", "true", "tls":
		tls = "tls"
	}

	remarks := firstQueryValue(query, "remarks", "remark", "name")
	if remarks == "" {
		remarks = server + ":" + port
	}

	values := map[string]string{
		"v":    "2",
		"ps":   remarks,
		"add":  server,
		"port": port,
		"id":   uuid,
		"aid":  aid,
		"scy":  cipher,
		"net":  network,
		"type": headerType,
		"host": host,
		"path": path,
		"tls":  tls,
	}
	if sni := firstQueryValue(query, "sni", "peer"); sni != "" {
		values["sni"] = sni
	}
	if alpn := firstQueryValue(query, "alpn"); alpn != "" {
		values["alpn"] = alpn
	}

	jsonBytes, err := json.Marshal(values)
	if err != nil {
		return line
	}
	return prefix + base64.StdEncoding.EncodeToString(jsonBytes)
}

func decodeLooseBase64(value string) (string, bool) {
	encodings := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			return string(decoded), true
		}
	}
	return "", false
}

func splitHostPortLoose(value string) (string, string, bool) {
	colon := strings.LastIndexByte(value, ':')
	if colon <= 0 || colon == len(value)-1 {
		return "", "", false
	}
	return strings.Trim(value[:colon], "[]"), value[colon+1:], true
}

func firstQueryValue(values url.Values, keys ...string) string {
	for _, key := range keys {
		if value := values.Get(key); value != "" {
			return value
		}
	}
	return ""
}
