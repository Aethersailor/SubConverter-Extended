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

		// Decode the entire URL line. This fixes inputs such as v2rayN's
		// uuid%3Apassword encoding and keeps malformed percent escapes unchanged.
		if decoded, err := url.QueryUnescape(line); err == nil {
			line = decoded
		}

		line = normalizeLegacyShadowrocketVMess(line)
		result = append(result, line)
	}

	return strings.Join(result, "\n")
}

func normalizeLegacyShadowrocketVMess(line string) string {
	const prefix = "vmess://"
	if !strings.HasPrefix(line, prefix) {
		return line
	}

	body := strings.TrimPrefix(line, prefix)
	queryStart := strings.IndexByte(body, '?')
	if queryStart < 0 {
		return line
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
