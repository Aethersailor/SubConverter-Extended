package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/xtls/libxray/share"
)

const (
	libXrayRelease        = "v26.7.28"
	libXrayModuleVersion  = "v1.260728.0"
	libXraySourceRevision = "80263da83e96b2972455b0a94b13ee1a10e51391"
	maxXrayInputBytes     = 16 * 1024 * 1024
)

type xrayBridgeNode struct {
	Name         string          `json:"name"`
	Protocol     string          `json:"protocol"`
	Server       string          `json:"server"`
	Port         uint16          `json:"port"`
	XrayOutbound json.RawMessage `json:"xray_outbound"`
}

type xrayBridgeResult struct {
	Release        string           `json:"release"`
	ModuleVersion  string           `json:"module_version"`
	SourceRevision string           `json:"source_revision"`
	Nodes          []xrayBridgeNode `json:"nodes,omitempty"`
	Dropped        int              `json:"dropped,omitempty"`
	Error          string           `json:"error,omitempty"`
}

type xrayParserInfo struct {
	Available      bool   `json:"available"`
	Library        string `json:"library"`
	Release        string `json:"release"`
	ModuleVersion  string `json:"module_version"`
	SourceRevision string `json:"source_revision"`
	RoutedTargets  int    `json:"routed_targets"`
}

type flexiblePort uint16

func (port *flexiblePort) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}

	var value uint64
	var err error
	if data[0] == '"' {
		var text string
		if err = json.Unmarshal(data, &text); err == nil {
			value, err = strconv.ParseUint(strings.TrimSpace(text), 10, 16)
		}
	} else {
		value, err = strconv.ParseUint(string(data), 10, 16)
	}
	if err != nil || value > 65535 {
		return fmt.Errorf("invalid port")
	}
	*port = flexiblePort(value)
	return nil
}

type xrayEndpoint struct {
	Address string       `json:"address"`
	Port    flexiblePort `json:"port"`
}

type xraySettingsProjection struct {
	xrayEndpoint
	Vnext   []xrayEndpoint `json:"vnext"`
	Servers []xrayEndpoint `json:"servers"`
}

var supportedXrayProtocols = map[string]struct{}{
	"hysteria":    {},
	"shadowsocks": {},
	"socks":       {},
	"trojan":      {},
	"vless":       {},
	"vmess":       {},
}

func xrayEndpointFromSettings(settings json.RawMessage) (xrayEndpoint, error) {
	var projection xraySettingsProjection
	if err := json.Unmarshal(settings, &projection); err != nil {
		return xrayEndpoint{}, fmt.Errorf("invalid outbound settings")
	}

	candidates := make([]xrayEndpoint, 0, 3)
	if projection.Address != "" || projection.Port != 0 {
		candidates = append(candidates, projection.xrayEndpoint)
	}
	if len(projection.Vnext) == 1 {
		candidates = append(candidates, projection.Vnext[0])
	} else if len(projection.Vnext) > 1 {
		return xrayEndpoint{}, fmt.Errorf("multiple vnext endpoints")
	}
	if len(projection.Servers) == 1 {
		candidates = append(candidates, projection.Servers[0])
	} else if len(projection.Servers) > 1 {
		return xrayEndpoint{}, fmt.Errorf("multiple server endpoints")
	}

	for _, candidate := range candidates {
		if strings.TrimSpace(candidate.Address) != "" && candidate.Port != 0 {
			candidate.Address = strings.TrimSpace(candidate.Address)
			return candidate, nil
		}
	}
	return xrayEndpoint{}, fmt.Errorf("missing endpoint")
}

func convertXraySubscription(subscription string) xrayBridgeResult {
	result := xrayBridgeResult{
		Release:        libXrayRelease,
		ModuleVersion:  libXrayModuleVersion,
		SourceRevision: libXraySourceRevision,
	}
	if len(subscription) > maxXrayInputBytes {
		result.Error = "subscription exceeds parser input limit"
		return result
	}
	if strings.TrimSpace(subscription) == "" {
		result.Error = "unsupported share format"
		return result
	}

	config, err := share.ConvertShareLinksToXrayJson(subscription)
	if err != nil {
		// Upstream diagnostics may include decoded credentials for malformed
		// links. Keep the C boundary useful but fail closed without returning
		// subscription-controlled error text.
		result.Error = "subscription parse failed"
		return result
	}

	result.Nodes = make([]xrayBridgeNode, 0, len(config.OutboundConfigs))
	for index := range config.OutboundConfigs {
		outbound := &config.OutboundConfigs[index]
		protocol := strings.ToLower(strings.TrimSpace(outbound.Protocol))
		if _, supported := supportedXrayProtocols[protocol]; !supported || outbound.Settings == nil {
			result.Dropped++
			continue
		}

		endpoint, endpointErr := xrayEndpointFromSettings(*outbound.Settings)
		if endpointErr != nil {
			result.Dropped++
			continue
		}
		name := ""
		if outbound.SendThrough != nil {
			name = strings.TrimSpace(*outbound.SendThrough)
		}
		if name == "" {
			name = strings.TrimSpace(outbound.Tag)
		}
		if name == "" {
			name = fmt.Sprintf("%s-%d", protocol, index+1)
		}
		// libXray temporarily stores a display name in sendThrough while parsing
		// share links. It validates a copy with this field cleared. Preserve the
		// same executable outbound normalization at our boundary.
		outbound.SendThrough = nil
		rawOutbound, marshalErr := json.Marshal(outbound)
		if marshalErr != nil {
			result.Error = "failed to preserve Xray outbound"
			result.Nodes = nil
			return result
		}
		result.Nodes = append(result.Nodes, xrayBridgeNode{
			Name:         name,
			Protocol:     protocol,
			Server:       endpoint.Address,
			Port:         uint16(endpoint.Port),
			XrayOutbound: rawOutbound,
		})
	}

	if len(result.Nodes) == 0 {
		result.Error = "no supported Xray proxy outbound found"
		result.Nodes = nil
	}
	return result
}

func marshalXrayBridgeResult(result any) string {
	payload, err := json.Marshal(result)
	if err != nil {
		return `{"error":"failed to marshal parser result"}`
	}
	return string(payload)
}

func currentXrayParserInfo() xrayParserInfo {
	return xrayParserInfo{
		Available:      true,
		Library:        "libXray",
		Release:        libXrayRelease,
		ModuleVersion:  libXrayModuleVersion,
		SourceRevision: libXraySourceRevision,
		RoutedTargets:  0,
	}
}
