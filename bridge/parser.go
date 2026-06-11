package main

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/common/convert"
	"github.com/metacubex/mihomo/common/yaml"
)

type proxySchema struct {
	Proxies []map[string]any `yaml:"proxies"`
}

func parseSubscriptionWithMihomo(subscription string) ([]map[string]any, error) {
	buf := []byte(preprocessSubscription(subscription))
	schema := &proxySchema{}

	// Match Mihomo's proxy-provider parser: prefer a native `proxies` YAML
	// document, then fall back to its URI/base64 subscription converter.
	if err := yaml.Unmarshal(buf, schema); err != nil {
		proxies, convertErr := convert.ConvertsV2Ray(buf)
		if convertErr != nil {
			return nil, fmt.Errorf("%w, %w", err, convertErr)
		}
		schema.Proxies = proxies
	}

	if schema.Proxies == nil {
		return nil, errors.New("file must have a `proxies` field")
	}

	proxies := make([]map[string]any, 0, len(schema.Proxies))
	names := make(map[string]struct{}, len(schema.Proxies))
	for index, mapping := range schema.Proxies {
		name, ok := mapping["name"].(string)
		if !ok || name == "" {
			return nil, fmt.Errorf("proxy %d error: missing name", index)
		}
		if _, exists := names[name]; exists {
			continue
		}

		if err := validateProxyMapping(mapping); err != nil {
			return nil, fmt.Errorf("proxy %d error: %w", index, err)
		}

		names[name] = struct{}{}
		proxies = append(proxies, mapping)
	}

	if len(proxies) == 0 {
		return nil, errors.New("file doesn't have any proxy")
	}
	return proxies, nil
}

func validateProxyMapping(mapping map[string]any) error {
	// This bridge exports decoded mappings only. Constructing live outbound
	// adapters here would pull Mihomo's complete transport stack into the binary.
	proxyType, ok := mapping["type"].(string)
	if !ok || proxyType == "" {
		return errors.New("missing type")
	}

	rules, ok := generatedProxyRules[proxyType]
	if !ok {
		return fmt.Errorf("unsupported proxy type: %s", proxyType)
	}

	for field, rule := range rules {
		value, exists := mapping[field]
		if rule.required && (!exists || isEmptyRequiredValue(value)) {
			return fmt.Errorf("missing %s", field)
		}
		if exists && !isCompatibleProxyValue(value, rule.kind) {
			return fmt.Errorf("%s must be %s", field, rule.kind)
		}
	}

	if value, exists := mapping["port"]; exists {
		port, ok := proxyInteger(value)
		if !ok || port < 1 || port > 65535 {
			return errors.New("port must be between 1 and 65535")
		}
	}
	if value, exists := mapping["smux"]; exists && !isCompatibleProxyValue(value, "object") {
		return errors.New("smux must be object")
	}
	return nil
}

func isEmptyRequiredValue(value any) bool {
	if value == nil {
		return true
	}
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text) == ""
	}
	return false
}

func isCompatibleProxyValue(value any, kind string) bool {
	if value == nil {
		return false
	}
	switch kind {
	case "any":
		return true
	case "string":
		switch value.(type) {
		case string, bool,
			int, int8, int16, int32, int64,
			uint, uint8, uint16, uint32, uint64,
			float32, float64:
			return true
		default:
			return false
		}
	case "int":
		_, ok := proxyInteger(value)
		return ok
	case "bool":
		switch typed := value.(type) {
		case bool:
			return true
		case string:
			_, err := strconv.ParseBool(typed)
			if err == nil {
				return true
			}
			return typed == "0" || typed == "1"
		case int, int8, int16, int32, int64,
			uint, uint8, uint16, uint32, uint64:
			integer, ok := proxyInteger(value)
			return ok && (integer == 0 || integer == 1)
		default:
			return false
		}
	case "array":
		kind := reflect.TypeOf(value).Kind()
		return kind == reflect.Array || kind == reflect.Slice
	case "object":
		return reflect.TypeOf(value).Kind() == reflect.Map
	default:
		return false
	}
}

func proxyInteger(value any) (int64, bool) {
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int8:
		return int64(typed), true
	case int16:
		return int64(typed), true
	case int32:
		return int64(typed), true
	case int64:
		return typed, true
	case uint:
		if uint64(typed) > math.MaxInt64 {
			return 0, false
		}
		return int64(typed), true
	case uint8:
		return int64(typed), true
	case uint16:
		return int64(typed), true
	case uint32:
		return int64(typed), true
	case uint64:
		if typed > math.MaxInt64 {
			return 0, false
		}
		return int64(typed), true
	case float32:
		value := float64(typed)
		if math.Trunc(value) != value || value < math.MinInt64 || value > math.MaxInt64 {
			return 0, false
		}
		return int64(value), true
	case float64:
		if math.Trunc(typed) != typed || typed < math.MinInt64 || typed > math.MaxInt64 {
			return 0, false
		}
		return int64(typed), true
	case string:
		integer, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		return integer, err == nil
	default:
		return 0, false
	}
}
