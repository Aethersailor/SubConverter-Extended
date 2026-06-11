package main

import (
	"errors"
	"fmt"

	"github.com/metacubex/mihomo/adapter"
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

		proxy, err := adapter.ParseProxy(mapping)
		if err != nil {
			return nil, fmt.Errorf("proxy %d error: %w", index, err)
		}
		if err := proxy.Close(); err != nil {
			return nil, fmt.Errorf("proxy %d close error: %w", index, err)
		}

		names[name] = struct{}{}
		proxies = append(proxies, mapping)
	}

	if len(proxies) == 0 {
		return nil, errors.New("file doesn't have any proxy")
	}
	return proxies, nil
}
