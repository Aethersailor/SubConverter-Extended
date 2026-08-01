package main

import (
	"encoding/json"
	"fmt"
	"os"

	mihomoYAML "github.com/metacubex/mihomo/common/yaml"
	mihomoConstant "github.com/metacubex/mihomo/constant"
	mihomoRules "github.com/metacubex/mihomo/rules"
	mihomoRuleCommon "github.com/metacubex/mihomo/rules/common"
)

type mihomoRuleConfig struct {
	Rules    []string            `yaml:"rules"`
	SubRules map[string][]string `yaml:"sub-rules"`
}

func parseRuleLine(
	line string, subRules map[string][]mihomoConstant.Rule,
) (mihomoConstant.Rule, error) {
	typeName, payload, target, params := mihomoRuleCommon.ParseRulePayload(line, true)
	if typeName == "" || target == "" {
		return nil, fmt.Errorf("invalid rule format: %s", line)
	}
	if typeName == "SUB-RULE" {
		if _, ok := subRules[target]; !ok {
			return nil, fmt.Errorf("sub-rule not found: %s", target)
		}
	}
	return mihomoRules.ParseRule(typeName, payload, target, params, subRules)
}

func validateConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var config mihomoRuleConfig
	if err := mihomoYAML.Unmarshal(data, &config); err != nil {
		return err
	}
	if len(config.SubRules) == 0 {
		return fmt.Errorf("sub-rules are missing")
	}
	knownSubRules := make(map[string][]mihomoConstant.Rule, len(config.SubRules))
	for name := range config.SubRules {
		knownSubRules[name] = nil
	}
	for name, rules := range config.SubRules {
		for _, line := range rules {
			parsed, err := parseRuleLine(line, knownSubRules)
			if err != nil {
				return fmt.Errorf("sub-rules[%s]: %w", name, err)
			}
			knownSubRules[name] = append(knownSubRules[name], parsed)
		}
	}
	for _, line := range config.Rules {
		if _, err := parseRuleLine(line, knownSubRules); err != nil {
			return fmt.Errorf("rules: %w", err)
		}
	}
	return nil
}

func parseRegex(rule string) (int, error) {
	typeName, payload, target, params := mihomoRuleCommon.ParseRulePayload(rule, true)
	switch typeName {
	case "DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX":
	default:
		return 1, fmt.Errorf("not a Mihomo regex rule")
	}
	parsed, err := mihomoRules.ParseRule(typeName, payload, target, params, nil)
	if err != nil {
		return 1, err
	}
	result, err := json.Marshal(map[string]string{
		"type":    typeName,
		"payload": parsed.Payload(),
		"target":  target,
	})
	if err != nil {
		return 1, err
	}
	fmt.Println(string(result))
	return 0, nil
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "--regex" {
		if code, err := parseRegex(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(code)
		}
		return
	}
	if len(os.Args) == 2 {
		if err := validateConfig(os.Args[1]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	fmt.Fprintln(os.Stderr, "usage: mihomo_config_test_helper <config>")
	fmt.Fprintln(os.Stderr, "       mihomo_config_test_helper --regex <rule>")
	os.Exit(2)
}
