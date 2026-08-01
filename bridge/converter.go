package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"runtime/debug"
	"unsafe"

	mihomoYAML "github.com/metacubex/mihomo/common/yaml"
	mihomoConstant "github.com/metacubex/mihomo/constant"
	mihomoRules "github.com/metacubex/mihomo/rules"
	mihomoRuleCommon "github.com/metacubex/mihomo/rules/common"
)

// ReleaseUnusedMemory forces the embedded Go runtime to return unused heap
// pages after an unusually large subscription parse.
//
//export ReleaseUnusedMemory
func ReleaseUnusedMemory() {
	debug.FreeOSMemory()
}

// ValidateMihomoRegex compiles a regex through the same regexp2-backed rule
// implementation used by Mihomo's DOMAIN-REGEX and PROCESS-*-REGEX rules.
//
//export ValidateMihomoRegex
func ValidateMihomoRegex(pattern *C.char) C.int {
	if pattern == nil {
		return 0
	}
	_, err := mihomoRuleCommon.NewDomainRegex(C.GoString(pattern), "")
	if err != nil {
		return 0
	}
	return 1
}

// ParseMihomoRegexRule parses one final Clash regex rule with Mihomo's rule
// parser and returns its canonical type, payload, and target as JSON.  This
// is used by the compatibility helper to verify that SubConverter's output
// has the exact payload Mihomo will compile.
//
//export ParseMihomoRegexRule
func ParseMihomoRegexRule(rule *C.char) *C.char {
	result := map[string]string{}
	if rule == nil {
		result["error"] = "null rule"
		encoded, _ := json.Marshal(result)
		return C.CString(string(encoded))
	}

	typeName, payload, target, _ := mihomoRuleCommon.ParseRulePayload(
		C.GoString(rule), true,
	)
	switch typeName {
	case "DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX":
	default:
		result["error"] = "not a Mihomo regex rule"
		encoded, _ := json.Marshal(result)
		return C.CString(string(encoded))
	}
	var parsed mihomoConstant.Rule
	var err error
	switch typeName {
	case "DOMAIN-REGEX":
		parsed, err = mihomoRuleCommon.NewDomainRegex(payload, target)
	case "PROCESS-NAME-REGEX":
		parsed, err = mihomoRuleCommon.NewProcess(
			payload, target, mihomoConstant.ProcessNameRegex,
		)
	case "PROCESS-PATH-REGEX":
		parsed, err = mihomoRuleCommon.NewProcess(
			payload, target, mihomoConstant.ProcessPathRegex,
		)
	}
	if err != nil {
		result["error"] = err.Error()
	} else {
		result["type"] = typeName
		result["payload"] = parsed.Payload()
		result["target"] = target
	}
	encoded, _ := json.Marshal(result)
	return C.CString(string(encoded))
}

type mihomoRuleConfig struct {
	Rules    []string            `yaml:"rules"`
	SubRules map[string][]string `yaml:"sub-rules"`
}

func parseMihomoRule(
	typeName, payload, target string,
	params []string,
	subRules map[string][]mihomoConstant.Rule,
) (mihomoConstant.Rule, error) {
	return mihomoRules.ParseRule(typeName, payload, target, params, subRules)
}

func parseMihomoRuleLine(
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
	return parseMihomoRule(typeName, payload, target, params, subRules)
}

// ValidateMihomoRuleConfig parses the rule-bearing portion of a YAML config
// with Mihomo's own YAML and rule parsers.  This is intentionally narrower
// than config.Parse, which relies on process-global runtime linknames that
// are unavailable when Mihomo is embedded as a c-archive.
//
//export ValidateMihomoRuleConfig
func ValidateMihomoRuleConfig(data *C.char) *C.char {
	if data == nil {
		return C.CString("null rule config")
	}
	var config mihomoRuleConfig
	if err := mihomoYAML.Unmarshal([]byte(C.GoString(data)), &config); err != nil {
		return C.CString(err.Error())
	}
	if len(config.SubRules) == 0 {
		return C.CString("sub-rules are missing")
	}
	knownSubRules := make(map[string][]mihomoConstant.Rule, len(config.SubRules))
	for name := range config.SubRules {
		knownSubRules[name] = nil
	}
	for name, rules := range config.SubRules {
		for _, line := range rules {
			parsed, err := parseMihomoRuleLine(line, knownSubRules)
			if err != nil {
				return C.CString(fmt.Sprintf("sub-rules[%s]: %s", name, err))
			}
			knownSubRules[name] = append(knownSubRules[name], parsed)
		}
	}
	for _, line := range config.Rules {
		if _, err := parseMihomoRuleLine(line, knownSubRules); err != nil {
			return C.CString(fmt.Sprintf("rules: %s", err))
		}
	}
	return C.CString("")
}

// ResolveAgeRecipient validates one Age public or secret key and returns a
// canonical public recipient plus a SHA-256 fingerprint. Errors intentionally
// do not include the supplied key.
//
//export ResolveAgeRecipient
func ResolveAgeRecipient(key *C.char) *C.char {
	if key == nil {
		result, _ := json.Marshal(ageRecipientResult{Error: "invalid age key"})
		return C.CString(string(result))
	}

	resolved, err := resolveAgeRecipient(C.GoString(key))
	if err != nil {
		resolved = ageRecipientResult{Error: err.Error()}
	}
	result, _ := json.Marshal(resolved)
	return C.CString(string(result))
}

// EncryptAgeArmored encrypts a successful configuration response using the
// resolved public recipient. The OK/ERROR prefix keeps the C boundary simple;
// valid armored output can never be confused with an error.
//
//export EncryptAgeArmored
func EncryptAgeArmored(data *C.char, recipient *C.char) *C.char {
	if data == nil || recipient == nil {
		return C.CString("ERROR\ninvalid age encryption input")
	}

	encrypted, err := encryptAgeArmored(C.GoString(data), C.GoString(recipient))
	if err != nil {
		return C.CString("ERROR\n" + err.Error())
	}
	return C.CString("OK\n" + encrypted)
}

// ConvertSubscription parses native Mihomo provider YAML or URI subscriptions.
//
//export ConvertSubscription
func ConvertSubscription(data *C.char) *C.char {
	if data == nil {
		return C.CString(`{"error": "null input"}`)
	}

	// Convert C string to Go string
	subscription := C.GoString(data)

	proxies, err := parseSubscriptionWithMihomo(subscription)
	if err != nil {
		errJSON, _ := json.Marshal(map[string]string{
			"error": err.Error(),
		})
		return C.CString(string(errJSON))
	}

	// Marshal result to JSON
	result, err := json.Marshal(proxies)
	if err != nil {
		errJSON, _ := json.Marshal(map[string]string{
			"error": "failed to marshal result: " + err.Error(),
		})
		return C.CString(string(errJSON))
	}

	return C.CString(string(result))
}

// FreeString frees memory allocated by Go (must be called from C++ after using the result)
//
//export FreeString
func FreeString(s *C.char) {
	C.free(unsafe.Pointer(s))
}

func main() {
	// Required for buildmode=c-archive
}
