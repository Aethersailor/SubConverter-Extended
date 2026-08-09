package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type capabilityField struct {
	Kind     string `json:"kind"`
	Required bool   `json:"required"`
}

type capabilityManifest struct {
	Schema        int                                   `json:"schema"`
	Module        string                                `json:"module"`
	ModuleVersion string                                `json:"module_version"`
	ProxyTypes    map[string]map[string]capabilityField `json:"proxy_types"`
}

type paramDefinition struct {
	Kind      string
	Hardcoded bool
}

func main() {
	outputPath := flag.String("o", "", "output path for param_compat.h")
	manifestPath := flag.String("manifest", "", "path to mihomo_capabilities.json")
	flag.Parse()
	if *outputPath == "" || *manifestPath == "" {
		log.Fatal("usage: generate_param_compat -manifest <manifest_path> -o <output_path>")
	}

	manifest := loadCapabilityManifest(*manifestPath)
	moduleRoot := findModuleRoot()
	if moduleRoot == "" {
		log.Fatal("cannot find bridge/go.mod")
	}
	mihomoRoot := findMihomoRoot(moduleRoot)
	if mihomoRoot == "" {
		log.Fatal("cannot find Mihomo source directory")
	}
	hardcoded := detectHardcodedParams(
		filepath.Join(mihomoRoot, "common", "convert", "converter.go"),
		manifest.ProxyTypes,
	)

	compatibility := make(map[string]map[string]paramDefinition, len(manifest.ProxyTypes))
	for protocol, fields := range manifest.ProxyTypes {
		parameters := make(map[string]paramDefinition, len(fields))
		for name, field := range fields {
			parameters[name] = paramDefinition{
				Kind:      field.Kind,
				Hardcoded: hardcoded[protocol][name],
			}
		}
		compatibility[protocol] = parameters
	}

	if err := generateCppHeader(compatibility, manifest.ModuleVersion, *outputPath); err != nil {
		log.Fatal(err)
	}
	log.Printf("Generated %s from %d canonical Mihomo proxy types\n", *outputPath, len(compatibility))
}

func loadCapabilityManifest(path string) capabilityManifest {
	content, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read Mihomo capability manifest: %v", err)
	}
	var manifest capabilityManifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		log.Fatalf("parse Mihomo capability manifest: %v", err)
	}
	if manifest.Schema != 1 || manifest.Module != "github.com/metacubex/mihomo" ||
		manifest.ModuleVersion == "" || len(manifest.ProxyTypes) == 0 {
		log.Fatal("Mihomo capability manifest is incomplete or incompatible")
	}
	for protocol, fields := range manifest.ProxyTypes {
		if protocol == "" || len(fields) == 0 {
			log.Fatalf("Mihomo capability manifest contains an empty proxy definition: %q", protocol)
		}
		for name, field := range fields {
			if name == "" || field.Kind == "" {
				log.Fatalf("Mihomo capability manifest contains an incomplete field for %q", protocol)
			}
		}
	}
	return manifest
}

func findModuleRoot() string {
	for _, candidate := range []string{".", "../bridge", "bridge"} {
		if _, err := os.Stat(filepath.Join(candidate, "go.mod")); err == nil {
			root, absErr := filepath.Abs(candidate)
			if absErr == nil {
				return root
			}
			return candidate
		}
	}
	return ""
}

func findMihomoRoot(moduleRoot string) string {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/metacubex/mihomo")
	cmd.Dir = moduleRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("go list could not locate Mihomo: %v: %s\n", err, strings.TrimSpace(string(output)))
		return ""
	}
	root := strings.TrimSpace(string(output))
	if root == "" {
		return ""
	}
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		return ""
	}
	return root
}

func detectHardcodedParams(path string, proxyTypes map[string]map[string]capabilityField) map[string]map[string]bool {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		log.Fatalf("parse Mihomo converter: %v", err)
	}

	result := make(map[string]map[string]bool)
	ast.Inspect(file, func(node ast.Node) bool {
		function, ok := node.(*ast.FuncDecl)
		if !ok || function.Name.Name != "ConvertsV2Ray" {
			return true
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			switchStatement, ok := node.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			identifier, ok := switchStatement.Tag.(*ast.Ident)
			if !ok || identifier.Name != "scheme" {
				return true
			}
			for _, item := range switchStatement.Body.List {
				clause, ok := item.(*ast.CaseClause)
				if ok {
					detectClauseHardcodedParams(clause, proxyTypes, result)
				}
			}
			return false
		})
		return false
	})
	return result
}

func detectClauseHardcodedParams(
	clause *ast.CaseClause,
	proxyTypes map[string]map[string]capabilityField,
	result map[string]map[string]bool,
) {
	caseSchemes := make([]string, 0, len(clause.List))
	for _, expression := range clause.List {
		literal, ok := expression.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			continue
		}
		value, err := strconv.Unquote(literal.Value)
		if err == nil {
			caseSchemes = append(caseSchemes, value)
		}
	}

	variableTypes := make(map[string]map[string]bool)
	ast.Inspect(clause, func(node ast.Node) bool {
		statement, ok := node.(*ast.AssignStmt)
		if !ok || len(statement.Lhs) != len(statement.Rhs) {
			return true
		}
		for index, left := range statement.Lhs {
			variable, field, ok := indexedAssignment(left)
			if !ok || field != "type" {
				continue
			}
			candidates := stringLiterals(statement.Rhs[index])
			if identifier, ok := statement.Rhs[index].(*ast.Ident); ok && identifier.Name == "scheme" {
				candidates = append(candidates, caseSchemes...)
			}
			for _, candidate := range candidates {
				if _, exists := proxyTypes[candidate]; exists {
					if variableTypes[variable] == nil {
						variableTypes[variable] = make(map[string]bool)
					}
					variableTypes[variable][candidate] = true
				}
			}
			if len(variableTypes[variable]) == 0 {
				if _, exists := proxyTypes[variable]; exists {
					variableTypes[variable] = map[string]bool{variable: true}
				}
			}
		}
		return true
	})

	ast.Inspect(clause, func(node ast.Node) bool {
		statement, ok := node.(*ast.AssignStmt)
		if !ok || len(statement.Lhs) != len(statement.Rhs) {
			return true
		}
		for index, left := range statement.Lhs {
			variable, field, ok := indexedAssignment(left)
			if !ok || field == "type" {
				continue
			}
			if _, literal := literalValue(statement.Rhs[index]); !literal {
				continue
			}
			protocols := variableTypes[variable]
			if len(protocols) == 0 {
				if _, exists := proxyTypes[variable]; exists {
					protocols = map[string]bool{variable: true}
				}
			}
			for protocol := range protocols {
				fields := proxyTypes[protocol]
				if _, exists := fields[field]; !exists {
					continue
				}
				if result[protocol] == nil {
					result[protocol] = make(map[string]bool)
				}
				result[protocol][field] = true
			}
		}
		return true
	})
}

func indexedAssignment(expression ast.Expr) (variable string, field string, ok bool) {
	indexed, ok := expression.(*ast.IndexExpr)
	if !ok {
		return "", "", false
	}
	identifier, ok := indexed.X.(*ast.Ident)
	if !ok {
		return "", "", false
	}
	literal, ok := indexed.Index.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", "", false
	}
	field, err := strconv.Unquote(literal.Value)
	if err != nil {
		return "", "", false
	}
	return identifier.Name, field, true
}

func stringLiterals(expression ast.Expr) []string {
	seen := make(map[string]bool)
	var result []string
	ast.Inspect(expression, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(literal.Value)
		if err == nil && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
		return true
	})
	return result
}

func literalValue(expression ast.Expr) (string, bool) {
	switch value := expression.(type) {
	case *ast.BasicLit:
		if value.Kind == token.STRING {
			unquoted, err := strconv.Unquote(value.Value)
			return unquoted, err == nil
		}
		if value.Kind == token.INT || value.Kind == token.FLOAT {
			return value.Value, true
		}
	case *ast.Ident:
		if value.Name == "true" || value.Name == "false" {
			return value.Name, true
		}
	}
	return "", false
}

func generateCppHeader(compatibility map[string]map[string]paramDefinition, version, outputPath string) error {
	var output strings.Builder
	output.WriteString("// Auto-generated by scripts/generate_param_compat.go\n")
	output.WriteString("// DO NOT EDIT MANUALLY\n")
	fmt.Fprintf(&output, "// Based on Mihomo version: %s\n\n", version)
	output.WriteString("#pragma once\n#include <map>\n#include <string>\n\nnamespace mihomo {\n\n")
	output.WriteString("struct ParamCompatInfo {\n    bool supported;\n    std::string type;\n    bool hardcoded;\n};\n\n")
	output.WriteString("const std::map<std::string, std::map<std::string, ParamCompatInfo>> PARAM_COMPAT = {\n")

	protocols := sortedKeys(compatibility)
	for _, protocol := range protocols {
		fmt.Fprintf(&output, "    {\"%s\", {\n", protocol)
		parameters := compatibility[protocol]
		for _, parameter := range sortedKeys(parameters) {
			definition := parameters[parameter]
			fmt.Fprintf(&output, "        {\"%s\", {true, \"%s\", %t}},\n", parameter, definition.Kind, definition.Hardcoded)
		}
		output.WriteString("    }},\n")
	}

	output.WriteString("};\n\n")
	output.WriteString("inline bool isParamSupported(const std::string& protocol, const std::string& param) {\n")
	output.WriteString("    auto proto_it = PARAM_COMPAT.find(protocol);\n    if (proto_it == PARAM_COMPAT.end()) return false;\n")
	output.WriteString("    auto param_it = proto_it->second.find(param);\n    return param_it != proto_it->second.end() && param_it->second.supported;\n}\n\n")
	output.WriteString("inline bool isParamHardcoded(const std::string& protocol, const std::string& param) {\n")
	output.WriteString("    auto proto_it = PARAM_COMPAT.find(protocol);\n    if (proto_it == PARAM_COMPAT.end()) return false;\n")
	output.WriteString("    auto param_it = proto_it->second.find(param);\n    return param_it != proto_it->second.end() && param_it->second.hardcoded;\n}\n\n")
	output.WriteString("} // namespace mihomo\n")

	if err := os.WriteFile(outputPath, []byte(output.String()), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", outputPath, err)
	}
	return nil
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
