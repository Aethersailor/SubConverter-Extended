package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type fieldRule struct {
	Kind     string
	Required bool
}

func main() {
	outputPath := flag.String("o", "", "output path for the generated Go source")
	flag.Parse()
	if *outputPath == "" {
		fmt.Fprintln(os.Stderr, "usage: go run generate_proxy_validation.go -o <output_path>")
		os.Exit(1)
	}

	moduleRoot, err := findModuleRoot()
	if err != nil {
		fatal(err)
	}
	mihomoRoot, err := findMihomoRoot(moduleRoot)
	if err != nil {
		fatal(err)
	}

	protocolOptions, err := parseProtocolOptions(filepath.Join(mihomoRoot, "adapter", "parser.go"))
	if err != nil {
		fatal(err)
	}
	structs, err := parseOutboundStructs(filepath.Join(mihomoRoot, "adapter", "outbound"))
	if err != nil {
		fatal(err)
	}

	rules := make(map[string]map[string]fieldRule, len(protocolOptions))
	for protocol, optionType := range protocolOptions {
		fields := make(map[string]fieldRule)
		collectFields(optionType, structs, fields, make(map[string]bool))
		rules[protocol] = fields
	}

	if err := writeGeneratedSource(*outputPath, rules); err != nil {
		fatal(err)
	}
	fmt.Printf("Generated %s with %d Mihomo proxy types\n", *outputPath, len(rules))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func findModuleRoot() (string, error) {
	for _, candidate := range []string{".", "bridge", "../bridge"} {
		if _, err := os.Stat(filepath.Join(candidate, "go.mod")); err == nil {
			return filepath.Abs(candidate)
		}
	}
	return "", fmt.Errorf("cannot find bridge/go.mod")
}

func findMihomoRoot(moduleRoot string) (string, error) {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/metacubex/mihomo")
	cmd.Dir = moduleRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("locate Mihomo module: %w: %s", err, strings.TrimSpace(string(output)))
	}
	root := strings.TrimSpace(string(output))
	if root == "" {
		return "", fmt.Errorf("go list returned an empty Mihomo module path")
	}
	return root, nil
}

func parseProtocolOptions(path string) (map[string]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	result := make(map[string]string)
	ast.Inspect(file, func(node ast.Node) bool {
		switchStmt, ok := node.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		ident, ok := switchStmt.Tag.(*ast.Ident)
		if !ok || ident.Name != "proxyType" {
			return true
		}

		for _, item := range switchStmt.Body.List {
			clause, ok := item.(*ast.CaseClause)
			if !ok || len(clause.List) == 0 {
				continue
			}
			optionType := findOptionType(clause)
			if optionType == "" {
				continue
			}
			for _, expression := range clause.List {
				literal, ok := expression.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				protocol, err := strconv.Unquote(literal.Value)
				if err == nil {
					result[protocol] = optionType
				}
			}
		}
		return false
	})

	if len(result) == 0 {
		return nil, fmt.Errorf("no proxy types found in %s", path)
	}
	return result, nil
}

func findOptionType(clause *ast.CaseClause) string {
	optionType := ""
	ast.Inspect(clause, func(node ast.Node) bool {
		if optionType != "" {
			return false
		}
		composite, ok := node.(*ast.CompositeLit)
		if !ok {
			return true
		}
		selector, ok := composite.Type.(*ast.SelectorExpr)
		if !ok || selector.Sel == nil || !strings.HasSuffix(selector.Sel.Name, "Option") {
			return true
		}
		optionType = selector.Sel.Name
		return false
	})
	return optionType
}

func parseOutboundStructs(root string) (map[string]*ast.StructType, error) {
	structs := make(map[string]*ast.StructType)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}

		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		for _, declaration := range file.Decls {
			gen, ok := declaration.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, spec := range gen.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				structType, ok := typeSpec.Type.(*ast.StructType)
				if ok {
					if _, exists := structs[typeSpec.Name.Name]; !exists {
						structs[typeSpec.Name.Name] = structType
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return structs, nil
}

func collectFields(typeName string, structs map[string]*ast.StructType, result map[string]fieldRule, visiting map[string]bool) {
	if visiting[typeName] {
		return
	}
	structType, ok := structs[typeName]
	if !ok {
		return
	}
	visiting[typeName] = true
	defer delete(visiting, typeName)

	for _, field := range structType.Fields.List {
		if field.Tag == nil {
			if len(field.Names) == 0 {
				if embedded := embeddedTypeName(field.Type); embedded != "" {
					collectFields(embedded, structs, result, visiting)
				}
			}
			continue
		}

		name, omitEmpty := proxyField(field.Tag.Value)
		if name == "" || name == "-" {
			continue
		}
		result[name] = fieldRule{
			Kind:     fieldKind(field.Type, structs),
			// Endpoint fields are required unless Mihomo explicitly supports
			// an alternate form, such as WireGuard's peer list.
			Required: (name == "server" || name == "port") && !omitEmpty,
		}
	}
}

func embeddedTypeName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.StarExpr:
		return embeddedTypeName(typed.X)
	default:
		return ""
	}
}

func proxyField(rawTag string) (string, bool) {
	tag, err := strconv.Unquote(rawTag)
	if err != nil {
		return "", false
	}
	for tag != "" {
		key, value, rest, ok := nextStructTag(tag)
		if !ok {
			break
		}
		tag = rest
		if key != "proxy" {
			continue
		}
		parts := strings.Split(value, ",")
		omitEmpty := false
		for _, option := range parts[1:] {
			omitEmpty = omitEmpty || option == "omitempty"
		}
		return parts[0], omitEmpty
	}
	return "", false
}

func nextStructTag(tag string) (key string, value string, rest string, ok bool) {
	tag = strings.TrimLeft(tag, " ")
	if tag == "" {
		return "", "", "", false
	}
	index := strings.Index(tag, ":")
	if index <= 0 || index+1 >= len(tag) || tag[index+1] != '"' {
		return "", "", "", false
	}
	key = tag[:index]
	quoted := tag[index+1:]
	end := 1
	for end < len(quoted) {
		if quoted[end] == '"' && quoted[end-1] != '\\' {
			break
		}
		end++
	}
	if end >= len(quoted) {
		return "", "", "", false
	}
	value, err := strconv.Unquote(quoted[:end+1])
	if err != nil {
		return "", "", "", false
	}
	return key, value, quoted[end+1:], true
}

func fieldKind(expression ast.Expr, structs map[string]*ast.StructType) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		switch typed.Name {
		case "bool":
			return "bool"
		case "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64", "float32", "float64":
			return "int"
		case "string":
			return "string"
		default:
			if _, ok := structs[typed.Name]; ok {
				return "object"
			}
			return "string"
		}
	case *ast.ArrayType:
		return "array"
	case *ast.MapType, *ast.StructType:
		return "object"
	case *ast.StarExpr:
		return fieldKind(typed.X, structs)
	case *ast.InterfaceType:
		return "any"
	default:
		return "string"
	}
}

func writeGeneratedSource(path string, rules map[string]map[string]fieldRule) error {
	var builder strings.Builder
	builder.WriteString("// Code generated by scripts/generate_proxy_validation.go; DO NOT EDIT.\n\n")
	builder.WriteString("package main\n\n")
	builder.WriteString("type proxyFieldRule struct {\n\tkind string\n\trequired bool\n}\n\n")
	builder.WriteString("var generatedProxyRules = map[string]map[string]proxyFieldRule{\n")

	protocols := make([]string, 0, len(rules))
	for protocol := range rules {
		protocols = append(protocols, protocol)
	}
	sort.Strings(protocols)

	for _, protocol := range protocols {
		rule := rules[protocol]
		fmt.Fprintf(&builder, "\t%q: {\n", protocol)
		fields := make([]string, 0, len(rule))
		for field := range rule {
			fields = append(fields, field)
		}
		sort.Strings(fields)
		for _, field := range fields {
			fieldRule := rule[field]
			fmt.Fprintf(&builder, "\t\t%q: {kind: %q, required: %t},\n", field, fieldRule.Kind, fieldRule.Required)
		}
		builder.WriteString("\t},\n")
	}
	builder.WriteString("}\n")

	formatted, err := formatSource(builder.String())
	if err != nil {
		return err
	}
	return os.WriteFile(path, formatted, 0o644)
}

func formatSource(source string) ([]byte, error) {
	tempDir, err := os.MkdirTemp("", "proxy-validation-format-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	path := filepath.Join(tempDir, "generated.go")
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		return nil, err
	}
	cmd := exec.Command("gofmt", "-w", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("gofmt generated source: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return os.ReadFile(path)
}
