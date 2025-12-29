package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ParamDef represents a parameter definition
type ParamDef struct {
	Name        string // YAML parameter name (e.g., "skip-cert-verify")
	FieldType   string // e.g., "bool", "string", "int", "array", "object"
	IsOptional  bool   // Whether the parameter is optional
	IsHardcoded bool   // true if Mihomo hardcodes this parameter in converter.go
	Source      string // Protocol name or "BasicOption"
}

// ProtocolCompat represents protocol parameter compatibility
type ProtocolCompat struct {
	Name   string               // Protocol name (e.g., "tuic")
	Params map[string]*ParamDef // Parameter definitions
}

var (
	mihomoRoot  string
	basicParams map[string]*ParamDef
)

func main() {
	outputPath := flag.String("o", "", "Output path for param_compat.h")
	flag.Parse()

	if *outputPath == "" {
		log.Fatal("Usage: generate_param_compat -o <output_path>")
	}

	// Determine mihomo root directory
	mihomoRoot = findMihomoRoot()
	if mihomoRoot == "" {
		log.Fatal("Cannot find mihomo source directory")
	}
	log.Printf("Using mihomo root: %s\n", mihomoRoot)

	// Extract BasicOption parameters first
	basicParams = extractBasicOptionParams()
	log.Printf("Extracted %d BasicOption parameters\n", len(basicParams))

	// PHASE 1: Auto-scan all protocol files and build mapping
	protocolFileMap := buildProtocolFileMap()
	log.Printf("Auto-discovered %d protocol files\n", len(protocolFileMap))

	// PHASE 2: Read authoritative protocol list from mihomo_schemes.h
	// This ensures we only process protocols that Mihomo actually supports parsing
	protocols := extractProtocolList(*outputPath)
	log.Printf("Found %d protocols in mihomo_schemes.h\n", len(protocols))

	// PHASE 3: Auto-extract protocol aliases from converter.go
	// This eliminates hardcoded alias mappings
	aliasMap := extractProtocolAliases()
	log.Printf("Auto-extracted %d protocol alias mappings\n", len(aliasMap))

	// PHASE 3.5: Auto-detect hardcoded parameters in converter.go
	// This identifies parameters that Mihomo hardcodes (e.g., trojan["udp"] = true)
	hardcodedParams := detectHardcodedParams()
	log.Printf("Auto-detected %d hardcoded parameter instances\n", countHardcodedInstances(hardcodedParams))

	// PHASE 4: Parse each protocol's parameters using auto-discovered mapping
	compatMap := make(map[string]*ProtocolCompat)
	for _, proto := range protocols {
		log.Printf("Processing protocol: %s\n", proto)
		compat := parseProtocolParamsAuto(proto, protocolFileMap, aliasMap)
		if compat != nil {
			// Mark hardcoded parameters
			if hardcoded, exists := hardcodedParams[proto]; exists {
				for _, paramName := range hardcoded {
					if param, ok := compat.Params[paramName]; ok {
						param.IsHardcoded = true
						log.Printf("  Marked '%s' as hardcoded for protocol '%s'\n", paramName, proto)
					}
				}
			}
			compatMap[proto] = compat
		}
	}

	// Generate C++ header file
	generateCppHeader(compatMap, *outputPath)
	log.Printf("Generated: %s\n", *outputPath)
}

// findMihomoRoot locates the mihomo source directory
func findMihomoRoot() string {
	// Try several common locations relative to scripts directory
	candidates := []string{
		"../../mihomo",
		"../mihomo",
		"../../bridge/mihomo",
	}

	for _, candidate := range candidates {
		absPath, _ := filepath.Abs(candidate)
		if dirExists(absPath) {
			goModPath := filepath.Join(absPath, "go.mod")
			if fileExists(goModPath) {
				return absPath
			}
		}
	}

	return ""
}

// extractProtocolList reads protocol names from mihomo_schemes.h
func extractProtocolList(outputPath string) []string {
	// Try to find mihomo_schemes.h in the same directory as output
	schemesPath := filepath.Join(filepath.Dir(outputPath), "mihomo_schemes.h")

	data, err := os.ReadFile(schemesPath)
	if err != nil {
		log.Printf("Warning: cannot read %s, using default protocol list\n", schemesPath)
		return getDefaultProtocols()
	}

	// Extract scheme names from the header
	re := regexp.MustCompile(`"([a-z0-9]+)",`)
	matches := re.FindAllStringSubmatch(string(data), -1)

	protocols := make([]string, 0)
	for _, match := range matches {
		if len(match) > 1 {
			protocols = append(protocols, match[1])
		}
	}

	if len(protocols) == 0 {
		return getDefaultProtocols()
	}

	return protocols
}

// getDefaultProtocols returns a fallback list of common protocols
func getDefaultProtocols() []string {
	return []string{
		"ss", "ssr", "vmess", "vless", "trojan",
		"tuic", "hysteria", "hysteria2", "hy2",
		"snell", "http", "socks5", "wireguard",
	}
}

// extractBasicOptionParams extracts parameters from BasicOption struct
func extractBasicOptionParams() map[string]*ParamDef {
	basePath := filepath.Join(mihomoRoot, "adapter/outbound/base.go")

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, basePath, nil, 0)
	if err != nil {
		log.Printf("Warning: cannot parse base.go: %v\n", err)
		return getDefaultBasicParams()
	}

	// Find BasicOption struct
	var basicStruct *ast.StructType
	ast.Inspect(node, func(n ast.Node) bool {
		if typeSpec, ok := n.(*ast.TypeSpec); ok {
			if typeSpec.Name.Name == "BasicOption" {
				if structType, ok := typeSpec.Type.(*ast.StructType); ok {
					basicStruct = structType
					return false
				}
			}
		}
		return true
	})

	if basicStruct == nil {
		log.Println("Warning: BasicOption struct not found, using defaults")
		return getDefaultBasicParams()
	}

	params := make(map[string]*ParamDef)
	for _, field := range basicStruct.Fields.List {
		param := extractParamFromField(field)
		if param != nil {
			param.Source = "BasicOption"
			params[param.Name] = param
		}
	}

	return params
}

// getDefaultBasicParams returns fallback BasicOption parameters
func getDefaultBasicParams() map[string]*ParamDef {
	return map[string]*ParamDef{
		"tfo":   {Name: "tfo", FieldType: "bool", IsOptional: true, Source: "BasicOption"},
		"mptcp": {Name: "mptcp", FieldType: "bool", IsOptional: true, Source: "BasicOption"},
	}
}

// ProtocolFileInfo stores discovered protocol file information
type ProtocolFileInfo struct {
	FilePath   string
	StructName string
}

// buildProtocolFileMap auto-discovers all protocol files and their Option structs
// This eliminates the need for hardcoded protocol→file→struct mappings
func buildProtocolFileMap() map[string]*ProtocolFileInfo {
	fileMap := make(map[string]*ProtocolFileInfo)
	outboundDir := filepath.Join(mihomoRoot, "adapter/outbound")

	// Scan all .go files in outbound directory
	files, err := filepath.Glob(filepath.Join(outboundDir, "*.go"))
	if err != nil {
		log.Printf("Warning: failed to scan outbound directory: %v\n", err)
		return fileMap
	}

	for _, filePath := range files {
		// Parse the Go file
		fset := token.NewFileSet()
		node, err := parser.ParseFile(fset, filePath, nil, 0)
		if err != nil {
			continue
		}

		// Look for XXXOption struct definitions
		ast.Inspect(node, func(n ast.Node) bool {
			if typeSpec, ok := n.(*ast.TypeSpec); ok {
				structName := typeSpec.Name.Name
				// Check if it's an Option struct (ends with "Option")
				if strings.HasSuffix(structName, "Option") && structName != "BasicOption" {
					if _, ok := typeSpec.Type.(*ast.StructType); ok {
						// Extract base protocol name from struct name
						// e.g., "ShadowSocksOption" → "shadowsocks"
						baseName := strings.ToLower(strings.TrimSuffix(structName, "Option"))

						// Store the mapping
						fileMap[baseName] = &ProtocolFileInfo{
							FilePath:   filePath,
							StructName: structName,
						}
					}
				}
			}
			return true
		})
	}

	return fileMap
}

// extractProtocolAliases auto-extracts protocol alias mappings from converter.go
// This eliminates hardcoded alias mappings like {"hy2": "hysteria2"}
// by parsing the switch case statements: case "hysteria2", "hy2":
func extractProtocolAliases() map[string]string {
	aliasMap := make(map[string]string)
	converterPath := filepath.Join(mihomoRoot, "common/convert/converter.go")

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, converterPath, nil, 0)
	if err != nil {
		log.Printf("Warning: cannot parse converter.go: %v\n", err)
		return aliasMap
	}

	// Find ConvertsV2Ray function
	ast.Inspect(node, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "ConvertsV2Ray" {
			return true
		}

		// Find switch statements
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switchStmt, ok := n.(*ast.SwitchStmt)
			if !ok {
				return true
			}

			// Iterate through each case
			for _, caseClause := range switchStmt.Body.List {
				cc, ok := caseClause.(*ast.CaseClause)
				if !ok {
					continue
				}

				// Extract all protocol names in this case
				var caseProtocols []string
				for _, expr := range cc.List {
					if lit, ok := expr.(*ast.BasicLit); ok {
						if lit.Kind == token.STRING {
							val := strings.Trim(lit.Value, "\"")
							caseProtocols = append(caseProtocols, val)
						}
					}
				}

				// If this case has multiple protocols, they are aliases
				// e.g., case "hysteria2", "hy2" means hy2 -> hysteria2
				if len(caseProtocols) > 1 {
					// Use first as canonical, rest as aliases
					canonical := caseProtocols[0]
					for _, alias := range caseProtocols[1:] {
						aliasMap[alias] = canonical
					}
				}
			}
			return true
		})

		return false // Stop after finding ConvertsV2Ray
	})

	return aliasMap
}

// detectHardcodedParams scans converter.go for hardcoded parameter assignments
// Returns map[protocol][]paramName
func detectHardcodedParams() map[string][]string {
	hardcoded := make(map[string][]string)
	converterPath := filepath.Join(mihomoRoot, "common/convert/converter.go")

	data, err := os.ReadFile(converterPath)
	if err != nil {
		log.Printf("Warning: cannot read converter.go: %v\n", err)
		return hardcoded
	}

	content := string(data)

	// Pattern to match: protocolName["param"] = value
	// Examples: trojan["udp"] = true, tuic["udp"] = true
	re := regexp.MustCompile(`(\w+)\["([^"]+)"\]\s*=\s*(.+)`)

	lines := strings.Split(content, "\n")
	currentProtocol := ""

	for _, line := range lines {
		// Detect case statement: case "protocol":
		caseMatch := regexp.MustCompile(`case\s+"(\w+)"`).FindStringSubmatch(line)
		if len(caseMatch) > 1 {
			currentProtocol = caseMatch[1]
			// Handle aliases: hysteria2/hy2 map to hysteria2
			if currentProtocol == "hy2" {
				currentProtocol = "hysteria2"
			}
			continue
		}

		// Detect hardcoded assignment
		matches := re.FindStringSubmatch(line)
		if len(matches) >= 4 {
			paramName := matches[2]
			value := strings.TrimSpace(matches[3])

			// Check if assignment is a literal (true, false, number, "string")
			isLiteral := regexp.MustCompile(`^(true|false|\d+|"[^"]*")$`).MatchString(value)

			if isLiteral && currentProtocol != "" {
				// Skip if it's from query params (not hardcoded)
				if !strings.Contains(line, ".Get(") &&
					!strings.Contains(line, ".Parse") &&
					!strings.Contains(line, "strconv") {
					hardcoded[currentProtocol] = append(hardcoded[currentProtocol], paramName)
					log.Printf("Detected hardcoded: %s[\"%s\"] = %s\n", currentProtocol, paramName, value)
				}
			}
		}
	}

	return hardcoded
}

// countHardcodedInstances counts total number of hardcoded parameter instances
func countHardcodedInstances(hardcoded map[string][]string) int {
	count := 0
	for _, params := range hardcoded {
		count += len(params)
	}
	return count
}

// parseProtocolParamsAuto uses auto-discovered file mapping and auto-extracted aliases
func parseProtocolParamsAuto(protocol string, fileMap map[string]*ProtocolFileInfo, aliasMap map[string]string) *ProtocolCompat {
	// Try to find protocol in auto-discovered map
	var info *ProtocolFileInfo

	// Try direct match first
	info = fileMap[protocol]

	// Try auto-extracted aliases if direct match fails
	if info == nil {
		// Check if this protocol has an alias
		if canonical, hasAlias := aliasMap[protocol]; hasAlias {
			info = fileMap[canonical]
			if info != nil {
				log.Printf("Info: protocol '%s' resolved via alias to '%s'\n", protocol, canonical)
			}
		}
	}

	// Manual fallback for protocols that cannot be auto-resolved
	// This handles abbreviations like ss->shadowsocks, ssr->shadowsocksr
	if info == nil {
		manualMap := map[string]string{
			"ss":      "shadowsocks",
			"ssr":     "shadowsocksr",
			"socks5h": "socks5",
		}
		if target, ok := manualMap[protocol]; ok {
			info = fileMap[target]
			if info != nil {
				log.Printf("Info: protocol '%s' resolved via manual mapping to '%s'\n", protocol, target)
			}
		}
	}

	// Try intelligent substring matching for abbreviated protocol names
	// e.g., "ss" should match "shadowsocks", "ssr" should match "shadowsocksr"
	if info == nil {
		lowerProto := strings.ToLower(protocol)
		var bestMatch *ProtocolFileInfo
		var bestMatchName string
		shortestLen := 9999

		for fileName, fileInfo := range fileMap {
			lowerFile := strings.ToLower(fileName)

			// Check if protocol is a prefix or substring of filename
			if strings.HasPrefix(lowerFile, lowerProto) || strings.Contains(lowerFile, lowerProto) {
				// Verify this is a reasonable match (at least 2 characters)
				if len(lowerProto) >= 2 {
					// Prefer prefix matches over contains matches
					// Prefer shorter matches (shadowsocks over ssh for "ss")
					isPrefixMatch := strings.HasPrefix(lowerFile, lowerProto)

					// Score calculation: prefix match = higher priority
					if isPrefixMatch && (bestMatch == nil || len(fileName) < shortestLen) {
						bestMatch = fileInfo
						bestMatchName = fileName
						shortestLen = len(fileName)
					} else if !isPrefixMatch && bestMatch == nil {
						bestMatch = fileInfo
						bestMatchName = fileName
						shortestLen = len(fileName)
					}
				}
			}
		}

		if bestMatch != nil {
			info = bestMatch
			log.Printf("Info: protocol '%s' matched to '%s' via intelligent matching\n", protocol, bestMatchName)
		}
	}

	// Try common variations if still not found
	if info == nil {
		variations := []string{
			protocol,
			strings.ToLower(protocol),
			strings.ReplaceAll(protocol, "-", ""),
			strings.ReplaceAll(protocol, "_", ""),
		}

		for _, v := range variations {
			if fileMap[v] != nil {
				info = fileMap[v]
				break
			}
		}
	}

	if info == nil {
		log.Printf("Warning: no file mapping found for protocol '%s'\n", protocol)
		return nil
	}

	// Parse the file
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, info.FilePath, nil, 0)
	if err != nil {
		log.Printf("Warning: cannot parse %s: %v\n", info.FilePath, err)
		return nil
	}

	// Find the specific Option struct
	var optionStruct *ast.StructType
	ast.Inspect(node, func(n ast.Node) bool {
		if typeSpec, ok := n.(*ast.TypeSpec); ok {
			if typeSpec.Name.Name == info.StructName {
				if structType, ok := typeSpec.Type.(*ast.StructType); ok {
					optionStruct = structType
					return false
				}
			}
		}
		return true
	})

	if optionStruct == nil {
		log.Printf("Warning: Option struct '%s' not found in %s\n", info.StructName, info.FilePath)
		return nil
	}

	// Extract parameters (same logic as before)
	params := make(map[string]*ParamDef)
	for k, v := range basicParams {
		paramCopy := *v
		params[k] = &paramCopy
	}

	for _, field := range optionStruct.Fields.List {
		if len(field.Names) == 0 {
			continue
		}

		param := extractParamFromField(field)
		if param != nil {
			param.Source = protocol
			params[param.Name] = param
		}
	}

	return &ProtocolCompat{
		Name:   protocol,
		Params: params,
	}
}

// parseProtocolParams parses parameters for a specific protocol
func parseProtocolParams(protocol string) *ProtocolCompat {
	filename := findProtocolFile(protocol)
	if filename == "" {
		return nil
	}

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filename, nil, 0)
	if err != nil {
		log.Printf("Warning: cannot parse %s: %v\n", filename, err)
		return nil
	}

	// Find protocol Option struct
	optionStruct := findOptionStruct(node, protocol)
	if optionStruct == nil {
		log.Printf("Warning: Option struct not found for %s\n", protocol)
		return nil
	}

	// Start with BasicOption parameters
	params := make(map[string]*ParamDef)
	for k, v := range basicParams {
		paramCopy := *v
		params[k] = &paramCopy
	}

	// Extract protocol-specific parameters
	for _, field := range optionStruct.Fields.List {
		// Skip embedded BasicOption
		if len(field.Names) == 0 {
			continue
		}

		param := extractParamFromField(field)
		if param != nil {
			param.Source = protocol
			params[param.Name] = param
		}
	}

	return &ProtocolCompat{
		Name:   protocol,
		Params: params,
	}
}

// findProtocolFile locates the source file for a protocol
func findProtocolFile(protocol string) string {
	// Normalize protocol name to match actual Go file names in mihomo
	baseName := protocol
	switch protocol {
	case "hy2":
		baseName = "hysteria2"
	case "ss":
		baseName = "shadowsocks"
	case "ssr":
		baseName = "shadowsocksr"
	case "socks", "socks5", "socks5h":
		// All SOCKS variants use the same socks5.go file
		baseName = "socks5"
	case "anytls":
		baseName = "anytls"
	}

	candidates := []string{
		filepath.Join(mihomoRoot, "adapter/outbound", baseName+".go"),
		filepath.Join(mihomoRoot, "adapter/outbound", protocol+".go"),
	}

	for _, path := range candidates {
		if fileExists(path) {
			return path
		}
	}

	return ""
}

// findOptionStruct finds the XXXOption struct for a protocol
func findOptionStruct(node *ast.File, protocol string) *ast.StructType {
	// Possible struct names: TuicOption, Hysteria2Option, ShadowSocksOption, etc.
	possibleNames := []string{
		capitalize(protocol) + "Option",
		strings.ToUpper(protocol) + "Option",
	}

	// Special cases for protocols with non-standard struct names
	switch protocol {
	case "ss":
		possibleNames = append(possibleNames, "ShadowSocksOption")
	case "ssr":
		possibleNames = append(possibleNames, "ShadowSocksROption")
	case "hy2":
		possibleNames = append(possibleNames, "Hysteria2Option")
	case "socks", "socks5", "socks5h":
		possibleNames = append(possibleNames, "Socks5Option", "SocksOption")
	case "anytls":
		possibleNames = append(possibleNames, "AnyTLSOption")
	}

	var result *ast.StructType
	ast.Inspect(node, func(n ast.Node) bool {
		if typeSpec, ok := n.(*ast.TypeSpec); ok {
			for _, name := range possibleNames {
				if typeSpec.Name.Name == name {
					if structType, ok := typeSpec.Type.(*ast.StructType); ok {
						result = structType
						return false
					}
				}
			}
		}
		return true
	})

	return result
}

// extractParamFromField extracts parameter definition from a struct field
func extractParamFromField(field *ast.Field) *ParamDef {
	if field.Tag == nil {
		return nil
	}

	tagValue := strings.Trim(field.Tag.Value, "`")
	proxyTag := extractProxyTag(tagValue)

	// Skip fields without proxy tag or with proxy:"-"
	if proxyTag == "" || proxyTag == "-" {
		return nil
	}

	// Parse tag: "name,omitempty" or just "name"
	parts := strings.Split(proxyTag, ",")
	paramName := parts[0]
	isOptional := false

	for _, part := range parts[1:] {
		if part == "omitempty" {
			isOptional = true
		}
	}

	fieldType := getFieldType(field.Type)

	return &ParamDef{
		Name:       paramName,
		FieldType:  fieldType,
		IsOptional: isOptional,
	}
}

// extractProxyTag extracts the proxy tag value from struct tag
func extractProxyTag(tag string) string {
	re := regexp.MustCompile(`proxy:"([^"]+)"`)
	matches := re.FindStringSubmatch(tag)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// getFieldType returns the string representation of a field type
func getFieldType(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		switch t.Name {
		case "bool":
			return "bool"
		case "string":
			return "string"
		case "int", "uint", "int64", "uint64", "int32", "uint32":
			return "int"
		default:
			return "string"
		}
	case *ast.ArrayType:
		return "array"
	case *ast.MapType:
		return "object"
	case *ast.SelectorExpr:
		// Handle types like C.DNSPrefer
		return "string"
	default:
		return "string"
	}
}

// generateCppHeader generates the C++ header file
func generateCppHeader(compatMap map[string]*ProtocolCompat, outputPath string) {
	var sb strings.Builder

	// Header
	sb.WriteString("// Auto-generated by scripts/generate_param_compat.go\n")
	sb.WriteString("// DO NOT EDIT MANUALLY\n\n")
	sb.WriteString("#pragma once\n")
	sb.WriteString("#include <map>\n")
	sb.WriteString("#include <string>\n\n")
	sb.WriteString("namespace mihomo {\n\n")

	// ParamCompatInfo struct
	sb.WriteString("struct ParamCompatInfo {\n")
	sb.WriteString("    bool supported;\n")
	sb.WriteString("    std::string type;\n")
	sb.WriteString("    bool hardcoded;  // true if Mihomo hardcodes this parameter\n")
	sb.WriteString("};\n\n")

	// PARAM_COMPAT map
	sb.WriteString("const std::map<std::string, std::map<std::string, ParamCompatInfo>> PARAM_COMPAT = {\n")

	for _, proto := range getSortedProtocols(compatMap) {
		compat := compatMap[proto]
		sb.WriteString(fmt.Sprintf("    // Protocol: %s\n", proto))
		sb.WriteString(fmt.Sprintf("    {\"%s\", {\n", proto))

		for _, paramName := range getSortedParams(compat.Params) {
			param := compat.Params[paramName]
			hardcodedStr := "false"
			if param.IsHardcoded {
				hardcodedStr = "true"
			}
			sb.WriteString(fmt.Sprintf("        {\"%s\", {true, \"%s\", %s}},", paramName, param.FieldType, hardcodedStr))
			sb.WriteString(fmt.Sprintf(" // %s", param.Source))
			if param.IsHardcoded {
				sb.WriteString(" [HARDCODED]")
			}
			sb.WriteString("\n")
		}

		sb.WriteString("    }},\n")
	}

	sb.WriteString("};\n\n")

	// Helper function
	sb.WriteString("// Check if a protocol supports a specific parameter\n")
	sb.WriteString("inline bool isParamSupported(const std::string& protocol, const std::string& param) {\n")
	sb.WriteString("    auto proto_it = PARAM_COMPAT.find(protocol);\n")
	sb.WriteString("    if (proto_it == PARAM_COMPAT.end()) return false;\n")
	sb.WriteString("    auto param_it = proto_it->second.find(param);\n")
	sb.WriteString("    return param_it != proto_it->second.end() && param_it->second.supported;\n")
	sb.WriteString("}\n\n")

	sb.WriteString("// Check if a parameter is hardcoded by Mihomo for this protocol\n")
	sb.WriteString("// Hardcoded parameters should NOT be overridden by global settings\n")
	sb.WriteString("inline bool isParamHardcoded(const std::string& protocol, const std::string& param) {\n")
	sb.WriteString("    auto proto_it = PARAM_COMPAT.find(protocol);\n")
	sb.WriteString("    if (proto_it == PARAM_COMPAT.end()) return false;\n")
	sb.WriteString("    auto param_it = proto_it->second.find(param);\n")
	sb.WriteString("    return param_it != proto_it->second.end() && param_it->second.hardcoded;\n")
	sb.WriteString("}\n\n")

	sb.WriteString("} // namespace mihomo\n")

	// Write to file
	err := os.WriteFile(outputPath, []byte(sb.String()), 0644)
	if err != nil {
		log.Fatalf("Failed to write output file: %v", err)
	}
}

// Helper functions
func capitalize(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return !os.IsNotExist(err) && info.IsDir()
}

func getSortedProtocols(m map[string]*ProtocolCompat) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Simple alphabetical sort
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}

func getSortedParams(m map[string]*ParamDef) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Simple alphabetical sort
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}
