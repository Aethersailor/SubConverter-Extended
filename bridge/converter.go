package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"net/url"
	"strings"
	"unsafe"

	"github.com/metacubex/mihomo/common/convert"
)

// preprocessSubscription fixes URL encoding issues in subscription links
// Decodes the entire URL line to ensure Mihomo parser receives properly unencoded links
func preprocessSubscription(subscription string) string {
	lines := strings.Split(subscription, "\n")
	var result []string

	for _, line := range lines {
		line = strings.TrimRight(line, " \r")
		if line == "" {
			result = append(result, line)
			continue
		}

		// Decode the entire URL line
		// This fixes issues like v2rayN's uuid%3Apassword encoding
		// Safe for all protocols: url.QueryUnescape only decodes %XX patterns
		// and leaves structural characters (://, @, ?, #) intact
		if decoded, err := url.QueryUnescape(line); err == nil {
			line = decoded
		}
		// If decoding fails (malformed %), keep original line

		result = append(result, line)
	}

	return strings.Join(result, "\n")
}

// ConvertSubscription converts V2Ray subscription links to mihomo proxy configs
//
//export ConvertSubscription
func ConvertSubscription(data *C.char) *C.char {
	if data == nil {
		return C.CString(`{"error": "null input"}`)
	}

	// Convert C string to Go string
	subscription := C.GoString(data)

	// Preprocess subscription to fix URL encoding issues (e.g., v2rayN exported links)
	subscription = preprocessSubscription(subscription)

	// Call mihomo's converter
	proxies, err := convert.ConvertsV2Ray([]byte(subscription))
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
