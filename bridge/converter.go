package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"runtime/debug"
	"sync"
	"unsafe"
)

const parseMemoryReleaseThreshold = 256 * 1024

var parseMemoryState struct {
	sync.Mutex
	active       int
	pendingBytes int
}

func beginSubscriptionParse(size int) {
	parseMemoryState.Lock()
	defer parseMemoryState.Unlock()
	parseMemoryState.active++
	if size >= parseMemoryReleaseThreshold-parseMemoryState.pendingBytes {
		parseMemoryState.pendingBytes = parseMemoryReleaseThreshold
	} else {
		parseMemoryState.pendingBytes += size
	}
}

func finishSubscriptionParse() {
	parseMemoryState.Lock()
	defer parseMemoryState.Unlock()
	parseMemoryState.active--
	if parseMemoryState.active != 0 ||
		parseMemoryState.pendingBytes < parseMemoryReleaseThreshold {
		return
	}

	parseMemoryState.pendingBytes = 0
	// This runs after the parsing helper has returned, so its large maps and
	// JSON buffers are no longer rooted by the active cgo stack frame.
	debug.FreeOSMemory()
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

	subscription := C.GoString(data)
	beginSubscriptionParse(len(subscription))
	result := convertSubscription(subscription)
	subscription = ""
	finishSubscriptionParse()
	return result
}

func convertSubscription(subscription string) *C.char {
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
