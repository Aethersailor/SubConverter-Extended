package main

/*
#include <stdlib.h>
*/
import "C"

// ConvertXraySubscription parses share links through the pinned official
// libXray parser. It does not start Xray, perform network I/O, or alter any
// existing target route.
//
//export ConvertXraySubscription
func ConvertXraySubscription(data *C.char) *C.char {
	if data == nil {
		return C.CString(marshalXrayBridgeResult(xrayBridgeResult{
			Release:        libXrayRelease,
			ModuleVersion:  libXrayModuleVersion,
			SourceRevision: libXraySourceRevision,
			Error:          "null input",
		}))
	}
	return C.CString(marshalXrayBridgeResult(convertXraySubscription(C.GoString(data))))
}

// XrayParserInfo returns immutable build provenance. routed_targets remains
// zero until a later, separately reviewed change enables a client path.
//
//export XrayParserInfo
func XrayParserInfo() *C.char {
	return C.CString(marshalXrayBridgeResult(currentXrayParserInfo()))
}
