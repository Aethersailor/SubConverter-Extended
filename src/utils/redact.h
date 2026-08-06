#ifndef REDACT_H_INCLUDED
#define REDACT_H_INCLUDED

#include <string>

// Remove credentials, bearer values, and well-known URL secrets before text is
// written to any diagnostic log sink.
std::string redactSensitiveLogText(const std::string &text);

// Return a stable diagnostic description without exposing the source value.
// HTTP(S) hosts are retained when they can be extracted without credentials;
// opaque subscription and node URIs expose only their scheme, length and hash.
std::string summarizeUrlForLog(const std::string &value);

#endif // REDACT_H_INCLUDED
