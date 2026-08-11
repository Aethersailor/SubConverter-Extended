#ifndef REDACT_H_INCLUDED
#define REDACT_H_INCLUDED

#include <string>

// Remove credentials, bearer values, and well-known URL secrets before text is
// written to any diagnostic log sink.
std::string redactSensitiveLogText(const std::string &text);

// Apply the complete log-sink policy: redact known secrets, escape control
// characters so one call produces one physical line, and cap attacker-
// controlled output without splitting a UTF-8 code point.
std::string sanitizeLogLine(const std::string &text);

// Describe an arbitrary exception or parser diagnostic without retaining any
// attacker-controlled text or a stable digest that could validate guesses of
// short secrets. This is suitable for errors whose wording may contain
// configuration values, request data, or filesystem paths.
std::string summarizeSensitiveTextForLog(const std::string &value);

// Return a stable diagnostic description without exposing the source value.
// HTTP(S) hosts are retained when they can be extracted without credentials;
// opaque subscription and node URIs expose only their scheme and length.
std::string summarizeUrlForLog(const std::string &value);

#endif // REDACT_H_INCLUDED
