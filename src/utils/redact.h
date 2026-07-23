#ifndef REDACT_H_INCLUDED
#define REDACT_H_INCLUDED

#include <string>

// Remove credentials, bearer values, and well-known URL secrets before text is
// written to any diagnostic log sink.
std::string redactSensitiveLogText(const std::string &text);

#endif // REDACT_H_INCLUDED
