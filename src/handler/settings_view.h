#ifndef SETTINGS_VIEW_H_INCLUDED
#define SETTINGS_VIEW_H_INCLUDED

#include <memory>

struct Settings;

using SettingsSnapshot = std::shared_ptr<const Settings>;

// Publish one fully finalized Settings generation. Readers retain the returned
// shared object for their whole request, so a later reload cannot change the
// values observed by that request.
void publishSettingsSnapshot(const Settings &settings);
SettingsSnapshot captureSettingsSnapshot();

// Return the snapshot bound to the current request. Code outside a request
// keeps the legacy global Settings behavior so startup/configuration parsing is
// unchanged.
#ifdef NO_WEBGET
// The static-library build intentionally excludes the request runtime and has
// always read its caller-provided global Settings object directly.
extern Settings global;
inline const Settings &effectiveSettings() { return global; }
#else
const Settings &effectiveSettings();
#endif
SettingsSnapshot captureEffectiveSettingsSnapshot();

class ScopedSettingsView {
public:
  explicit ScopedSettingsView(SettingsSnapshot snapshot);
  ~ScopedSettingsView();

  ScopedSettingsView(const ScopedSettingsView &) = delete;
  ScopedSettingsView &operator=(const ScopedSettingsView &) = delete;

private:
  SettingsSnapshot previous_;
};

#endif // SETTINGS_VIEW_H_INCLUDED
