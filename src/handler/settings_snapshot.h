#ifndef SETTINGS_SNAPSHOT_H_INCLUDED
#define SETTINGS_SNAPSHOT_H_INCLUDED

#include <string>

struct Settings;

std::string sanitizedSettingsSnapshot(const Settings &settings);

#endif // SETTINGS_SNAPSHOT_H_INCLUDED
