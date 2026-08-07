#ifndef PREFERENCE_FILE_H_INCLUDED
#define PREFERENCE_FILE_H_INCLUDED

#include <string>

enum class PreferenceFileStatus {
    Ready,
    CopyFailed,
    CopyFailedTemporaryRemaining,
    CopyCommittedUnsynced,
    NotFound,
};

struct PreferenceFileSelection {
    PreferenceFileStatus status = PreferenceFileStatus::NotFound;
    std::string path = "pref.ini";
    std::string source;
};

// Select the historical default preference format and, on first start, copy
// the matching example without silently accepting an incomplete copy.
PreferenceFileSelection prepareDefaultPreferenceFile();
bool defaultPreferenceRequiresExit(const PreferenceFileSelection &selection,
                                   const std::string &effective_path);

#endif // PREFERENCE_FILE_H_INCLUDED
