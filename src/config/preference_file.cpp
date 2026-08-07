#include "preference_file.h"

#include "utils/file.h"

namespace {

PreferenceFileSelection copyExample(const std::string &source,
                                    const std::string &destination) {
    const FileCommitResult result = fileCopyDetailed(source, destination);
    if(result == FileCommitResult::Durable)
        return {PreferenceFileStatus::Ready, destination, source};
    if(result == FileCommitResult::CommittedUnsynced)
        return {PreferenceFileStatus::CopyCommittedUnsynced, destination,
                source};
    if(result == FileCommitResult::FailedTemporaryRemaining)
        return {PreferenceFileStatus::CopyFailedTemporaryRemaining,
                destination, source};
    return {PreferenceFileStatus::CopyFailed, destination, source};
}

} // namespace

PreferenceFileSelection prepareDefaultPreferenceFile() {
    if(fileExist("pref.toml"))
        return {PreferenceFileStatus::Ready, "pref.toml", ""};
    if(fileExist("pref.yml"))
        return {PreferenceFileStatus::Ready, "pref.yml", ""};
    if(fileExist("pref.ini"))
        return {PreferenceFileStatus::Ready, "pref.ini", ""};

    if(fileExist("pref.example.toml"))
        return copyExample("pref.example.toml", "pref.toml");
    if(fileExist("pref.example.yml"))
        return copyExample("pref.example.yml", "pref.yml");
    if(fileExist("pref.example.ini"))
        return copyExample("pref.example.ini", "pref.ini");
    return {};
}

bool defaultPreferenceRequiresExit(const PreferenceFileSelection &selection,
                                   const std::string &effective_path) {
    return effective_path == selection.path &&
           (selection.status == PreferenceFileStatus::CopyFailed ||
            selection.status ==
                PreferenceFileStatus::CopyFailedTemporaryRemaining);
}
