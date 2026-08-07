#include "handler/settings_view.h"

#include <atomic>
#include <utility>

#include "handler/settings.h"

namespace {

std::atomic<SettingsSnapshot> published_settings{
    std::make_shared<const Settings>()};
thread_local SettingsSnapshot request_settings;

} // namespace

void publishSettingsSnapshot(const Settings &settings) {
  SettingsSnapshot next = std::make_shared<const Settings>(settings);
  published_settings.store(std::move(next), std::memory_order_release);
}

SettingsSnapshot captureSettingsSnapshot() {
  return published_settings.load(std::memory_order_acquire);
}

const Settings &effectiveSettings() {
  return request_settings ? *request_settings : global;
}

SettingsSnapshot captureEffectiveSettingsSnapshot() {
  return request_settings ? request_settings : captureSettingsSnapshot();
}

ScopedSettingsView::ScopedSettingsView(SettingsSnapshot snapshot)
    : previous_(std::move(request_settings)) {
  request_settings = std::move(snapshot);
}

ScopedSettingsView::~ScopedSettingsView() {
  request_settings = std::move(previous_);
}
