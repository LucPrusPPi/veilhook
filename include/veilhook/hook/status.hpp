#pragma once

namespace veilhook::hook {

enum class InstallStatus {
    Ok,
    AlreadyInstalled,
    BadPrologue,
    NoTrampolineMemory,
    TrampolineOverflow,
    TrampolineTooFar,
    PatchFailed,
    RelocFailed,
    PageBoundary,
    SectionMapFailed,
};

inline bool install_ok(InstallStatus status) {
    return status == InstallStatus::Ok || status == InstallStatus::AlreadyInstalled;
}

} // namespace veilhook::hook
