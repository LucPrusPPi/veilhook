#pragma once

#include <windows.h>
#include <cstdint>
#include <functional>
#include <memory>
#include <veilhook/veh_hub.hpp>

namespace veilhook::hwbp {

enum class Type {
    Execute = 0,
    Write = 1,
    ReadWrite = 3
};

enum class Length {
    Len1 = 0,
    Len2 = 1,
    Len4 = 3,
    Len8 = 2
};

using HwbpCallback = std::function<void(PEXCEPTION_POINTERS)>;

class Manager {
public:
    static Manager& get();

    // Set a hardware breakpoint on a specific thread.
    // Returns the slot index (0-3) on success, or -1 if no slots are available.
    int set(HANDLE thread, uintptr_t addr, Type type, Length length, HwbpCallback callback);
    
    // Clear a specific slot on a specific thread
    bool clear(HANDLE thread, int slot);

    // Helpers for the current thread
    int set_for_current_thread(uintptr_t addr, Type type, Length length, HwbpCallback callback);
    bool clear_for_current_thread(int slot);

private:
    Manager();
    ~Manager();

    bool handle_exception(PEXCEPTION_POINTERS ep);

    std::unique_ptr<veh::Subscription> veh_sub_;
    
    // Note: In MVP we are storing callbacks globally per address or per thread.
    // Realistically, Dr0-Dr3 is per-thread, so our dispatcher needs to find the callback.
    // For simplicity, we can store callbacks keyed by address since we usually hook a specific address.
    struct HookEntry {
        uintptr_t addr;
        HwbpCallback callback;
    };
    
    std::vector<HookEntry> hooks_;
    std::shared_mutex rw_lock_;
};

} // namespace veilhook::hwbp
