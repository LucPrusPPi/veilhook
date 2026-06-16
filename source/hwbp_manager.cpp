#include <veilhook/hwbp_manager.hpp>
#include <veilhook/veh_hub.hpp>
#include <veilhook/syscalls.hpp>
#include <algorithm>

namespace veilhook::hwbp {

Manager& Manager::get() {
    static Manager instance;
    return instance;
}

Manager::Manager() {
    veh_sub_ = veh::Hub::get().add_handler(
        EXCEPTION_SINGLE_STEP, 
        100, // High priority
        [this](PEXCEPTION_POINTERS ep) { return handle_exception(ep); }
    );
}

Manager::~Manager() = default;

int Manager::set(HANDLE thread, uintptr_t addr, Type type, Length length, HwbpCallback callback) {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (syscalls::nt_get_context_thread(thread, &ctx) != syscalls::STATUS_SUCCESS) {
        return -1;
    }

    int available_slot = -1;
    for (int i = 0; i < 4; ++i) {
        if ((ctx.Dr7 & (1ull << (i * 2))) == 0) {
            available_slot = i;
            break;
        }
    }

    if (available_slot == -1) {
        return -1;
    }

    switch (available_slot) {
        case 0: ctx.Dr0 = addr; break;
        case 1: ctx.Dr1 = addr; break;
        case 2: ctx.Dr2 = addr; break;
        case 3: ctx.Dr3 = addr; break;
    }

    // Set local enable bit
    ctx.Dr7 |= (1ull << (available_slot * 2));

    // Clear previous length/type for this slot
    ctx.Dr7 &= ~(0xFull << (16 + available_slot * 4));

    // Set new length and type
    uint64_t condition = (static_cast<uint64_t>(type) | (static_cast<uint64_t>(length) << 2));
    ctx.Dr7 |= (condition << (16 + available_slot * 4));

    if (syscalls::nt_set_context_thread(thread, &ctx) != syscalls::STATUS_SUCCESS) {
        return -1;
    }

    std::unique_lock lock(rw_lock_);
    
    // Add or update callback
    auto it = std::find_if(hooks_.begin(), hooks_.end(), [addr](const HookEntry& e) { return e.addr == addr; });
    if (it != hooks_.end()) {
        it->callback = std::move(callback);
    } else {
        hooks_.push_back({addr, std::move(callback)});
    }

    return available_slot;
}

bool Manager::clear(HANDLE thread, int slot) {
    if (slot < 0 || slot > 3) return false;

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (syscalls::nt_get_context_thread(thread, &ctx) != syscalls::STATUS_SUCCESS) {
        return false;
    }

    // Clear local enable bit
    ctx.Dr7 &= ~(1ull << (slot * 2));
    
    // Clear length/type
    ctx.Dr7 &= ~(0xFull << (16 + slot * 4));

    switch (slot) {
        case 0: ctx.Dr0 = 0; break;
        case 1: ctx.Dr1 = 0; break;
        case 2: ctx.Dr2 = 0; break;
        case 3: ctx.Dr3 = 0; break;
    }

    return syscalls::nt_set_context_thread(thread, &ctx) == syscalls::STATUS_SUCCESS;
}

int Manager::set_for_current_thread(uintptr_t addr, Type type, Length length, HwbpCallback callback) {
    return set(GetCurrentThread(), addr, type, length, std::move(callback));
}

bool Manager::clear_for_current_thread(int slot) {
    return clear(GetCurrentThread(), slot);
}

bool Manager::handle_exception(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
        return false;
    }

    // Check Dr6 to see which breakpoint triggered
    uintptr_t dr6 = ep->ContextRecord->Dr6;
    int triggered_slot = -1;
    
    for (int i = 0; i < 4; ++i) {
        if (dr6 & (1ull << i)) {
            triggered_slot = i;
            break;
        }
    }

    if (triggered_slot == -1) {
        return false; // Could be EFLAGS.TF single step
    }

    // Clear the triggered status in Dr6
    ep->ContextRecord->Dr6 &= ~(1ull << triggered_slot);

    uintptr_t addr = 0;
    switch (triggered_slot) {
        case 0: addr = ep->ContextRecord->Dr0; break;
        case 1: addr = ep->ContextRecord->Dr1; break;
        case 2: addr = ep->ContextRecord->Dr2; break;
        case 3: addr = ep->ContextRecord->Dr3; break;
    }

    HwbpCallback cb;
    {
        std::shared_lock lock(rw_lock_);
        auto it = std::find_if(hooks_.begin(), hooks_.end(), [addr](const HookEntry& e) { return e.addr == addr; });
        if (it != hooks_.end()) {
            cb = it->callback;
        }
    }

    if (cb) {
        cb(ep);
        // Set Resume Flag to step over the breakpoint without triggering it again immediately
        ep->ContextRecord->EFlags |= (1 << 16); // RF flag
        return true;
    }

    return false;
}

} // namespace veilhook::hwbp
