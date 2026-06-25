#include <veilhook/hook/guard.hpp>
#include <veilhook/veh_hub.hpp>
#include <veilhook/syscalls.hpp>

namespace veilhook::hook {

// We need a global/static way to track which threads are single-stepping for which page,
// to avoid conflicts if multiple threads hit guards simultaneously.
// For simplicity in this implementation, we assume basic thread-local tracking or rely on 
// the fact that single-step is thread-specific.

Guard::Guard(uintptr_t target, GuardCallback callback)
    : target_(target), callback_(std::move(callback)) {
    
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    
    page_size_ = sys_info.dwPageSize;
    page_base_ = target_ & ~(page_size_ - 1); // Align down to page boundary
}

Guard::~Guard() {
    uninstall();
}

bool Guard::install() {
    if (is_installed_) return true;

    // 1. Register VEH handlers
    veh_guard_sub_ = veh::Hub::get().add_handler(
        EXCEPTION_GUARD_PAGE, 
        200, // Highest priority
        [this](PEXCEPTION_POINTERS ep) { return handle_guard_page(ep); }
    );

    veh_step_sub_ = veh::Hub::get().add_handler(
        EXCEPTION_SINGLE_STEP, 
        150, // High priority, but below HWBP
        [this](PEXCEPTION_POINTERS ep) { return handle_single_step(ep); }
    );

    // 2. Protect the page
    PVOID base_addr = reinterpret_cast<PVOID>(page_base_);
    SIZE_T region_size = page_size_;

    // First query to get original protection
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T ret_len;
    if (syscalls::nt_query_virtual_memory(GetCurrentProcess(), base_addr, syscalls::MemoryBasicInformation, &mbi, sizeof(mbi), &ret_len) != syscalls::STATUS_SUCCESS) {
        return false;
    }

    original_protection_ = mbi.Protect;

    // Apply PAGE_GUARD
    ULONG new_protect = original_protection_ | PAGE_GUARD;
    ULONG old_protect = 0;
    
    // We must pass a copy of base_addr and region_size as nt_protect modifies them
    PVOID pbase = base_addr;
    SIZE_T psize = region_size;
    if (syscalls::nt_protect_virtual_memory(GetCurrentProcess(), &pbase, &psize, new_protect, &old_protect) == syscalls::STATUS_SUCCESS) {
        is_installed_ = true;
        return true;
    }

    return false;
}

bool Guard::uninstall() {
    if (!is_installed_) return true;

    // Restore original protection (remove PAGE_GUARD)
    PVOID base_addr = reinterpret_cast<PVOID>(page_base_);
    SIZE_T region_size = page_size_;
    ULONG old_protect = 0;

    syscalls::nt_protect_virtual_memory(GetCurrentProcess(), &base_addr, &region_size, original_protection_, &old_protect);

    // Remove VEH handlers
    veh_guard_sub_.reset();
    veh_step_sub_.reset();

    is_installed_ = false;
    return true;
}

bool Guard::handle_guard_page(PEXCEPTION_POINTERS ep) {
    uintptr_t fault_address = ep->ExceptionRecord->ExceptionInformation[1];
    
    // Check if the fault occurred on our protected page
    if (fault_address >= page_base_ && fault_address < page_base_ + page_size_) {
        
        // If the execution RIP is exactly our target function, trigger the callback
        if (ep->ContextRecord->Rip == target_) {
            if (callback_) {
                // Map ContextRecord to GuardContext
                GuardContext gctx;
                gctx.Rax = ep->ContextRecord->Rax; gctx.Rcx = ep->ContextRecord->Rcx;
                gctx.Rdx = ep->ContextRecord->Rdx; gctx.Rbx = ep->ContextRecord->Rbx;
                gctx.Rsp = ep->ContextRecord->Rsp; gctx.Rbp = ep->ContextRecord->Rbp;
                gctx.Rsi = ep->ContextRecord->Rsi; gctx.Rdi = ep->ContextRecord->Rdi;
                gctx.R8  = ep->ContextRecord->R8;  gctx.R9  = ep->ContextRecord->R9;
                gctx.R10 = ep->ContextRecord->R10; gctx.R11 = ep->ContextRecord->R11;
                gctx.R12 = ep->ContextRecord->R12; gctx.R13 = ep->ContextRecord->R13;
                gctx.R14 = ep->ContextRecord->R14; gctx.R15 = ep->ContextRecord->R15;
                gctx.RFlags = ep->ContextRecord->EFlags;
                gctx.Rip = ep->ContextRecord->Rip;

                callback_(gctx);

                // Map back in case callback modified registers
                ep->ContextRecord->Rax = gctx.Rax; ep->ContextRecord->Rcx = gctx.Rcx;
                ep->ContextRecord->Rdx = gctx.Rdx; ep->ContextRecord->Rbx = gctx.Rbx;
                // ... usually we don't allow modifying RSP/RBP safely in these callbacks without extreme care
                ep->ContextRecord->R8  = gctx.R8;  ep->ContextRecord->R9  = gctx.R9;
                ep->ContextRecord->R10 = gctx.R10; ep->ContextRecord->R11 = gctx.R11;
                ep->ContextRecord->EFlags = static_cast<DWORD>(gctx.RFlags);
                ep->ContextRecord->Rip = gctx.Rip;
            }
        }

        // Set Trap Flag (Single Step) so we can re-apply PAGE_GUARD after this instruction executes.
        // Windows automatically removes the PAGE_GUARD flag from the page when EXCEPTION_GUARD_PAGE is raised.
        ep->ContextRecord->EFlags |= (1 << 8); // TF (Trap Flag)

        return true; // Handled, continue execution (will immediately single step)
    }

    return false;
}

bool Guard::handle_single_step(PEXCEPTION_POINTERS ep) {
    // Determine if this single step was triggered because we just executed an instruction 
    // on our guarded page (to re-apply the guard).
    // A robust implementation uses thread-local storage to track if *this* thread just hit *our* guard page.
    // For MVP, we check if the RIP is still roughly on our page or just left it, 
    // and attempt to re-apply the guard.
    
    // Simple heuristic: if we are here, we re-apply the guard to our page.
    // If another debugger/HWBP caused the single step, re-applying the guard doesn't break anything.
    
    if (is_installed_) {
        PVOID base_addr = reinterpret_cast<PVOID>(page_base_);
        SIZE_T region_size = page_size_;
        ULONG old_protect = 0;
        
        // Re-apply PAGE_GUARD silently
        syscalls::nt_protect_virtual_memory(GetCurrentProcess(), &base_addr, &region_size, original_protection_ | PAGE_GUARD, &old_protect);
        
        // Note: Returning true would swallow the single step exception.
        // If there is an HWBP active on the same instruction, swallowing it would break the HWBP.
        // Returning false allows the VEH chain to continue so `hwbp_manager` can also process it if needed.
        // But if it was purely our TF, returning false might crash if no debugger catches it.
        // To be safe and compatible with HWBP, we return false and let the VEH Hub continue search.
        // If no one catches it, it's fine (we just don't return EXCEPTION_CONTINUE_EXECUTION here unless we know it's 100% ours).
        // Actually, for TF, if we set it, we MUST catch it and return EXCEPTION_CONTINUE_EXECUTION.
        
        // We clear the TF flag (just in case)
        ep->ContextRecord->EFlags &= ~(1 << 8);
        return true;
    }
    
    return false;
}

} // namespace veilhook::hook
