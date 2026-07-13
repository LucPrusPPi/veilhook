#include <veilhook/hook/phantom.hpp>
#include <veilhook/cave_alloc.hpp>
#include <veilhook/decode.hpp>
#include <veilhook/reloc.hpp>
#include <veilhook/syscalls.hpp>
#include <asmjit/asmjit.h>
#include <tlhelp32.h>
#include <cstring>

#ifndef SEC_COMMIT
#define SEC_COMMIT 0x8000000
#endif

// To support the inherit_disposition properly:
typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

namespace veilhook::hook {
namespace {

bool protect_page(PVOID page_base, SIZE_T page_size, ULONG new_protect, ULONG* old_protect) {
    PVOID base = page_base;
    SIZE_T region = page_size;
    if (syscalls::nt_protect_virtual_memory(
            GetCurrentProcess(), &base, &region, new_protect, old_protect) == syscalls::STATUS_SUCCESS) {
        return true;
    }

    DWORD old_dw = 0;
    if (VirtualProtect(page_base, page_size, new_protect, &old_dw)) {
        if (old_protect) {
            *old_protect = old_dw;
        }
        return true;
    }

    return false;
}

// Thread suspension helper for safe installation
static bool suspend_all_threads(std::vector<HANDLE>& suspended_threads) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    DWORD current_process_id = GetCurrentProcessId();
    DWORD current_thread_id = GetCurrentThreadId();

    THREADENTRY32 te32;
    te32.dwSize = sizeof(te32);

    if (Thread32First(snapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == current_process_id && te32.th32ThreadID != current_thread_id) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID);
                if (hThread) {
                    ULONG suspend_count;
                    syscalls::nt_suspend_thread(hThread, &suspend_count);
                    suspended_threads.push_back(hThread);
                }
            }
        } while (Thread32Next(snapshot, &te32));
    }
    CloseHandle(snapshot);
    return true;
}

static void resume_all_threads(const std::vector<HANDLE>& suspended_threads) {
    for (HANDLE hThread : suspended_threads) {
        ULONG suspend_count;
        syscalls::nt_resume_thread(hThread, &suspend_count);
        CloseHandle(hThread);
    }
}

} // namespace

Phantom::Phantom(uintptr_t target, uintptr_t destination)
    : target_(target), destination_(destination) {}

Phantom::~Phantom() {
    uninstall();
}

bool Phantom::install() {
    VEIL_JUNK_CODE();
    if (is_installed_) {
        last_status_ = InstallStatus::AlreadyInstalled;
        return true;
    }

    decode::InstructionView decoder;
    
    // Check if we need 14 bytes (far jump) or 5 bytes (near jump)
    size_t required_jmp_size = 5;
    int64_t rel_disp_check = static_cast<int64_t>(destination_) - static_cast<int64_t>(target_ + 5);
    if (std::abs(rel_disp_check) > 0x7FFFFFFF) {
        required_jmp_size = 14;
    }

    patch_size_ = decoder.get_boundary_length(reinterpret_cast<uint8_t*>(target_), required_jmp_size);
    if (patch_size_ == 0) {
        last_status_ = InstallStatus::BadPrologue;
        return false;
    }

    original_bytes_.resize(patch_size_);
    std::memcpy(original_bytes_.data(), reinterpret_cast<void*>(target_), patch_size_);

    // 1. Calculate Page Alignments
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    size_t page_size = sys_info.dwPageSize;
    page_size_ = page_size;
    
    uintptr_t page_base = target_ & ~(page_size - 1);
    size_t offset_in_page = target_ - page_base;
    
    // If the hook crosses a page boundary, we'd need to remap 2 pages. 
    // For simplicity of MVP, we check if it fits in 1 page.
    if (offset_in_page + patch_size_ > page_size) {
        last_status_ = InstallStatus::PageBoundary;
        return false;
    }

    // 2. We need a trampoline to call the original function.
    // For Phantom hooking, we can just use our existing cave allocator logic
    // to build a trampoline out-of-bounds, since the view mapping itself handles the stealth.
    // Actually, to make it even more stealthy, we could map a custom cave. 
    // We'll use CaveAlloc.
    
    trampoline_size_ = patch_size_ * 4 + 128;
    trampoline_ = mem::CaveAlloc::get().allocate(target_, trampoline_size_);
    if (!trampoline_) {
        last_status_ = InstallStatus::NoTrampolineMemory;
        return false;
    }

    asmjit::JitRuntime rt;
    asmjit::CodeHolder code;
    code.init(rt.environment(), reinterpret_cast<uint64_t>(trampoline_));
    asmjit::x86::Assembler a(&code);

    original_callable_ = trampoline_;

    std::vector<reloc::InstSite> reloc_sites;
    reloc::BranchSlotTable branch_slots;
    const auto reloc_status = reloc::emit_stolen_range(
        a,
        decoder.zydis_decoder(),
        original_bytes_.data(),
        patch_size_,
        static_cast<uint64_t>(target_),
        reinterpret_cast<uint64_t>(trampoline_),
        &reloc_sites,
        &branch_slots);

    if (reloc_status != reloc::Status::Ok) {
        mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
        trampoline_ = nullptr;
        last_status_ = InstallStatus::RelocFailed;
        return false;
    }

    reloc_sites_ = std::move(reloc_sites);

    reloc::emit_absolute_jump(a, target_ + patch_size_);
    reloc::emit_branch_slot_data(a, branch_slots);

    asmjit::CodeBuffer& tramp_buffer = code.sectionById(0)->buffer();
    if (tramp_buffer.size() > trampoline_size_) {
        mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
        trampoline_ = nullptr;
        last_status_ = InstallStatus::TrampolineOverflow;
        return false;
    }

    std::memcpy(trampoline_, tramp_buffer.data(), tramp_buffer.size());
    trampoline_size_ = tramp_buffer.size();

    ULONG tramp_old = 0;
    PVOID tramp_base = trampoline_;
    SIZE_T tramp_region = trampoline_size_;
    protect_page(tramp_base, tramp_region, PAGE_EXECUTE_READ, &tramp_old);

    // 3. Create a new Section backed by Pagefile (Memory mapped file)
    LARGE_INTEGER max_size;
    max_size.QuadPart = page_size;
    
    NTSTATUS status = syscalls::nt_create_section(
        &h_section_, SECTION_ALL_ACCESS, nullptr, &max_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr);
    if (status != syscalls::STATUS_SUCCESS) {
        mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
        trampoline_ = nullptr;
        last_status_ = InstallStatus::SectionMapFailed;
        return false;
    }

    // 4. Map the new section to a temporary local address
    PVOID temp_view = nullptr;
    SIZE_T view_size = page_size;
    
    status = syscalls::nt_map_view_of_section(
        h_section_, GetCurrentProcess(), &temp_view, 0, page_size, nullptr, &view_size, ViewUnmap, 0, PAGE_READWRITE);
    if (status != syscalls::STATUS_SUCCESS) {
        CloseHandle(h_section_);
        mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
        trampoline_ = nullptr;
        last_status_ = InstallStatus::SectionMapFailed;
        return false;
    }

    // 5. Copy original page contents into our new section
    std::memcpy(temp_view, reinterpret_cast<void*>(page_base), page_size);

    // 6. Apply the JMP Hook inside the temporary view
    uint8_t* temp_target = reinterpret_cast<uint8_t*>(temp_view) + offset_in_page;
    std::vector<uint8_t> patch(patch_size_, 0x90);
    int64_t rel_disp = static_cast<int64_t>(destination_) - static_cast<int64_t>(target_ + 5);
    
    if (std::abs(rel_disp) <= 0x7FFFFFFF) {
        patch[0] = 0xE9;
        *reinterpret_cast<int32_t*>(&patch[1]) = static_cast<int32_t>(rel_disp);
    } else {
        // Need 14 bytes for absolute jump in our section
        if (patch_size_ >= 14) {
            patch[0] = 0xFF; patch[1] = 0x25;
            *reinterpret_cast<int32_t*>(&patch[2]) = 0;
            *reinterpret_cast<uint64_t*>(&patch[6]) = destination_;
        } else {
            // Rel jump failed and no room for Far jump
            syscalls::nt_unmap_view_of_section(GetCurrentProcess(), temp_view);
            CloseHandle(h_section_);
            mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
            trampoline_ = nullptr;
            last_status_ = InstallStatus::TrampolineTooFar;
            return false;
        }
    }
    std::memcpy(temp_target, patch.data(), patch_size_);

    PVOID temp_protect_base = temp_view;
    SIZE_T temp_protect_size = page_size;
    ULONG temp_old = 0;
    protect_page(temp_protect_base, temp_protect_size, PAGE_EXECUTE_READ, &temp_old);

    // 7. Suspend threads to prevent race conditions during unmap/map
    std::vector<HANDLE> suspended_threads;
    suspend_all_threads(suspended_threads);

    // 8. The Remapping Magic
    // Unmap the original view (the game's module memory)
    PVOID base_addr = reinterpret_cast<PVOID>(page_base);
    NTSTATUS unmap_status = syscalls::nt_unmap_view_of_section(GetCurrentProcess(), base_addr);
    
    if (unmap_status != syscalls::STATUS_SUCCESS) {
        // We failed to unmap. The module might be locked or protected.
        resume_all_threads(suspended_threads);
        syscalls::nt_unmap_view_of_section(GetCurrentProcess(), temp_view);
        CloseHandle(h_section_);
        mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
        trampoline_ = nullptr;
        last_status_ = InstallStatus::PatchFailed;
        return false;
    }

    // Map our modified section into the exact same address
    SIZE_T map_size = page_size;
    // Final view stays RWX: section-backed RX remaps are unstable on uninstall.
    NTSTATUS map_status = syscalls::nt_map_view_of_section(
        h_section_, GetCurrentProcess(), &base_addr, 0, page_size, nullptr, &map_size, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);

    // Fix thread RIPs if they were executing in the overwritten hook bytes
    for (HANDLE hThread : suspended_threads) {
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (syscalls::nt_get_context_thread(hThread, &ctx) == syscalls::STATUS_SUCCESS) {
            if (ctx.Rip >= target_ && ctx.Rip < target_ + patch_size_) {
                ctx.Rip = reloc::translate_runtime_ip(
                    ctx.Rip,
                    target_,
                    patch_size_,
                    reinterpret_cast<uint64_t>(trampoline_),
                    reloc_sites_);
                syscalls::nt_set_context_thread(hThread, &ctx);
            }
        }
    }

    resume_all_threads(suspended_threads);

    // We no longer need the temporary local view
    syscalls::nt_unmap_view_of_section(GetCurrentProcess(), temp_view);

    if (map_status == syscalls::STATUS_SUCCESS) {
        is_installed_ = true;
        p_view_ = base_addr;
        last_status_ = InstallStatus::Ok;
        return true;
    }

    last_status_ = InstallStatus::SectionMapFailed;
    return false;
}

bool Phantom::uninstall() {
    VEIL_JUNK_CODE();
    if (!is_installed_) return true;

    std::vector<HANDLE> suspended_threads;
    suspend_all_threads(suspended_threads);

    ULONG old_protect = 0;
    protect_page(p_view_, page_size_, PAGE_EXECUTE_READWRITE, &old_protect);

    std::memcpy(reinterpret_cast<void*>(target_), original_bytes_.data(), patch_size_);

    for (HANDLE hThread : suspended_threads) {
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (syscalls::nt_get_context_thread(hThread, &ctx) == syscalls::STATUS_SUCCESS) {
            if (ctx.Rip >= target_ && ctx.Rip < target_ + patch_size_) {
                ctx.Rip = reloc::translate_runtime_ip(
                    ctx.Rip,
                    target_,
                    patch_size_,
                    reinterpret_cast<uint64_t>(trampoline_),
                    reloc_sites_);
                syscalls::nt_set_context_thread(hThread, &ctx);
            } else if (trampoline_ &&
                ctx.Rip >= reinterpret_cast<uint64_t>(trampoline_) &&
                ctx.Rip < reinterpret_cast<uint64_t>(trampoline_) + trampoline_size_) {
                ctx.Rip = reloc::translate_emit_ip_to_source(
                    ctx.Rip,
                    reinterpret_cast<uint64_t>(trampoline_),
                    trampoline_size_,
                    target_,
                    reloc_sites_);
                syscalls::nt_set_context_thread(hThread, &ctx);
            }
        }
    }

    resume_all_threads(suspended_threads);

    // We keep the section mapped, because unmapping it would leave a hole in memory.
    // The memory is effectively restored to its original execution state.
    // To truly free it, we'd need to leak it for the lifetime of the process, 
    // which is standard for these types of deep hooks.

    mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
    is_installed_ = false;
    return true;
}

} // namespace veilhook::hook
