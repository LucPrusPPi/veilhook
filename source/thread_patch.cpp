#include <veilhook/thread_patch.hpp>
#include <veilhook/syscalls.hpp>
#include <tlhelp32.h>
#include <cstring>
#include <vector>

namespace veilhook::thread_patch {

bool suspend_others_and_patch(
    uintptr_t target,
    size_t patch_size,
    const std::vector<uint8_t>& patch_bytes,
    uint8_t* trampoline)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    const DWORD pid = GetCurrentProcessId();
    const DWORD tid = GetCurrentThreadId();
    std::vector<HANDLE> suspended;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);

    if (Thread32First(snapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == pid && te.th32ThreadID != tid) {
                HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (h) {
                    ULONG count = 0;
                    if (syscalls::nt_suspend_thread(h, &count) == syscalls::STATUS_SUCCESS) {
                        suspended.push_back(h);
                    } else {
                        CloseHandle(h);
                    }
                }
            }
        } while (Thread32Next(snapshot, &te));
    }
    CloseHandle(snapshot);

    ULONG old_protect = 0;
    bool ok = false;
    PVOID base = reinterpret_cast<PVOID>(target);
    SIZE_T region = patch_bytes.size();

    if (syscalls::nt_protect_virtual_memory(GetCurrentProcess(), &base, &region, PAGE_EXECUTE_READWRITE, &old_protect)
        == syscalls::STATUS_SUCCESS)
    {
        if (trampoline) {
            for (HANDLE h : suspended) {
                CONTEXT ctx{};
                ctx.ContextFlags = CONTEXT_CONTROL;
                if (syscalls::nt_get_context_thread(h, &ctx) == syscalls::STATUS_SUCCESS) {
                    if (ctx.Rip >= target && ctx.Rip < target + patch_size) {
                        const size_t offset = ctx.Rip - target;
                        ctx.Rip = reinterpret_cast<DWORD64>(trampoline) + offset;
                        syscalls::nt_set_context_thread(h, &ctx);
                    }
                }
            }
        }

        std::memcpy(reinterpret_cast<void*>(target), patch_bytes.data(), patch_bytes.size());

        base = reinterpret_cast<PVOID>(target);
        region = patch_bytes.size();
        syscalls::nt_protect_virtual_memory(GetCurrentProcess(), &base, &region, old_protect, &old_protect);
        ok = true;
    }

    for (HANDLE h : suspended) {
        ULONG count = 0;
        syscalls::nt_resume_thread(h, &count);
        CloseHandle(h);
    }

    return ok;
}

} // namespace veilhook::thread_patch
