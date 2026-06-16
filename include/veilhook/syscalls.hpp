#pragma once
#include <windows.h>
#include <winternl.h>
#include <cstdint>

namespace veilhook::syscalls {

constexpr NTSTATUS STATUS_SUCCESS = static_cast<NTSTATUS>(0x00000000);
constexpr NTSTATUS STATUS_UNSUCCESSFUL = static_cast<NTSTATUS>(0xC0000001);

// Initialize HalosGate resolver
bool init();

// We don't use HWBP for syscalls here. Instead, we use dynamically assembled 
// indirect syscall stubs to invoke the functions directly via a legitimate 
// ntdll 'syscall; ret' gadget.

// Syscall type definitions needed for Veilhook

using NtAllocateVirtualMemoryFn = NTSTATUS(NTAPI*)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

using NtFreeVirtualMemoryFn = NTSTATUS(NTAPI*)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

using NtProtectVirtualMemoryFn = NTSTATUS(NTAPI*)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

using NtGetContextThreadFn = NTSTATUS(NTAPI*)(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext
);

using NtSetContextThreadFn = NTSTATUS(NTAPI*)(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext
);

using NtSuspendThreadFn = NTSTATUS(NTAPI*)(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
);

using NtResumeThreadFn = NTSTATUS(NTAPI*)(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
);

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

using NtQueryVirtualMemoryFn = NTSTATUS(NTAPI*)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
);

// Our stealth wrapper functions:

NTSTATUS nt_allocate_virtual_memory(
    HANDLE process_handle,
    PVOID* base_address,
    ULONG_PTR zero_bits,
    PSIZE_T region_size,
    ULONG allocation_type,
    ULONG protect
);

NTSTATUS nt_free_virtual_memory(
    HANDLE process_handle,
    PVOID* base_address,
    PSIZE_T region_size,
    ULONG free_type
);

NTSTATUS nt_protect_virtual_memory(
    HANDLE process_handle,
    PVOID* base_address,
    PSIZE_T region_size,
    ULONG new_protect,
    PULONG old_protect
);

NTSTATUS nt_get_context_thread(
    HANDLE thread_handle,
    PCONTEXT thread_context
);

NTSTATUS nt_set_context_thread(
    HANDLE thread_handle,
    PCONTEXT thread_context
);

NTSTATUS nt_suspend_thread(
    HANDLE thread_handle,
    PULONG previous_suspend_count
);

NTSTATUS nt_resume_thread(
    HANDLE thread_handle,
    PULONG previous_suspend_count
);

NTSTATUS nt_query_virtual_memory(
    HANDLE process_handle,
    PVOID base_address,
    MEMORY_INFORMATION_CLASS memory_information_class,
    PVOID memory_information,
    SIZE_T memory_information_length,
    PSIZE_T return_length
);

} // namespace veilhook::syscalls
