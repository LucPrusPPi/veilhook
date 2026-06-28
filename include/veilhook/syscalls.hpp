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

using NtCreateSectionFn = NTSTATUS(NTAPI*)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

using NtMapViewOfSectionFn = NTSTATUS(NTAPI*)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition, // Actually SECTION_INHERIT
    ULONG AllocationType,
    ULONG Win32Protect
);

using NtUnmapViewOfSectionFn = NTSTATUS(NTAPI*)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
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

NTSTATUS nt_create_section(
    PHANDLE section_handle,
    ACCESS_MASK desired_access,
    POBJECT_ATTRIBUTES object_attributes,
    PLARGE_INTEGER maximum_size,
    ULONG section_page_protection,
    ULONG allocation_attributes,
    HANDLE file_handle
);

NTSTATUS nt_map_view_of_section(
    HANDLE section_handle,
    HANDLE process_handle,
    PVOID* base_address,
    ULONG_PTR zero_bits,
    SIZE_T commit_size,
    PLARGE_INTEGER section_offset,
    PSIZE_T view_size,
    DWORD inherit_disposition,
    ULONG allocation_type,
    ULONG win32_protect
);

NTSTATUS nt_unmap_view_of_section(
    HANDLE process_handle,
    PVOID base_address
);

} // namespace veilhook::syscalls
