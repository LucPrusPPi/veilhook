#include <veilhook/syscalls.hpp>
#include <veilhook/xorstr.hpp>
#include <asmjit/asmjit.h>
#include <vector>
#include <string_view>
#include <cwctype>
#include <unordered_map>
#include <stdexcept>
#include <iostream>

namespace veilhook::syscalls {

namespace {

struct UNICODE_STRING_LDR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};

struct LDR_DATA_TABLE_ENTRY_LDR {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING_LDR FullDllName;
    UNICODE_STRING_LDR BaseDllName;
};

struct PEB_LDR_DATA_LDR {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
};

struct PEB_LDR {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[21];
    PEB_LDR_DATA_LDR* Ldr;
};

bool wstr_equal_case_insensitive(std::wstring_view s1, std::wstring_view s2) {
    if (s1.length() != s2.length())
        return false;
    return std::equal(s1.begin(), s1.end(), s2.begin(), [](wchar_t a, wchar_t b) {
        return std::towlower(a) == std::towlower(b);
    });
}

std::uintptr_t get_module_base_peb(std::wstring_view module_name) {
#ifdef _WIN64
    auto* peb = reinterpret_cast<PEB_LDR*>(__readgsqword(0x60));
#else
    return 0; // x64 only supported
#endif
    if (!peb || !peb->Ldr)
        return 0;

    auto* list_head = &peb->Ldr->InMemoryOrderModuleList;
    for (auto* it = list_head->Flink; it != list_head; it = it->Flink) {
        auto* entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY_LDR*>(
            reinterpret_cast<std::uint8_t*>(it) - offsetof(LDR_DATA_TABLE_ENTRY_LDR, InMemoryOrderLinks)
        );

        if (entry->BaseDllName.Buffer) {
            std::wstring_view current_name(entry->BaseDllName.Buffer, entry->BaseDllName.Length / sizeof(wchar_t));
            if (wstr_equal_case_insensitive(current_name, module_name)) {
                return reinterpret_cast<std::uintptr_t>(entry->DllBase);
            }
        }
    }
    return 0;
}

std::uintptr_t get_symbol_address_peb(std::uintptr_t module_base, std::string_view function_name) {
    if (!module_base) return 0;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module_base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(module_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    auto export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!export_rva) return 0;

    auto* exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(module_base + export_rva);
    auto* names = reinterpret_cast<DWORD*>(module_base + exports->AddressOfNames);
    auto* ordinals = reinterpret_cast<WORD*>(module_base + exports->AddressOfNameOrdinals);
    auto* functions = reinterpret_cast<DWORD*>(module_base + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
        const char* current_name = reinterpret_cast<const char*>(module_base + names[i]);
        if (function_name == current_name) {
            return module_base + functions[ordinals[i]];
        }
    }
    return 0;
}

std::uintptr_t find_syscall_return_address(std::uintptr_t function_address) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(function_address);
    for (WORD idx = 0; idx < 32; idx++) {
        if (p[idx] == 0x0F && p[idx + 1] == 0x05) { // syscall
            return function_address + idx;
        }
    }
    return 0;
}

WORD find_syscall_number(std::uintptr_t function_address) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(function_address);
    constexpr std::ptrdiff_t DOWN = 32;
    constexpr std::ptrdiff_t UP = -32;
    
    // mov r10, rcx; mov eax, SSN
    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) {
        return *reinterpret_cast<const WORD*>(p + 4);
    }

    // HalosGate fallback (search neighbors if hooked)
    for (WORD idx = 1; idx <= 500; idx++) {
        // Down
        const auto* p_down = reinterpret_cast<const std::uint8_t*>(function_address + idx * DOWN);
        if (p_down[0] == 0x4C && p_down[1] == 0x8B && p_down[2] == 0xD1 && p_down[3] == 0xB8) {
            WORD ssn = *reinterpret_cast<const WORD*>(p_down + 4);
            return ssn - idx;
        }

        // Up
        const auto* p_up = reinterpret_cast<const std::uint8_t*>(function_address + idx * UP);
        if (p_up[0] == 0x4C && p_up[1] == 0x8B && p_up[2] == 0xD1 && p_up[3] == 0xB8) {
            WORD ssn = *reinterpret_cast<const WORD*>(p_up + 4);
            return ssn + idx;
        }
    }
    return 0;
}

std::uintptr_t g_ntdll_base = 0;

struct SyscallStub {
    void* memory = nullptr;
    size_t size = 0;
};

std::unordered_map<std::string, SyscallStub> g_syscall_stubs;
asmjit::JitRuntime g_jit_runtime;

    SyscallStub create_syscall_stub(std::string_view name) {
    std::uintptr_t target_fn = get_symbol_address_peb(g_ntdll_base, name);
    if (!target_fn) throw std::runtime_error("Failed to find NT function");

    WORD ssn = find_syscall_number(target_fn);
    if (!ssn) throw std::runtime_error("Failed to resolve SSN via HalosGate");

    std::uintptr_t syscall_gadget = find_syscall_return_address(target_fn);
    if (!syscall_gadget) throw std::runtime_error("Failed to find syscall gadget");

    std::cout << "[Syscalls DEBUG] " << name << " | Target: " << std::hex << target_fn 
              << " | SSN: " << ssn << " | Gadget: " << syscall_gadget << std::dec << std::endl;

    asmjit::CodeHolder code;
    code.init(g_jit_runtime.environment());
    asmjit::x86::Assembler a(&code);

    using namespace asmjit::x86;
    
    // mov r10, rcx
    a.mov(r10, rcx);
    // mov eax, SSN
    a.mov(eax, ssn);
    // jmp [syscall_gadget]
    a.mov(r11, syscall_gadget);
    a.jmp(r11);

    void* fn_ptr;
    asmjit::Error err = g_jit_runtime.add(&fn_ptr, &code);
    if (err) throw std::runtime_error("Failed to compile syscall stub");

    return { fn_ptr, code.codeSize() };
}

void* get_syscall_stub(const char* name) {
    if (g_syscall_stubs.find(name) == g_syscall_stubs.end()) {
        g_syscall_stubs[name] = create_syscall_stub(name);
    }
    return g_syscall_stubs[name].memory;
}

} // namespace

bool init() {
    g_ntdll_base = get_module_base_peb(L"ntdll.dll");
    return g_ntdll_base != 0;
}

NTSTATUS nt_allocate_virtual_memory(
    HANDLE process_handle,
    PVOID* base_address,
    ULONG_PTR zero_bits,
    PSIZE_T region_size,
    ULONG allocation_type,
    ULONG protect)
{
    using Fn = NtAllocateVirtualMemoryFn;
    auto stub = reinterpret_cast<Fn>(get_syscall_stub(_XOR("NtAllocateVirtualMemory")));
    return stub(process_handle, base_address, zero_bits, region_size, allocation_type, protect);
}

NTSTATUS nt_free_virtual_memory(
    HANDLE process_handle,
    PVOID* base_address,
    PSIZE_T region_size,
    ULONG free_type)
{
    using Fn = NtFreeVirtualMemoryFn;
    auto stub = reinterpret_cast<Fn>(get_syscall_stub(_XOR("NtFreeVirtualMemory")));
    return stub(process_handle, base_address, region_size, free_type);
}

NTSTATUS nt_protect_virtual_memory(
    HANDLE process_handle,
    PVOID* base_address,
    PSIZE_T region_size,
    ULONG new_protect,
    PULONG old_protect)
{
    using Fn = NtProtectVirtualMemoryFn;
    auto stub = reinterpret_cast<Fn>(get_syscall_stub(_XOR("NtProtectVirtualMemory")));
    return stub(process_handle, base_address, region_size, new_protect, old_protect);
}

NTSTATUS nt_get_context_thread(
    HANDLE thread_handle,
    PCONTEXT thread_context)
{
    using Fn = NtGetContextThreadFn;
    auto stub = reinterpret_cast<Fn>(get_syscall_stub(_XOR("NtGetContextThread")));
    return stub(thread_handle, thread_context);
}

NTSTATUS nt_set_context_thread(
    HANDLE thread_handle,
    PCONTEXT thread_context)
{
    using Fn = NtSetContextThreadFn;
    auto stub = reinterpret_cast<Fn>(get_syscall_stub(_XOR("NtSetContextThread")));
    return stub(thread_handle, thread_context);
}

NTSTATUS nt_suspend_thread(
    HANDLE thread_handle,
    PULONG previous_suspend_count)
{
    using Fn = NtSuspendThreadFn;
    auto stub = reinterpret_cast<Fn>(get_syscall_stub(_XOR("NtSuspendThread")));
    return stub(thread_handle, previous_suspend_count);
}

NTSTATUS nt_resume_thread(
    HANDLE thread_handle,
    PULONG previous_suspend_count)
{
    using Fn = NtResumeThreadFn;
    auto stub = reinterpret_cast<Fn>(get_syscall_stub(_XOR("NtResumeThread")));
    return stub(thread_handle, previous_suspend_count);
}

NTSTATUS nt_query_virtual_memory(
    HANDLE process_handle,
    PVOID base_address,
    MEMORY_INFORMATION_CLASS memory_information_class,
    PVOID memory_information,
    SIZE_T memory_information_length,
    PSIZE_T return_length)
{
    using Fn = NtQueryVirtualMemoryFn;
    auto stub = reinterpret_cast<Fn>(get_syscall_stub(_XOR("NtQueryVirtualMemory")));
    return stub(process_handle, base_address, memory_information_class, memory_information, memory_information_length, return_length);
}
NTSTATUS nt_create_section(
    PHANDLE section_handle,
    ACCESS_MASK desired_access,
    POBJECT_ATTRIBUTES object_attributes,
    PLARGE_INTEGER maximum_size,
    ULONG section_page_protection,
    ULONG allocation_attributes,
    HANDLE file_handle)
{
    using Fn = NtCreateSectionFn;
    auto stub = reinterpret_cast<Fn>(get_syscall_stub(_XOR("NtCreateSection")));
    return stub(section_handle, desired_access, object_attributes, maximum_size, section_page_protection, allocation_attributes, file_handle);
}

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
    ULONG win32_protect)
{
    using Fn = NtMapViewOfSectionFn;
    auto stub = reinterpret_cast<Fn>(get_syscall_stub(_XOR("NtMapViewOfSection")));
    return stub(section_handle, process_handle, base_address, zero_bits, commit_size, section_offset, view_size, inherit_disposition, allocation_type, win32_protect);
}

NTSTATUS nt_unmap_view_of_section(
    HANDLE process_handle,
    PVOID base_address)
{
    using Fn = NtUnmapViewOfSectionFn;
    auto stub = reinterpret_cast<Fn>(get_syscall_stub(_XOR("NtUnmapViewOfSection")));
    return stub(process_handle, base_address);
}
} // namespace veilhook::syscalls
