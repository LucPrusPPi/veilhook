#include <veilhook/syscalls.hpp>
#include <veilhook/xorstr.hpp>
#include <asmjit/asmjit.h>
#include <array>
#include <string_view>
#include <cwctype>

namespace veilhook::syscalls {

namespace {

struct UNICODE_STRING_LDR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
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

enum class StubId : uint8_t {
    AllocateVirtualMemory = 0,
    FreeVirtualMemory,
    ProtectVirtualMemory,
    GetContextThread,
    SetContextThread,
    SuspendThread,
    ResumeThread,
    QueryVirtualMemory,
    CreateSection,
    MapViewOfSection,
    UnmapViewOfSection,
    Count
};

bool wstr_equal_case_insensitive(std::wstring_view s1, std::wstring_view s2) {
    if (s1.length() != s2.length()) {
        return false;
    }
    return std::equal(s1.begin(), s1.end(), s2.begin(), [](wchar_t a, wchar_t b) {
        return std::towlower(a) == std::towlower(b);
    });
}

std::uintptr_t get_module_base_peb(std::wstring_view module_name) {
#ifdef _WIN64
    auto* peb = reinterpret_cast<PEB_LDR*>(__readgsqword(0x60));
#else
    return 0;
#endif
    if (!peb || !peb->Ldr) {
        return 0;
    }

    auto* list_head = &peb->Ldr->InMemoryOrderModuleList;
    for (auto* it = list_head->Flink; it != list_head; it = it->Flink) {
        auto* entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY_LDR*>(
            reinterpret_cast<std::uint8_t*>(it) - offsetof(LDR_DATA_TABLE_ENTRY_LDR, InMemoryOrderLinks));

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
    if (!module_base) {
        return 0;
    }

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module_base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(module_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    const auto export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!export_rva) {
        return 0;
    }

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
    for (WORD idx = 0; idx < 32; ++idx) {
        if (p[idx] == 0x0F && p[idx + 1] == 0x05) {
            return function_address + idx;
        }
    }
    return 0;
}

WORD find_syscall_number(std::uintptr_t function_address) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(function_address);
    constexpr std::ptrdiff_t kDown = 32;
    constexpr std::ptrdiff_t kUp = -32;

    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) {
        return *reinterpret_cast<const WORD*>(p + 4);
    }

    for (WORD idx = 1; idx <= 500; ++idx) {
        const auto* p_down = reinterpret_cast<const std::uint8_t*>(function_address + idx * kDown);
        if (p_down[0] == 0x4C && p_down[1] == 0x8B && p_down[2] == 0xD1 && p_down[3] == 0xB8) {
            const WORD ssn = *reinterpret_cast<const WORD*>(p_down + 4);
            return static_cast<WORD>(ssn - idx);
        }

        const auto* p_up = reinterpret_cast<const std::uint8_t*>(function_address + idx * kUp);
        if (p_up[0] == 0x4C && p_up[1] == 0x8B && p_up[2] == 0xD1 && p_up[3] == 0xB8) {
            const WORD ssn = *reinterpret_cast<const WORD*>(p_up + 4);
            return static_cast<WORD>(ssn + idx);
        }
    }
    return 0;
}

std::uintptr_t g_ntdll_base = 0;

struct SyscallStub {
    void* memory = nullptr;
};

std::array<SyscallStub, static_cast<size_t>(StubId::Count)> g_syscall_stubs{};
std::array<bool, static_cast<size_t>(StubId::Count)> g_syscall_ready{};
asmjit::JitRuntime g_jit_runtime;

void decrypt_stub_name(StubId id, char* out, size_t cap) {
    switch (id) {
    case StubId::AllocateVirtualMemory:
        VEIL_XOR_DECRYPT(out, "NtAllocateVirtualMemory");
        break;
    case StubId::FreeVirtualMemory:
        VEIL_XOR_DECRYPT(out, "NtFreeVirtualMemory");
        break;
    case StubId::ProtectVirtualMemory:
        VEIL_XOR_DECRYPT(out, "NtProtectVirtualMemory");
        break;
    case StubId::GetContextThread:
        VEIL_XOR_DECRYPT(out, "NtGetContextThread");
        break;
    case StubId::SetContextThread:
        VEIL_XOR_DECRYPT(out, "NtSetContextThread");
        break;
    case StubId::SuspendThread:
        VEIL_XOR_DECRYPT(out, "NtSuspendThread");
        break;
    case StubId::ResumeThread:
        VEIL_XOR_DECRYPT(out, "NtResumeThread");
        break;
    case StubId::QueryVirtualMemory:
        VEIL_XOR_DECRYPT(out, "NtQueryVirtualMemory");
        break;
    case StubId::CreateSection:
        VEIL_XOR_DECRYPT(out, "NtCreateSection");
        break;
    case StubId::MapViewOfSection:
        VEIL_XOR_DECRYPT(out, "NtMapViewOfSection");
        break;
    case StubId::UnmapViewOfSection:
        VEIL_XOR_DECRYPT(out, "NtUnmapViewOfSection");
        break;
    default:
        if (cap > 0) {
            out[0] = '\0';
        }
        break;
    }
    (void)cap;
}

SyscallStub create_syscall_stub(std::string_view name) {
    const std::uintptr_t target_fn = get_symbol_address_peb(g_ntdll_base, name);
    if (!target_fn) {
        return {};
    }

    const WORD ssn = find_syscall_number(target_fn);
    if (!ssn) {
        return {};
    }

    const std::uintptr_t syscall_gadget = find_syscall_return_address(target_fn);
    if (!syscall_gadget) {
        return {};
    }

    asmjit::CodeHolder code;
    code.init(g_jit_runtime.environment());
    asmjit::x86::Assembler a(&code);

    using namespace asmjit::x86;

    a.mov(r10, rcx);
    a.mov(eax, ssn);
    a.mov(r11, syscall_gadget);
    a.jmp(r11);

    void* fn_ptr = nullptr;
    if (g_jit_runtime.add(&fn_ptr, &code) != asmjit::kErrorOk) {
        return {};
    }

    return {fn_ptr};
}

void* get_syscall_stub(StubId id) {
    const size_t idx = static_cast<size_t>(id);
    if (idx >= g_syscall_stubs.size()) {
        return nullptr;
    }

    if (!g_syscall_ready[idx]) {
        char name[48]{};
        decrypt_stub_name(id, name, sizeof(name));
        g_syscall_stubs[idx] = create_syscall_stub(name);
        g_syscall_ready[idx] = true;
    }

    return g_syscall_stubs[idx].memory;
}

template <typename Fn, typename... Args>
NTSTATUS invoke_syscall(StubId id, Args... args) {
    const auto stub = reinterpret_cast<Fn>(get_syscall_stub(id));
    if (!stub) {
        return STATUS_UNSUCCESSFUL;
    }
    return stub(args...);
}

} // namespace

bool init() {
    wchar_t ntdll_name[16]{};
    VEIL_XORW_DECRYPT(ntdll_name, L"ntdll.dll");
    g_ntdll_base = get_module_base_peb(ntdll_name);
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
    return invoke_syscall<NtAllocateVirtualMemoryFn>(
        StubId::AllocateVirtualMemory,
        process_handle,
        base_address,
        zero_bits,
        region_size,
        allocation_type,
        protect);
}

NTSTATUS nt_free_virtual_memory(
    HANDLE process_handle,
    PVOID* base_address,
    PSIZE_T region_size,
    ULONG free_type)
{
    return invoke_syscall<NtFreeVirtualMemoryFn>(
        StubId::FreeVirtualMemory, process_handle, base_address, region_size, free_type);
}

NTSTATUS nt_protect_virtual_memory(
    HANDLE process_handle,
    PVOID* base_address,
    PSIZE_T region_size,
    ULONG new_protect,
    PULONG old_protect)
{
    return invoke_syscall<NtProtectVirtualMemoryFn>(
        StubId::ProtectVirtualMemory, process_handle, base_address, region_size, new_protect, old_protect);
}

NTSTATUS nt_get_context_thread(HANDLE thread_handle, PCONTEXT thread_context) {
    return invoke_syscall<NtGetContextThreadFn>(StubId::GetContextThread, thread_handle, thread_context);
}

NTSTATUS nt_set_context_thread(HANDLE thread_handle, PCONTEXT thread_context) {
    return invoke_syscall<NtSetContextThreadFn>(StubId::SetContextThread, thread_handle, thread_context);
}

NTSTATUS nt_suspend_thread(HANDLE thread_handle, PULONG previous_suspend_count) {
    return invoke_syscall<NtSuspendThreadFn>(StubId::SuspendThread, thread_handle, previous_suspend_count);
}

NTSTATUS nt_resume_thread(HANDLE thread_handle, PULONG previous_suspend_count) {
    return invoke_syscall<NtResumeThreadFn>(StubId::ResumeThread, thread_handle, previous_suspend_count);
}

NTSTATUS nt_query_virtual_memory(
    HANDLE process_handle,
    PVOID base_address,
    MEMORY_INFORMATION_CLASS memory_information_class,
    PVOID memory_information,
    SIZE_T memory_information_length,
    PSIZE_T return_length)
{
    return invoke_syscall<NtQueryVirtualMemoryFn>(
        StubId::QueryVirtualMemory,
        process_handle,
        base_address,
        memory_information_class,
        memory_information,
        memory_information_length,
        return_length);
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
    return invoke_syscall<NtCreateSectionFn>(
        StubId::CreateSection,
        section_handle,
        desired_access,
        object_attributes,
        maximum_size,
        section_page_protection,
        allocation_attributes,
        file_handle);
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
    return invoke_syscall<NtMapViewOfSectionFn>(
        StubId::MapViewOfSection,
        section_handle,
        process_handle,
        base_address,
        zero_bits,
        commit_size,
        section_offset,
        view_size,
        inherit_disposition,
        allocation_type,
        win32_protect);
}

NTSTATUS nt_unmap_view_of_section(HANDLE process_handle, PVOID base_address) {
    return invoke_syscall<NtUnmapViewOfSectionFn>(StubId::UnmapViewOfSection, process_handle, base_address);
}

} // namespace veilhook::syscalls
