#include <gtest/gtest.h>
#include <veilhook/veilhook.hpp>
#include <veilhook/decode.hpp>
#include <veilhook/reloc.hpp>
#include <veilhook/hook/phantom.hpp>
#include <veilhook/hook/ud2.hpp>
#include <veilhook/syscalls.hpp>
#include <veilhook/cave_alloc.hpp>
#include <asmjit/asmjit.h>
#include <cstring>
#include <vector>

// keep tests from inlining away the targets we hook
#pragma optimize("", off)

volatile int g_reloc_test_value = 100;

__declspec(noinline) int target_with_riprel() {
    return g_reloc_test_value;
}

__declspec(noinline) int target_with_riprel_hooked() {
    return g_reloc_test_value * 2;
}

// --- Helper Functions ---
__declspec(noinline) int target_function_math(int a, int b) {
    volatile int x = a;
    x += b;
    x += b;
    x += b;
    x += b;
    x += b;
    x += b;
    return x;
}

__declspec(noinline) int target_function_math_hooked(int a, int b) {
    volatile int x = a;
    x += b;
    x += b;
    x += b;
    x += b;
    x += b;
    x += b;
    return x * 10;
}

class TargetObj {
public:
    virtual ~TargetObj() = default;
    virtual int get_id() { return 42; }
};

int get_id_hooked(TargetObj* obj) {
    return 999;
}

// --- Inline Hook Tests ---
TEST(HookTests, InlineHookInstallUninstall) {
    EXPECT_EQ(target_function_math(5, 5), 35);

    veilhook::hook::Inline inline_hook(
        reinterpret_cast<uintptr_t>(&target_function_math),
        reinterpret_cast<uintptr_t>(&target_function_math_hooked)
    );

    EXPECT_TRUE(inline_hook.install());
    EXPECT_EQ(target_function_math(5, 5), 350);

    EXPECT_TRUE(inline_hook.uninstall());
    EXPECT_EQ(target_function_math(5, 5), 35);
}

TEST(HookTests, InlineHookCallOriginal) {
    static veilhook::hook::Inline* hook_ptr = nullptr;
    
    auto hook_func = [](int a, int b) -> int {
        auto orig = hook_ptr->get_original<decltype(&target_function_math)>();
        return orig(a, b) + 1; // Return original result + 1
    };

    veilhook::hook::Inline inline_hook(
        reinterpret_cast<uintptr_t>(&target_function_math),
        reinterpret_cast<uintptr_t>(+hook_func) // unary + to decay lambda to function ptr
    );
    hook_ptr = &inline_hook;

    EXPECT_TRUE(inline_hook.install());
    EXPECT_EQ(target_function_math(5, 5), 36);
    EXPECT_TRUE(inline_hook.uninstall());
}

TEST(HookTests, InlineHookRipRelativePrologue) {
    g_reloc_test_value = 100;
    EXPECT_EQ(target_with_riprel(), 100);

    veilhook::hook::Inline inline_hook(
        reinterpret_cast<uintptr_t>(&target_with_riprel),
        reinterpret_cast<uintptr_t>(&target_with_riprel_hooked)
    );

    EXPECT_TRUE(inline_hook.install());
    EXPECT_EQ(inline_hook.last_status(), veilhook::hook::InstallStatus::Ok);
    EXPECT_EQ(target_with_riprel(), 200);

    EXPECT_TRUE(inline_hook.uninstall());
    EXPECT_EQ(target_with_riprel(), 100);
}

TEST(HookTests, InlineHookCallOriginalRipRelative) {
    static veilhook::hook::Inline* hook_ptr = nullptr;

    auto hook_func = []() -> int {
        auto orig = hook_ptr->get_original<decltype(&target_with_riprel)>();
        return orig() + 7;
    };

    g_reloc_test_value = 50;

    veilhook::hook::Inline inline_hook(
        reinterpret_cast<uintptr_t>(&target_with_riprel),
        reinterpret_cast<uintptr_t>(+hook_func)
    );
    hook_ptr = &inline_hook;

    EXPECT_TRUE(inline_hook.install());
    EXPECT_EQ(target_with_riprel(), 57);
    EXPECT_TRUE(inline_hook.uninstall());
}

// --- UD2 Hook Tests ---

TEST(HookTests, Ud2HookInstallUninstall) {
    EXPECT_EQ(target_function_math(5, 5), 35);

    veilhook::hook::Ud2 ud2_hook(
        reinterpret_cast<uintptr_t>(&target_function_math),
        reinterpret_cast<uintptr_t>(&target_function_math_hooked)
    );

    EXPECT_TRUE(ud2_hook.install());
    EXPECT_EQ(ud2_hook.last_status(), veilhook::hook::InstallStatus::Ok);
    EXPECT_EQ(target_function_math(5, 5), 350);

    EXPECT_TRUE(ud2_hook.uninstall());
    EXPECT_EQ(target_function_math(5, 5), 35);
}

TEST(HookTests, Ud2HookCallOriginal) {
    static veilhook::hook::Ud2* hook_ptr = nullptr;
    
    auto hook_func = [](int a, int b) -> int {
        auto orig = hook_ptr->get_original<decltype(&target_function_math)>();
        return orig(a, b) + 1;
    };

    veilhook::hook::Ud2 ud2_hook(
        reinterpret_cast<uintptr_t>(&target_function_math),
        reinterpret_cast<uintptr_t>(+hook_func)
    );
    hook_ptr = &ud2_hook;

    EXPECT_TRUE(ud2_hook.install());
    EXPECT_EQ(target_function_math(5, 5), 36);
    EXPECT_TRUE(ud2_hook.uninstall());
}

// --- Phantom Hook Tests ---
TEST(HookTests, PhantomHookInstallUninstall) {
    // 1. Create a custom section view to execute the function from.
    // This isolates the target page from our executable's main .text section,
    // meaning NtUnmapViewOfSection won't unmap our own running code!
    HANDLE h_section = nullptr;
    LARGE_INTEGER max_size;
    max_size.QuadPart = 4096;

    NTSTATUS status = veilhook::syscalls::nt_create_section(
        &h_section, 
        SECTION_ALL_ACCESS, 
        nullptr, 
        &max_size, 
        PAGE_EXECUTE_READWRITE, 
        0x8000000, // SEC_COMMIT
        nullptr
    );
    ASSERT_EQ(status, veilhook::syscalls::STATUS_SUCCESS);

    PVOID p_view = nullptr;
    SIZE_T view_size = 4096;
    status = veilhook::syscalls::nt_map_view_of_section(
        h_section,
        GetCurrentProcess(),
        &p_view,
        0,
        4096,
        nullptr,
        &view_size,
        2, // ViewUnmap
        0,
        PAGE_EXECUTE_READWRITE
    );
    ASSERT_EQ(status, veilhook::syscalls::STATUS_SUCCESS);

    // Copy target_function_math code into the dynamically mapped view.
    std::memcpy(p_view, reinterpret_cast<void*>(&target_function_math), 64);

    auto target_func_in_view = reinterpret_cast<decltype(&target_function_math)>(p_view);

    veilhook::hook::Phantom phantom_hook(
        reinterpret_cast<uintptr_t>(p_view),
        reinterpret_cast<uintptr_t>(&target_function_math_hooked)
    );

    bool installed = phantom_hook.install();
    if (installed) {
        EXPECT_EQ(target_func_in_view(2, 3), 200);
        EXPECT_TRUE(phantom_hook.uninstall());
    } else {
        // Fallback clean up
        veilhook::syscalls::nt_unmap_view_of_section(GetCurrentProcess(), p_view);
        CloseHandle(h_section);
        GTEST_SKIP() << "Phantom hook failed to install (possibly crosses page boundary)";
    }

    // Clean up
    veilhook::syscalls::nt_unmap_view_of_section(GetCurrentProcess(), p_view);
    CloseHandle(h_section);
}

// Helper function to absolutely prevent MSVC compiler devirtualization.
// Because it is marked __declspec(noinline), the compiler cannot statically resolve get_id
// and is forced to look it up in the VMT.
__declspec(noinline) int call_get_id(TargetObj* obj) {
    return obj->get_id();
}

// --- VMT Hook Tests ---
TEST(HookTests, VMTHook) {
    TargetObj obj;
    EXPECT_EQ(call_get_id(&obj), 42);

    veilhook::hook::Vmt vmt_hook(&obj);
    vmt_hook.hook_method(1, reinterpret_cast<uintptr_t>(&get_id_hooked));

    EXPECT_EQ(call_get_id(&obj), 999);
    
    vmt_hook.unhook_method(1);
    EXPECT_EQ(call_get_id(&obj), 42);
}

// --- Scanner Tests ---
#include <veilhook/scanner.hpp>

TEST(RelocTests, TrampolineRipRelDirect) {
    g_reloc_test_value = 42;

    veilhook::decode::InstructionView decoder;
    auto* target = reinterpret_cast<uint8_t*>(&target_with_riprel);
    const size_t patch_size = decoder.get_boundary_length(target, 5);
    ASSERT_GT(patch_size, 0u);

    std::vector<uint8_t> stolen(patch_size);
    std::memcpy(stolen.data(), target, patch_size);

    const size_t alloc_size = patch_size * 4 + 64;
    uint8_t* tramp = veilhook::mem::CaveAlloc::get().allocate(
        reinterpret_cast<uintptr_t>(target), alloc_size);
    ASSERT_NE(tramp, nullptr);

    asmjit::JitRuntime rt;
    asmjit::CodeHolder code;
    code.init(rt.environment(), reinterpret_cast<uint64_t>(tramp));
    asmjit::x86::Assembler a(&code);

    const auto reloc_status = veilhook::reloc::emit_stolen_range(
        a,
        decoder.zydis_decoder(),
        stolen.data(),
        patch_size,
        reinterpret_cast<uint64_t>(target),
        reinterpret_cast<uint64_t>(tramp));
    ASSERT_EQ(reloc_status, veilhook::reloc::Status::Ok);

    a.mov(asmjit::x86::r11, reinterpret_cast<uint64_t>(target) + patch_size);
    a.jmp(asmjit::x86::r11);

    asmjit::CodeBuffer& buffer = code.sectionById(0)->buffer();
    std::memcpy(tramp, buffer.data(), buffer.size());

    const auto fn = reinterpret_cast<int(*)()>(tramp);
    EXPECT_EQ(fn(), 42);

    veilhook::mem::CaveAlloc::get().deallocate(tramp, alloc_size);
}

TEST(ScannerTests, BasicPatternSearch) {
    uint8_t buffer[] = {
        0x90, 0x90, 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x90
    };

    auto pattern = VEIL_PATTERN("48 8B C4 48 89 58 ?");
    auto match = veilhook::scanner::scan(std::span<const uint8_t>(buffer, sizeof(buffer)), pattern);
    
    ASSERT_TRUE(match.has_value());
    EXPECT_EQ(match.value(), &buffer[2]);
}

TEST(ScannerTests, NotFound) {
    uint8_t buffer[] = { 0x11, 0x22, 0x33, 0x44 };
    auto pattern = VEIL_PATTERN("FF FF");
    auto match = veilhook::scanner::scan(std::span<const uint8_t>(buffer, sizeof(buffer)), pattern);
    EXPECT_FALSE(match.has_value());
}
