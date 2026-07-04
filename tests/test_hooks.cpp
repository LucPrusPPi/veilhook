#include <gtest/gtest.h>
#include <veilhook/veilhook.hpp>
#include <veilhook/hook/phantom.hpp>

// --- Helper Functions ---
int target_function_math(int a, int b) {
    return a + b;
}

int target_function_math_hooked(int a, int b) {
    return (a + b) * 10;
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
    EXPECT_EQ(target_function_math(5, 5), 10);

    veilhook::hook::Inline inline_hook(
        reinterpret_cast<uintptr_t>(&target_function_math),
        reinterpret_cast<uintptr_t>(&target_function_math_hooked)
    );

    EXPECT_TRUE(inline_hook.install());
    EXPECT_EQ(target_function_math(5, 5), 100);

    EXPECT_TRUE(inline_hook.uninstall());
    EXPECT_EQ(target_function_math(5, 5), 10);
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
    EXPECT_EQ(target_function_math(5, 5), 11);
    EXPECT_TRUE(inline_hook.uninstall());
}

// --- Phantom Hook Tests ---
TEST(HookTests, PhantomHookInstallUninstall) {
    EXPECT_EQ(target_function_math(2, 3), 5);

    veilhook::hook::Phantom phantom_hook(
        reinterpret_cast<uintptr_t>(&target_function_math),
        reinterpret_cast<uintptr_t>(&target_function_math_hooked)
    );

    bool installed = phantom_hook.install();
    if (installed) {
        EXPECT_EQ(target_function_math(2, 3), 50);
        EXPECT_TRUE(phantom_hook.uninstall());
        EXPECT_EQ(target_function_math(2, 3), 5);
    } else {
        GTEST_SKIP() << "Phantom hook failed to install (possibly crosses page boundary)";
    }
}

// --- VMT Hook Tests ---
TEST(HookTests, VMTHook) {
    TargetObj obj;
    EXPECT_EQ(obj.get_id(), 42);

    veilhook::hook::Vmt vmt_hook(&obj);
    vmt_hook.hook_method(1, reinterpret_cast<uintptr_t>(&get_id_hooked));

    EXPECT_EQ(obj.get_id(), 999);
    
    vmt_hook.unhook_method(1);
    EXPECT_EQ(obj.get_id(), 42);
}

// --- Scanner Tests ---
#include <veilhook/scanner.hpp>

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
