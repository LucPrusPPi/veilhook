#include <iostream>
#include <cassert>
#include <windows.h>
#include <veilhook/veilhook.hpp>

// --- VMT Hook Test ---
class TargetClass {
public:
    virtual ~TargetClass() = default;
    virtual int get_value() { return 42; }
    virtual int get_other() { return 10; }
};

int hk_get_value(TargetClass* this_ptr) {
    std::cout << "[+] VMT Hook Executed!" << std::endl;
    return 999;
}

void test_vmt_hook() {
    std::cout << "--- Testing VMT Hook ---" << std::endl;
    TargetClass obj;
    assert(obj.get_value() == 42);

    veilhook::hook::Vmt vmt_hook(&obj);
    
    // Index 1 is typically get_value (Index 0 is destructor in MSVC)
    vmt_hook.hook_method(1, reinterpret_cast<uintptr_t>(&hk_get_value));
    
    int val = obj.get_value();
    std::cout << "Obj Value after hook: " << val << std::endl;
    assert(val == 999);
    assert(obj.get_other() == 10); // Other methods remain intact
    
    vmt_hook.unhook_all();
    assert(obj.get_value() == 42);
    std::cout << "[+] VMT Hook test passed." << std::endl;
}

// --- Inline Hook Test ---
int target_function(int a, int b) {
    return a + b;
}

std::unique_ptr<veilhook::hook::Inline> g_inline_hook;

int hk_target_function(int a, int b) {
    std::cout << "[+] Inline Hook Executed! Args: " << a << ", " << b << std::endl;
    // Call original
    auto original = g_inline_hook->get_original<decltype(&target_function)>();
    return original(a, b) * 10;
}

void test_inline_hook() {
    std::cout << "--- Testing Inline Hook ---" << std::endl;
    assert(target_function(2, 3) == 5);

    g_inline_hook = std::make_unique<veilhook::hook::Inline>(
        reinterpret_cast<uintptr_t>(&target_function),
        reinterpret_cast<uintptr_t>(&hk_target_function)
    );

    bool installed = g_inline_hook->install();
    assert(installed);

    int val = target_function(2, 3);
    std::cout << "Hooked func returned: " << val << std::endl;
    assert(val == 50);

    g_inline_hook->uninstall();
    assert(target_function(2, 3) == 5);
    std::cout << "[+] Inline Hook test passed." << std::endl;
}

// --- Midline Hook Test ---
__declspec(noinline) int mid_target_func() {
    int x = 10;
    x += 20;
    // We will place a mid-hook right after x is assigned or computed
    x *= 2; 
    return x;
}

// Finding an instruction to mid-hook is tricky without an offset, we'll try hooking the start or + offset
std::unique_ptr<veilhook::hook::Mid> g_mid_hook;
bool mid_hook_hit = false;

void mid_callback(veilhook::hook::Context& ctx) {
    std::cout << "[+] Mid Hook Executed! RIP: " << std::hex << ctx.Rip << std::dec << std::endl;
    mid_hook_hit = true;
    // ctx.Rax etc can be inspected or modified
}

void test_mid_hook() {
    std::cout << "--- Testing Midline Hook ---" << std::endl;
    
    // We just hook the very start of the function for simplicity of the test
    g_mid_hook = std::make_unique<veilhook::hook::Mid>(
        reinterpret_cast<uintptr_t>(&mid_target_func),
        mid_callback
    );

    bool installed = g_mid_hook->install();
    assert(installed);

    int val = mid_target_func();
    assert(mid_hook_hit);
    std::cout << "[+] Mid Hook test passed." << std::endl;
    
    g_mid_hook->uninstall();
}

// --- HWBP Test ---
bool hwbp_hit = false;
void hwbp_callback(PEXCEPTION_POINTERS ep) {
    std::cout << "[+] HWBP Triggered at RIP: " << std::hex << ep->ContextRecord->Rip << std::dec << std::endl;
    hwbp_hit = true;
}

void test_hwbp() {
    std::cout << "--- Testing HWBP ---" << std::endl;
    
    auto& hwbp_mgr = veilhook::hwbp::Manager::get();
    
    int slot = hwbp_mgr.set_for_current_thread(
        reinterpret_cast<uintptr_t>(&mid_target_func),
        veilhook::hwbp::Type::Execute,
        veilhook::hwbp::Length::Len1,
        hwbp_callback
    );
    
    assert(slot != -1);
    
    mid_target_func();
    assert(hwbp_hit);
    
    hwbp_mgr.clear_for_current_thread(slot);
    std::cout << "[+] HWBP test passed." << std::endl;
}

int main() {
    try {
        test_vmt_hook();
        test_inline_hook();
        test_mid_hook();
        test_hwbp();
        
        std::cout << "\n[=== ALL TESTS PASSED ===]" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
