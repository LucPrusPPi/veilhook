#pragma once

#include <veilhook/hook/status.hpp>
#include <veilhook/veh_hub.hpp>
#include <veilhook/obfuscation.hpp>
#include <vector>
#include <cstdint>
#include <memory>

namespace veilhook::hook {

// Patches target with UD2 (0F 0B), catches STATUS_ILLEGAL_INSTRUCTION in VEH,
// redirects RIP to destination. Original bytes live in a cave trampoline.
class Ud2 {
public:
    Ud2(uintptr_t target, uintptr_t destination);
    ~Ud2();

    bool install();
    bool uninstall();
    InstallStatus last_status() const { return last_status_; }

    template <typename T>
    T get_original() const {
        return reinterpret_cast<T>(original_callable_);
    }

private:
    bool handle_exception(PEXCEPTION_POINTERS ep);

    uintptr_t target_;
    uintptr_t destination_;

    size_t patch_size_ = 0;
    std::vector<uint8_t> original_bytes_;

    uint8_t* trampoline_ = nullptr;
    size_t trampoline_size_ = 0;
    uint8_t* original_callable_ = nullptr;

    bool is_installed_ = false;
    InstallStatus last_status_ = InstallStatus::Ok;
    std::unique_ptr<veh::Subscription> veh_sub_;

    VEIL_STRUCT_PADDING_1;
    VEIL_STRUCT_PADDING_2;
    VEIL_STRUCT_PADDING_3;
};

} // namespace veilhook::hook
