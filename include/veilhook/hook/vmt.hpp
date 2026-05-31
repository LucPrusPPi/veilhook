#pragma once

#include <cstdint>
#include <memory>
#include <vector>

namespace veilhook::hook {

class Vmt {
public:
    // Takes the address of the object instance containing the vtable pointer
    explicit Vmt(void* instance);
    ~Vmt();

    // Hook a specific virtual method index. Returns the original method address.
    uintptr_t hook_method(uint32_t index, uintptr_t destination);
    
    // Restore a specific method
    bool unhook_method(uint32_t index);

    // Completely unhooks and restores original vtable
    void unhook_all();

private:
    void** instance_vtable_ptr_;
    uintptr_t* original_vtable_ = nullptr;
    size_t vtable_size_ = 0;
    
    // Shadow VMT allocated in CaveAlloc
    uintptr_t* shadow_vtable_ = nullptr;
    size_t shadow_allocation_size_ = 0;

    size_t count_vtable_methods(uintptr_t* vtable);
};

} // namespace veilhook::hook
