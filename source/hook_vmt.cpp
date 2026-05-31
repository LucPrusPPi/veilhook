#include <veilhook/hook/vmt.hpp>
#include <veilhook/cave_alloc.hpp>
#include <windows.h>
#include <stdexcept>

namespace veilhook::hook {

Vmt::Vmt(void* instance) {
    if (!instance) throw std::invalid_argument("instance is null");

    instance_vtable_ptr_ = reinterpret_cast<void**>(instance);
    original_vtable_ = *reinterpret_cast<uintptr_t**>(instance_vtable_ptr_);
    
    if (!original_vtable_) throw std::invalid_argument("original vtable is null");

    vtable_size_ = count_vtable_methods(original_vtable_);
    
    // Allocate shadow VMT using CaveAlloc
    // RTTI requires the pointer *before* the VMT to be valid, so we copy +1 element back
    shadow_allocation_size_ = (vtable_size_ + 1) * sizeof(uintptr_t);
    uint8_t* mem = mem::CaveAlloc::get().allocate(reinterpret_cast<uintptr_t>(original_vtable_), shadow_allocation_size_);
    
    if (!mem) throw std::runtime_error("Failed to allocate Shadow VMT");

    auto shadow_base = reinterpret_cast<uintptr_t*>(mem);
    
    // Copy original vtable including RTTI pointer
    std::memcpy(shadow_base, original_vtable_ - 1, shadow_allocation_size_);
    
    // Point shadow_vtable_ to the actual start of functions (skip RTTI ptr)
    shadow_vtable_ = shadow_base + 1;

    // Apply Swap
    *instance_vtable_ptr_ = shadow_vtable_;
}

Vmt::~Vmt() {
    unhook_all();
    if (shadow_vtable_) {
        // Free the actual base memory we allocated
        mem::CaveAlloc::get().deallocate(reinterpret_cast<uint8_t*>(shadow_vtable_ - 1), shadow_allocation_size_);
    }
}

size_t Vmt::count_vtable_methods(uintptr_t* vtable) {
    size_t count = 0;
    MEMORY_BASIC_INFORMATION mbi;
    
    while (true) {
        // Very basic validation that the pointer points to executable memory
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(vtable[count]), &mbi, sizeof(mbi))) {
            break;
        }
        
        if ((mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) == 0) {
            break;
        }
        
        count++;
    }
    
    return count;
}

uintptr_t Vmt::hook_method(uint32_t index, uintptr_t destination) {
    if (index >= vtable_size_) return 0;
    
    uintptr_t original = original_vtable_[index];
    shadow_vtable_[index] = destination;
    
    return original;
}

bool Vmt::unhook_method(uint32_t index) {
    if (index >= vtable_size_) return false;
    
    shadow_vtable_[index] = original_vtable_[index];
    return true;
}

void Vmt::unhook_all() {
    if (instance_vtable_ptr_ && original_vtable_) {
        *instance_vtable_ptr_ = original_vtable_;
    }
}

} // namespace veilhook::hook
