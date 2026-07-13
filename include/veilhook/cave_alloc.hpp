#pragma once

#include <windows.h>
#include <cstdint>
#include <vector>
#include <mutex>

namespace veilhook::mem {

class CaveAlloc {
public:
    static CaveAlloc& get();

    // Try to allocate executable memory within ±2GB of target.
    // Falls back to module caves, then a fresh page, then any free region.
    // Returns nullptr only if NtAllocateVirtualMemory fails entirely.
    uint8_t* allocate(uintptr_t target, size_t size);
    
    void deallocate(uint8_t* ptr, size_t size);

private:
    CaveAlloc() = default;
    ~CaveAlloc() = default;

    struct Allocation {
        uint8_t* base;
        size_t size;
        bool is_cave; // true if inside existing module, false if VirtualAlloc'd
    };

    std::vector<Allocation> allocations_;
    std::mutex lock_;

    uint8_t* find_cave_in_module(HMODULE mod, size_t size);
    uint8_t* allocate_page_near(uintptr_t target, size_t size);
};

} // namespace veilhook::mem
