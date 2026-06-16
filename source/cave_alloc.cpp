#include <veilhook/cave_alloc.hpp>
#include <veilhook/syscalls.hpp>
#include <veilhook/xorstr.hpp>
#include <tlhelp32.h>
#include <psapi.h>
#include <cmath>

namespace veilhook::mem {

CaveAlloc& CaveAlloc::get() {
    static CaveAlloc instance;
    return instance;
}

uint8_t* CaveAlloc::find_cave_in_module(HMODULE mod, size_t size) {
    MODULEINFO mod_info;
    if (!GetModuleInformation(GetCurrentProcess(), mod, &mod_info, sizeof(mod_info))) {
        return nullptr;
    }

    auto base = reinterpret_cast<uint8_t*>(mod_info.lpBaseOfDll);
    auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    auto section_header = IMAGE_FIRST_SECTION(nt_headers);
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section_header++) {
        if ((section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (section_header->Characteristics & IMAGE_SCN_MEM_READ)) {
            
            uint8_t* sec_base = base + section_header->VirtualAddress;
            size_t sec_size = section_header->Misc.VirtualSize;

            // Simple linear search for 0xCC or 0x00 caves
            size_t count = 0;
            for (size_t j = 0; j < sec_size; j++) {
                if (sec_base[j] == 0xCC || sec_base[j] == 0x00) {
                    count++;
                    if (count >= size) {
                        uint8_t* cave = sec_base + j - count + 1;
                        
                        // Temporarily make writable
                        ULONG old_protect = 0;
                        PVOID base_addr = reinterpret_cast<PVOID>(cave);
                        SIZE_T region_size = size;

                        if (syscalls::nt_protect_virtual_memory(GetCurrentProcess(), &base_addr, &region_size, PAGE_EXECUTE_READWRITE, &old_protect) == syscalls::STATUS_SUCCESS) {
                            return cave;
                        }
                    }
                } else {
                    count = 0;
                }
            }
        }
    }
    return nullptr;
}

uint8_t* CaveAlloc::allocate_page_near(uintptr_t target, size_t size) {
    // Try to allocate within 2GB for rel32
    uintptr_t min_addr = (target > 0x7FFFFFFF) ? target - 0x7FFFFFFF : 0;
    uintptr_t max_addr = target + 0x7FFFFFFF;

    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);

    min_addr = (std::max)(min_addr, reinterpret_cast<uintptr_t>(sys_info.lpMinimumApplicationAddress));
    max_addr = (std::min)(max_addr, reinterpret_cast<uintptr_t>(sys_info.lpMaximumApplicationAddress));

    uintptr_t current_addr = max_addr;
    current_addr -= current_addr % sys_info.dwAllocationGranularity;

    while (current_addr > min_addr) {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T ret_len;
        if (syscalls::nt_query_virtual_memory(GetCurrentProcess(), reinterpret_cast<PVOID>(current_addr), syscalls::MemoryBasicInformation, &mbi, sizeof(mbi), &ret_len) != syscalls::STATUS_SUCCESS) {
            break;
        }

        if (mbi.State == MEM_FREE) {
            PVOID ptr = reinterpret_cast<PVOID>(current_addr);
            SIZE_T region_size = size;
            if (syscalls::nt_allocate_virtual_memory(GetCurrentProcess(), &ptr, 0, &region_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) == syscalls::STATUS_SUCCESS) {
                return static_cast<uint8_t*>(ptr);
            }
        }

        if (current_addr < mbi.RegionSize) break;
        current_addr -= sys_info.dwAllocationGranularity;
    }

    // Fallback: far allocation anywhere
    PVOID far_ptr = nullptr;
    SIZE_T region_size = size;
    if (syscalls::nt_allocate_virtual_memory(GetCurrentProcess(), &far_ptr, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) == syscalls::STATUS_SUCCESS) {
        return static_cast<uint8_t*>(far_ptr);
    }
    return nullptr;
}

uint8_t* CaveAlloc::allocate(uintptr_t target, size_t size) {
    std::lock_guard lock(lock_);

    // 1. Try to find an existing cave in loaded modules near target
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me32;
        me32.dwSize = sizeof(me32);
        if (Module32FirstW(snapshot, &me32)) {
            do {
                uintptr_t mod_base = reinterpret_cast<uintptr_t>(me32.modBaseAddr);
                // Check if within 2GB roughly
                if (std::abs(static_cast<int64_t>(mod_base) - static_cast<int64_t>(target)) < 0x7FFFFFFF) {
                    uint8_t* cave = find_cave_in_module(me32.hModule, size);
                    if (cave) {
                        allocations_.push_back({cave, size, true});
                        CloseHandle(snapshot);
                        return cave;
                    }
                }
            } while (Module32NextW(snapshot, &me32));
        }
        CloseHandle(snapshot);
    }

    // 2. Fallback to VirtualAlloc near
    uint8_t* ptr = allocate_page_near(target, size);
    if (ptr) {
        allocations_.push_back({ptr, size, false});
    }
    return ptr;
}

void CaveAlloc::deallocate(uint8_t* ptr, size_t size) {
    std::lock_guard lock(lock_);
    
    auto it = std::find_if(allocations_.begin(), allocations_.end(), 
        [ptr](const Allocation& a) { return a.base == ptr; });
        
    if (it != allocations_.end()) {
        if (it->is_cave) {
            // Restore original memory protection if needed, zero out
            ULONG old_protect = 0;
            PVOID base_addr = reinterpret_cast<PVOID>(ptr);
            SIZE_T region_size = size;

            if (syscalls::nt_protect_virtual_memory(GetCurrentProcess(), &base_addr, &region_size, PAGE_EXECUTE_READWRITE, &old_protect) == syscalls::STATUS_SUCCESS) {
                memset(ptr, 0x00, size);
                base_addr = reinterpret_cast<PVOID>(ptr);
                region_size = size;
                syscalls::nt_protect_virtual_memory(GetCurrentProcess(), &base_addr, &region_size, old_protect, &old_protect);
            }
        } else {
            PVOID base_addr = reinterpret_cast<PVOID>(ptr);
            SIZE_T region_size = 0;
            syscalls::nt_free_virtual_memory(GetCurrentProcess(), &base_addr, &region_size, MEM_RELEASE);
        }
        allocations_.erase(it);
    }
}

} // namespace veilhook::mem
