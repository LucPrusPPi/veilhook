#include <veilhook/cave_alloc.hpp>
#include <tlhelp32.h>
#include <psapi.h>

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
                        DWORD old_protect;
                        if (VirtualProtect(cave, size, PAGE_EXECUTE_READWRITE, &old_protect)) {
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
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(current_addr), &mbi, sizeof(mbi))) {
            break;
        }

        if (mbi.State == MEM_FREE) {
            uint8_t* ptr = static_cast<uint8_t*>(VirtualAlloc(reinterpret_cast<LPVOID>(current_addr), size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
            if (ptr) {
                return ptr;
            }
        }

        if (current_addr < mbi.RegionSize) break;
        current_addr -= sys_info.dwAllocationGranularity;
    }

    // Fallback: far allocation anywhere
    return static_cast<uint8_t*>(VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
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
            DWORD old_protect;
            if (VirtualProtect(ptr, size, PAGE_EXECUTE_READWRITE, &old_protect)) {
                memset(ptr, 0x00, size);
                VirtualProtect(ptr, size, old_protect, &old_protect);
            }
        } else {
            VirtualFree(ptr, 0, MEM_RELEASE);
        }
        allocations_.erase(it);
    }
}

} // namespace veilhook::mem
