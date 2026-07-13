#pragma once

#include <windows.h>
#include <vector>
#include <memory>
#include <functional>
#include <shared_mutex>
#include <cstdint>

namespace veilhook::veh {

// Returns true if we handled it (CONTINUE_EXECUTION)
// Returns false to keep searching (CONTINUE_SEARCH)
using ExceptionFilter = std::function<bool(PEXCEPTION_POINTERS)>;

class Subscription {
public:
    virtual ~Subscription() = default;
};

class Hub {
public:
    static Hub& get();

    // Register a handler for a specific exception code.
    // Higher priority values execute first.
    // code=0 means "any exception"
    [[nodiscard]] std::unique_ptr<Subscription> add_handler(
        DWORD exception_code, 
        int priority, 
        ExceptionFilter filter
    );

private:
    Hub();
    ~Hub();

    static LONG CALLBACK exception_handler(PEXCEPTION_POINTERS ep);

    struct HandlerEntry {
        uint64_t id;
        DWORD code;
        int priority;
        ExceptionFilter filter;

        bool operator<(const HandlerEntry& other) const {
            return priority > other.priority; // Higher priority first
        }
    };

    std::shared_mutex rw_lock_;
    std::vector<HandlerEntry> handlers_;
    PVOID veh_handle_ = nullptr;
    uint64_t next_id_ = 1;

    void remove_handler(uint64_t id);
    friend class SubscriptionImpl;
};

} // namespace veilhook::veh
