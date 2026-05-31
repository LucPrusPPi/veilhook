#include <veilhook/veh_hub.hpp>
#include <algorithm>

namespace veilhook::veh {

class SubscriptionImpl : public Subscription {
public:
    SubscriptionImpl(Hub& hub, uint64_t id) : hub_(hub), id_(id) {}
    ~SubscriptionImpl() override {
        hub_.remove_handler(id_);
    }
private:
    Hub& hub_;
    uint64_t id_;
};

Hub& Hub::get() {
    static Hub instance;
    return instance;
}

Hub::Hub() {
    // 1 means call this handler first
    veh_handle_ = AddVectoredExceptionHandler(1, exception_handler);
}

Hub::~Hub() {
    if (veh_handle_) {
        RemoveVectoredExceptionHandler(veh_handle_);
    }
}

std::unique_ptr<Subscription> Hub::add_handler(DWORD exception_code, int priority, ExceptionFilter filter) {
    std::unique_lock lock(rw_lock_);
    
    uint64_t id = next_id_++;
    handlers_.push_back({id, exception_code, priority, std::move(filter)});
    
    // Keep sorted by priority descending
    std::sort(handlers_.begin(), handlers_.end());
    
    return std::make_unique<SubscriptionImpl>(*this, id);
}

void Hub::remove_handler(uint64_t id) {
    std::unique_lock lock(rw_lock_);
    handlers_.erase(
        std::remove_if(handlers_.begin(), handlers_.end(), 
            [id](const HandlerEntry& e) { return e.id == id; }),
        handlers_.end()
    );
}

LONG CALLBACK Hub::exception_handler(PEXCEPTION_POINTERS ep) {
    auto& self = get();
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    // Fast path filtering: only lock if we might have a handler
    // We expect EXCEPTION_SINGLE_STEP and EXCEPTION_BREAKPOINT to be the hot paths
    
    std::shared_lock lock(self.rw_lock_);
    for (const auto& handler : self.handlers_) {
        if (handler.code == code || handler.code == 0) { // 0 could mean 'any'
            if (handler.filter(ep)) {
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }
    
    return EXCEPTION_CONTINUE_SEARCH;
}

} // namespace veilhook::veh
