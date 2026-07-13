#include <veilhook/hook/mid.hpp>
#include <veilhook/cave_alloc.hpp>
#include <veilhook/decode.hpp>
#include <veilhook/reloc.hpp>
#include <veilhook/thread_patch.hpp>
#include <asmjit/asmjit.h>
#include <cstring>

namespace veilhook::hook {

Mid::Mid(uintptr_t target, MidCallback callback)
    : target_(target), callback_(std::move(callback)) {}

Mid::~Mid() {
    uninstall();
}

void __stdcall Mid::dispatch_callback(Context* ctx, Mid* instance) {
    if (instance && instance->callback_) {
        instance->callback_(*ctx);
    }
}

bool Mid::install() {
    if (is_installed_) {
        last_status_ = InstallStatus::AlreadyInstalled;
        return true;
    }

    decode::InstructionView decoder;
    patch_size_ = decoder.get_boundary_length(reinterpret_cast<uint8_t*>(target_), 5);
    if (patch_size_ == 0) {
        last_status_ = InstallStatus::BadPrologue;
        return false;
    }

    original_bytes_.resize(patch_size_);
    std::memcpy(original_bytes_.data(), reinterpret_cast<void*>(target_), patch_size_);

    trampoline_size_ = patch_size_ * 4 + 512;
    trampoline_ = mem::CaveAlloc::get().allocate(target_, trampoline_size_);
    if (!trampoline_) {
        last_status_ = InstallStatus::NoTrampolineMemory;
        return false;
    }

    asmjit::JitRuntime rt;
    asmjit::CodeHolder code;
    code.init(rt.environment(), reinterpret_cast<uint64_t>(trampoline_));
    asmjit::x86::Assembler a(&code);

    using namespace asmjit::x86;

    a.mov(rax, target_);
    a.push(rax);
    a.pushfq();

    a.push(r15);
    a.push(r14);
    a.push(r13);
    a.push(r12);
    a.push(r11);
    a.push(r10);
    a.push(r9);
    a.push(r8);
    a.push(rdi);
    a.push(rsi);
    a.push(rbp);
    a.push(rsp);
    a.push(rbx);
    a.push(rdx);
    a.push(rcx);
    a.push(rax);

    a.mov(rcx, rsp);
    a.mov(rdx, reinterpret_cast<uintptr_t>(this));

    a.mov(rbp, rsp);
    a.and_(rsp, ~0xFull);
    a.sub(rsp, 0x20);

    a.mov(rax, reinterpret_cast<uintptr_t>(&Mid::dispatch_callback));
    a.call(rax);

    a.mov(rsp, rbp);

    a.pop(rax);
    a.pop(rcx);
    a.pop(rdx);
    a.pop(rbx);
    a.lea(rsp, ptr(rsp, 8));
    a.pop(rbp);
    a.pop(rsi);
    a.pop(rdi);
    a.pop(r8);
    a.pop(r9);
    a.pop(r10);
    a.pop(r11);
    a.pop(r12);
    a.pop(r13);
    a.pop(r14);
    a.pop(r15);

    a.popfq();
    a.lea(rsp, ptr(rsp, 8));

    const uint64_t stolen_emit_base =
        reinterpret_cast<uint64_t>(trampoline_) + static_cast<uint64_t>(a.offset());

    std::vector<reloc::InstSite> reloc_sites;
    reloc::BranchSlotTable branch_slots;
    const auto reloc_status = reloc::emit_stolen_range(
        a,
        decoder.zydis_decoder(),
        original_bytes_.data(),
        original_bytes_.size(),
        static_cast<uint64_t>(target_),
        stolen_emit_base,
        &reloc_sites,
        &branch_slots);

    if (reloc_status != reloc::Status::Ok) {
        mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
        trampoline_ = nullptr;
        last_status_ = InstallStatus::RelocFailed;
        return false;
    }

    reloc::emit_absolute_jump(a, target_ + patch_size_);
    reloc::emit_branch_slot_data(a, branch_slots);

    asmjit::CodeBuffer& buffer = code.sectionById(0)->buffer();
    if (buffer.size() > trampoline_size_) {
        mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
        trampoline_ = nullptr;
        last_status_ = InstallStatus::TrampolineOverflow;
        return false;
    }

    trampoline_size_ = buffer.size();
    std::memcpy(trampoline_, buffer.data(), trampoline_size_);

    std::vector<uint8_t> patch(patch_size_, 0x90);
    int64_t rel_disp = reinterpret_cast<uintptr_t>(trampoline_) - (target_ + 5);

    if (std::abs(rel_disp) <= 0x7FFFFFFF) {
        patch[0] = 0xE9;
        *reinterpret_cast<int32_t*>(&patch[1]) = static_cast<int32_t>(rel_disp);
    } else {
        mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
        trampoline_ = nullptr;
        last_status_ = InstallStatus::TrampolineTooFar;
        return false;
    }

    if (thread_patch::suspend_others_and_patch(target_, patch_size_, patch, trampoline_, &reloc_sites)) {
        is_installed_ = true;
        last_status_ = InstallStatus::Ok;
        return true;
    }

    mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
    trampoline_ = nullptr;
    last_status_ = InstallStatus::PatchFailed;
    return false;
}

bool Mid::uninstall() {
    if (!is_installed_) {
        return true;
    }

    if (thread_patch::suspend_others_and_patch(target_, patch_size_, original_bytes_, nullptr)) {
        is_installed_ = false;
        mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
        trampoline_ = nullptr;
        return true;
    }

    return false;
}

} // namespace veilhook::hook
