#include <veilhook/hook/ud2.hpp>
#include <veilhook/cave_alloc.hpp>
#include <veilhook/decode.hpp>
#include <veilhook/reloc.hpp>
#include <veilhook/thread_patch.hpp>
#include <veilhook/obfuscation.hpp>
#include <asmjit/asmjit.h>
#include <cstring>

#ifndef STATUS_ILLEGAL_INSTRUCTION
#define STATUS_ILLEGAL_INSTRUCTION 0xC000001D
#endif

namespace veilhook::hook {

Ud2::Ud2(uintptr_t target, uintptr_t destination)
    : target_(target), destination_(destination) {}

Ud2::~Ud2() {
    uninstall();
}

bool Ud2::install() {
    VEIL_JUNK_CODE();
    if (is_installed_) {
        last_status_ = InstallStatus::AlreadyInstalled;
        return true;
    }

    decode::InstructionView decoder;

    patch_size_ = decoder.get_boundary_length(reinterpret_cast<uint8_t*>(target_), 2);
    if (patch_size_ == 0) {
        last_status_ = InstallStatus::BadPrologue;
        return false;
    }

    original_bytes_.resize(patch_size_);
    std::memcpy(original_bytes_.data(), reinterpret_cast<void*>(target_), patch_size_);

    trampoline_size_ = patch_size_ * 4 + 128;
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

    original_callable_ = trampoline_;

    const auto reloc_status = reloc::emit_stolen_range(
        a,
        decoder.zydis_decoder(),
        original_bytes_.data(),
        patch_size_,
        static_cast<uint64_t>(target_),
        reinterpret_cast<uint64_t>(trampoline_));

    if (reloc_status != reloc::Status::Ok) {
        mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
        trampoline_ = nullptr;
        last_status_ = InstallStatus::RelocFailed;
        return false;
    }

    a.mov(asmjit::x86::r11, target_ + patch_size_);
    a.jmp(asmjit::x86::r11);

    asmjit::CodeBuffer& buffer = code.sectionById(0)->buffer();
    if (buffer.size() > trampoline_size_) {
        mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
        trampoline_ = nullptr;
        last_status_ = InstallStatus::TrampolineOverflow;
        return false;
    }

    std::memcpy(trampoline_, buffer.data(), buffer.size());

    veh_sub_ = veh::Hub::get().add_handler(
        STATUS_ILLEGAL_INSTRUCTION,
        200,
        [this](PEXCEPTION_POINTERS ep) { return handle_exception(ep); });

    std::vector<uint8_t> patch(patch_size_, 0x90);
    patch[0] = 0x0F;
    patch[1] = 0x0B;

    if (thread_patch::suspend_others_and_patch(target_, patch_size_, patch, trampoline_)) {
        is_installed_ = true;
        last_status_ = InstallStatus::Ok;
        return true;
    }

    veh_sub_.reset();
    mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
    trampoline_ = nullptr;
    last_status_ = InstallStatus::PatchFailed;
    return false;
}

bool Ud2::uninstall() {
    VEIL_JUNK_CODE();
    if (!is_installed_) {
        return true;
    }

    if (thread_patch::suspend_others_and_patch(target_, patch_size_, original_bytes_, nullptr)) {
        veh_sub_.reset();
        is_installed_ = false;
        mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
        trampoline_ = nullptr;
        return true;
    }

    return false;
}

bool Ud2::handle_exception(PEXCEPTION_POINTERS ep) {
    if (ep->ContextRecord->Rip == target_) {
        ep->ContextRecord->Rip = destination_;
        return true;
    }
    return false;
}

} // namespace veilhook::hook
