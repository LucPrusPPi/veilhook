#include <veilhook/reloc.hpp>

#include <Zydis/Decoder.h>
#include <Zydis/Utils.h>
#include <asmjit/asmjit.h>
#include <asmjit/x86.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <unordered_map>
#include <vector>

namespace veilhook::reloc {
namespace {

using asmjit::x86::CondCode;

std::optional<CondCode> mnemonic_to_cond(ZydisMnemonic mnemonic) {
    using namespace asmjit::x86;
    switch (mnemonic) {
    case ZYDIS_MNEMONIC_JO: return CondCode::kO;
    case ZYDIS_MNEMONIC_JNO: return CondCode::kNO;
    case ZYDIS_MNEMONIC_JB: return CondCode::kB;
    case ZYDIS_MNEMONIC_JNB: return CondCode::kAE;
    case ZYDIS_MNEMONIC_JZ: return CondCode::kZ;
    case ZYDIS_MNEMONIC_JNZ: return CondCode::kNZ;
    case ZYDIS_MNEMONIC_JBE: return CondCode::kBE;
    case ZYDIS_MNEMONIC_JNBE: return CondCode::kA;
    case ZYDIS_MNEMONIC_JS: return CondCode::kS;
    case ZYDIS_MNEMONIC_JNS: return CondCode::kNS;
    case ZYDIS_MNEMONIC_JP: return CondCode::kP;
    case ZYDIS_MNEMONIC_JNP: return CondCode::kNP;
    case ZYDIS_MNEMONIC_JL: return CondCode::kL;
    case ZYDIS_MNEMONIC_JNL: return CondCode::kGE;
    case ZYDIS_MNEMONIC_JLE: return CondCode::kLE;
    case ZYDIS_MNEMONIC_JNLE: return CondCode::kG;
    case ZYDIS_MNEMONIC_JCXZ:
    case ZYDIS_MNEMONIC_JECXZ:
    case ZYDIS_MNEMONIC_JRCXZ: return std::nullopt;
    default: return std::nullopt;
    }
}

bool is_internal_target(uint64_t target, uint64_t base, size_t size) {
    return target >= base && target < base + size;
}

size_t internal_offset(uint64_t target, uint64_t base) {
    return static_cast<size_t>(target - base);
}

bool instruction_has_rip_relative_memory(
    const ZydisDecodedInstruction& instruction,
    const ZydisDecodedOperand* operands,
    const ZydisDecodedOperand** rip_operand) {
    for (ZyanU8 i = 0; i < instruction.operand_count; ++i) {
        if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            operands[i].mem.base == ZYDIS_REGISTER_RIP) {
            *rip_operand = &operands[i];
            return true;
        }
    }

    if (instruction.raw.disp.size != 0 &&
        instruction.raw.modrm.mod == 0 &&
        instruction.raw.modrm.rm == 5) {
        for (ZyanU8 i = 0; i < instruction.operand_count; ++i) {
            if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                *rip_operand = &operands[i];
                return true;
            }
        }
    }

    return false;
}

bool patch_rip_relative(
    std::vector<uint8_t>& bytes,
    const ZydisDecodedInstruction& instruction,
    const ZydisDecodedOperand& operand,
    uint64_t old_runtime_ip,
    uint64_t new_runtime_ip,
    Status& status) {
    uint64_t absolute = 0;
    if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(
            &instruction, &operand, old_runtime_ip, &absolute))) {
        status = Status::UnsupportedInstruction;
        return true;
    }

    const int64_t new_disp = static_cast<int64_t>(absolute) -
        static_cast<int64_t>(new_runtime_ip + instruction.length);

    if (instruction.raw.disp.size == 8) {
        if (new_disp < INT8_MIN || new_disp > INT8_MAX) {
            status = Status::DispOverflow;
            return true;
        }
        if (instruction.raw.disp.offset == 0) {
            status = Status::UnsupportedInstruction;
            return true;
        }
        const auto disp8 = static_cast<int8_t>(new_disp);
        std::memcpy(bytes.data() + instruction.raw.disp.offset, &disp8, sizeof(disp8));
        return true;
    }

    if (instruction.raw.disp.size != 32) {
        status = Status::UnsupportedInstruction;
        return true;
    }

    if (new_disp < INT32_MIN || new_disp > INT32_MAX) {
        status = Status::DispOverflow;
        return true;
    }

    if (instruction.raw.disp.offset == 0) {
        status = Status::UnsupportedInstruction;
        return true;
    }

    const auto disp32 = static_cast<int32_t>(new_disp);
    std::memcpy(bytes.data() + instruction.raw.disp.offset, &disp32, sizeof(disp32));
    return true;
}

asmjit::x86::Gp zydis_to_gp(ZydisRegister reg) {
    using namespace asmjit::x86;
    switch (reg) {
    case ZYDIS_REGISTER_RAX: return rax;
    case ZYDIS_REGISTER_RCX: return rcx;
    case ZYDIS_REGISTER_RDX: return rdx;
    case ZYDIS_REGISTER_RBX: return rbx;
    case ZYDIS_REGISTER_RSP: return rsp;
    case ZYDIS_REGISTER_RBP: return rbp;
    case ZYDIS_REGISTER_RSI: return rsi;
    case ZYDIS_REGISTER_RDI: return rdi;
    case ZYDIS_REGISTER_R8: return r8;
    case ZYDIS_REGISTER_R9: return r9;
    case ZYDIS_REGISTER_R10: return r10;
    case ZYDIS_REGISTER_R11: return r11;
    case ZYDIS_REGISTER_R12: return r12;
    case ZYDIS_REGISTER_R13: return r13;
    case ZYDIS_REGISTER_R14: return r14;
    case ZYDIS_REGISTER_R15: return r15;
    case ZYDIS_REGISTER_EAX: return rax;
    case ZYDIS_REGISTER_ECX: return rcx;
    case ZYDIS_REGISTER_EDX: return rdx;
    case ZYDIS_REGISTER_EBX: return rbx;
    case ZYDIS_REGISTER_ESP: return rsp;
    case ZYDIS_REGISTER_EBP: return rbp;
    case ZYDIS_REGISTER_ESI: return rsi;
    case ZYDIS_REGISTER_EDI: return rdi;
    case ZYDIS_REGISTER_R8D: return r8;
    case ZYDIS_REGISTER_R9D: return r9;
    case ZYDIS_REGISTER_R10D: return r10;
    case ZYDIS_REGISTER_R11D: return r11;
    case ZYDIS_REGISTER_R12D: return r12;
    case ZYDIS_REGISTER_R13D: return r13;
    case ZYDIS_REGISTER_R14D: return r14;
    case ZYDIS_REGISTER_R15D: return r15;
    default: return asmjit::x86::Gp();
    }
}

void collect_used_gprs(
    const ZydisDecodedInstruction& instruction,
    const ZydisDecodedOperand* operands,
    std::array<bool, 16>& used) {
    using namespace asmjit::x86;

    for (ZyanU8 i = 0; i < instruction.operand_count_visible; ++i) {
        if (operands[i].type != ZYDIS_OPERAND_TYPE_REGISTER) {
            continue;
        }
        const auto gp = zydis_to_gp(operands[i].reg.value);
        if (gp.isValid()) {
            used[static_cast<size_t>(gp.id())] = true;
        }
    }

    if (instruction.mnemonic == ZYDIS_MNEMONIC_CMPXCHG) {
        used[static_cast<size_t>(rax.id())] = true;
    }
}

asmjit::x86::Gp pick_scratch_gpr(const std::array<bool, 16>& used) {
    using namespace asmjit::x86;
    for (const Gp candidate : {r11, r10, r9, r8}) {
        if (!used[static_cast<size_t>(candidate.id())]) {
            return candidate;
        }
    }
    return Gp();
}

std::pair<asmjit::x86::Gp, asmjit::x86::Gp> pick_two_scratch_gprs(
    const std::array<bool, 16>& used) {
    const asmjit::x86::Gp first = pick_scratch_gpr(used);
    if (!first.isValid()) {
        return {asmjit::x86::Gp(), asmjit::x86::Gp()};
    }

    std::array<bool, 16> extended = used;
    extended[static_cast<size_t>(first.id())] = true;
    const asmjit::x86::Gp second = pick_scratch_gpr(extended);
    return {first, second};
}

asmjit::x86::Mem sized_mem_ptr(asmjit::x86::Gp base, const ZydisDecodedOperand& mem_op) {
    using namespace asmjit::x86;
    switch (mem_op.size) {
    case 8: return byte_ptr(base);
    case 16: return word_ptr(base);
    case 32: return dword_ptr(base);
    case 64: return qword_ptr(base);
    default:
        if (mem_op.size <= 8) return byte_ptr(base);
        if (mem_op.size <= 16) return word_ptr(base);
        if (mem_op.size <= 32) return dword_ptr(base);
        return qword_ptr(base);
    }
}

const ZydisDecodedOperand* find_rip_memory_operand(
    const ZydisDecodedInstruction& instruction,
    const ZydisDecodedOperand* operands) {
    for (ZyanU8 i = 0; i < instruction.operand_count_visible; ++i) {
        if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            operands[i].mem.base == ZYDIS_REGISTER_RIP) {
            return &operands[i];
        }
    }
    return nullptr;
}

const ZydisDecodedOperand* find_other_operand(
    const ZydisDecodedInstruction& instruction,
    const ZydisDecodedOperand* operands,
    const ZydisDecodedOperand* skip) {
    for (ZyanU8 i = 0; i < instruction.operand_count_visible; ++i) {
        if (&operands[i] == skip) {
            continue;
        }
        if (operands[i].type == ZYDIS_OPERAND_TYPE_REGISTER ||
            operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            return &operands[i];
        }
    }
    return nullptr;
}

std::optional<asmjit::x86::Xmm> zydis_to_xmm(ZydisRegister reg) {
    using namespace asmjit::x86;
    if (reg >= ZYDIS_REGISTER_XMM0 && reg <= ZYDIS_REGISTER_XMM15) {
        return xmm(static_cast<uint32_t>(reg - ZYDIS_REGISTER_XMM0));
    }
    return std::nullopt;
}

std::optional<asmjit::x86::Ymm> zydis_to_ymm(ZydisRegister reg) {
    using namespace asmjit::x86;
    if (reg >= ZYDIS_REGISTER_YMM0 && reg <= ZYDIS_REGISTER_YMM15) {
        return ymm(static_cast<uint32_t>(reg - ZYDIS_REGISTER_YMM0));
    }
    return std::nullopt;
}

bool emit_vector_load(
    asmjit::x86::Assembler& a,
    ZydisMnemonic mnemonic,
    const ZydisDecodedOperand& dst,
    const asmjit::x86::Mem& mem) {
    using namespace asmjit::x86;
    if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER) {
        return false;
    }

    if (const auto xmm = zydis_to_xmm(dst.reg.value)) {
        switch (mnemonic) {
        case ZYDIS_MNEMONIC_MOVUPS: a.movups(*xmm, mem); return true;
        case ZYDIS_MNEMONIC_MOVUPD: a.movupd(*xmm, mem); return true;
        case ZYDIS_MNEMONIC_MOVAPS: a.movaps(*xmm, mem); return true;
        case ZYDIS_MNEMONIC_MOVAPD: a.movapd(*xmm, mem); return true;
        case ZYDIS_MNEMONIC_MOVDQU: a.movdqu(*xmm, mem); return true;
        case ZYDIS_MNEMONIC_MOVDQA: a.movdqa(*xmm, mem); return true;
        case ZYDIS_MNEMONIC_MOVSS: a.movss(*xmm, mem); return true;
        case ZYDIS_MNEMONIC_MOVSD: a.movsd(*xmm, mem); return true;
        default: return false;
        }
    }

    if (const auto ymm = zydis_to_ymm(dst.reg.value)) {
        switch (mnemonic) {
        case ZYDIS_MNEMONIC_VMOVUPS: a.vmovups(*ymm, mem); return true;
        case ZYDIS_MNEMONIC_VMOVUPD: a.vmovupd(*ymm, mem); return true;
        case ZYDIS_MNEMONIC_VMOVAPS: a.vmovaps(*ymm, mem); return true;
        case ZYDIS_MNEMONIC_VMOVDQU: a.vmovdqu(*ymm, mem); return true;
        case ZYDIS_MNEMONIC_VMOVDQA: a.vmovdqa(*ymm, mem); return true;
        default: return false;
        }
    }

    return false;
}

bool emit_vector_store(
    asmjit::x86::Assembler& a,
    ZydisMnemonic mnemonic,
    const asmjit::x86::Mem& mem,
    const ZydisDecodedOperand& src) {
    using namespace asmjit::x86;
    if (src.type != ZYDIS_OPERAND_TYPE_REGISTER) {
        return false;
    }

    if (const auto xmm = zydis_to_xmm(src.reg.value)) {
        switch (mnemonic) {
        case ZYDIS_MNEMONIC_MOVUPS: a.movups(mem, *xmm); return true;
        case ZYDIS_MNEMONIC_MOVUPD: a.movupd(mem, *xmm); return true;
        case ZYDIS_MNEMONIC_MOVAPS: a.movaps(mem, *xmm); return true;
        case ZYDIS_MNEMONIC_MOVAPD: a.movapd(mem, *xmm); return true;
        case ZYDIS_MNEMONIC_MOVDQU: a.movdqu(mem, *xmm); return true;
        case ZYDIS_MNEMONIC_MOVDQA: a.movdqa(mem, *xmm); return true;
        case ZYDIS_MNEMONIC_MOVSS: a.movss(mem, *xmm); return true;
        case ZYDIS_MNEMONIC_MOVSD: a.movsd(mem, *xmm); return true;
        default: return false;
        }
    }

    if (const auto ymm = zydis_to_ymm(src.reg.value)) {
        switch (mnemonic) {
        case ZYDIS_MNEMONIC_VMOVUPS: a.vmovups(mem, *ymm); return true;
        case ZYDIS_MNEMONIC_VMOVUPD: a.vmovupd(mem, *ymm); return true;
        case ZYDIS_MNEMONIC_VMOVAPS: a.vmovaps(mem, *ymm); return true;
        case ZYDIS_MNEMONIC_VMOVDQU: a.vmovdqu(mem, *ymm); return true;
        case ZYDIS_MNEMONIC_VMOVDQA: a.vmovdqa(mem, *ymm); return true;
        default: return false;
        }
    }

    return false;
}

Status emit_rip_memory_translation(
    asmjit::x86::Assembler& a,
    const ZydisDecodedInstruction& instruction,
    const ZydisDecodedOperand* operands,
    uint64_t old_runtime_ip) {
    using namespace asmjit::x86;

    const ZydisDecodedOperand* mem_op = find_rip_memory_operand(instruction, operands);
    if (!mem_op) {
        return Status::UnsupportedInstruction;
    }

    uint64_t absolute = 0;
    if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(
            &instruction, mem_op, old_runtime_ip, &absolute))) {
        return Status::UnsupportedInstruction;
    }

    const ZydisDecodedOperand* other = find_other_operand(instruction, operands, mem_op);
    const bool mem_is_dest = (mem_op->actions & ZYDIS_OPERAND_ACTION_WRITE) != 0;
    size_t mem_index = 0;
    for (ZyanU8 i = 0; i < instruction.operand_count_visible; ++i) {
        if (&operands[i] == mem_op) {
            mem_index = i;
            break;
        }
    }
    size_t other_index = 0;
    for (ZyanU8 i = 0; i < instruction.operand_count_visible; ++i) {
        if (&operands[i] == other) {
            other_index = i;
            break;
        }
    }
    const bool mem_before_other = other == nullptr || mem_index < other_index;

    if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA) {
        if (!other || other->type != ZYDIS_OPERAND_TYPE_REGISTER) {
            return Status::UnsupportedInstruction;
        }
        a.mov(zydis_to_gp(other->reg.value), absolute);
        return Status::Ok;
    }

    std::array<bool, 16> used{};
    collect_used_gprs(instruction, operands, used);

    if (!mem_is_dest &&
        (instruction.mnemonic == ZYDIS_MNEMONIC_CMP ||
         instruction.mnemonic == ZYDIS_MNEMONIC_TEST) &&
        other && other->type == ZYDIS_OPERAND_TYPE_REGISTER && !mem_before_other) {
        const auto [addr_scratch, temp_scratch] = pick_two_scratch_gprs(used);
        if (!temp_scratch.isValid()) {
            return Status::UnsupportedInstruction;
        }

        a.push(addr_scratch);
        a.mov(addr_scratch, absolute);
        a.push(temp_scratch);
        a.mov(temp_scratch, sized_mem_ptr(addr_scratch, *mem_op));
        if (instruction.mnemonic == ZYDIS_MNEMONIC_CMP) {
            a.cmp(zydis_to_gp(other->reg.value), temp_scratch);
        } else {
            a.test(zydis_to_gp(other->reg.value), temp_scratch);
        }
        a.pop(temp_scratch);
        a.pop(addr_scratch);
        return Status::Ok;
    }

    const asmjit::x86::Gp addr_scratch = pick_scratch_gpr(used);
    if (!addr_scratch.isValid()) {
        return Status::UnsupportedInstruction;
    }

    a.push(addr_scratch);
    a.mov(addr_scratch, absolute);
    const Mem mem = sized_mem_ptr(addr_scratch, *mem_op);

    if (mem_is_dest) {
        if (!other || other->type != ZYDIS_OPERAND_TYPE_REGISTER) {
            a.pop(addr_scratch);
            return Status::UnsupportedInstruction;
        }
        switch (instruction.mnemonic) {
        case ZYDIS_MNEMONIC_MOV:
            if (emit_vector_store(a, instruction.mnemonic, mem, *other)) {
                break;
            }
            a.mov(mem, zydis_to_gp(other->reg.value));
            break;
        case ZYDIS_MNEMONIC_ADD:
        case ZYDIS_MNEMONIC_SUB:
        case ZYDIS_MNEMONIC_AND:
        case ZYDIS_MNEMONIC_OR:
        case ZYDIS_MNEMONIC_XOR:
        case ZYDIS_MNEMONIC_ADC:
        case ZYDIS_MNEMONIC_SBB: {
            const auto reg = zydis_to_gp(other->reg.value);
            switch (instruction.mnemonic) {
            case ZYDIS_MNEMONIC_ADD: a.add(mem, reg); break;
            case ZYDIS_MNEMONIC_SUB: a.sub(mem, reg); break;
            case ZYDIS_MNEMONIC_AND: a.and_(mem, reg); break;
            case ZYDIS_MNEMONIC_OR: a.or_(mem, reg); break;
            case ZYDIS_MNEMONIC_XOR: a.xor_(mem, reg); break;
            case ZYDIS_MNEMONIC_ADC: a.adc(mem, reg); break;
            case ZYDIS_MNEMONIC_SBB: a.sbb(mem, reg); break;
            default: break;
            }
            break;
        }
        case ZYDIS_MNEMONIC_XCHG:
            a.xchg(mem, zydis_to_gp(other->reg.value));
            break;
        case ZYDIS_MNEMONIC_CMPXCHG:
            if (!other || other->type != ZYDIS_OPERAND_TYPE_REGISTER) {
                a.pop(addr_scratch);
                return Status::UnsupportedInstruction;
            }
            a.lock();
            a.cmpxchg(mem, zydis_to_gp(other->reg.value));
            break;
        case ZYDIS_MNEMONIC_INC: a.inc(mem); break;
        case ZYDIS_MNEMONIC_DEC: a.dec(mem); break;
        case ZYDIS_MNEMONIC_NOT: a.not_(mem); break;
        case ZYDIS_MNEMONIC_NEG: a.neg(mem); break;
        default:
            a.pop(addr_scratch);
            return Status::UnsupportedInstruction;
        }
    } else {
        switch (instruction.mnemonic) {
        case ZYDIS_MNEMONIC_MOV: {
            if (!other) {
                a.pop(addr_scratch);
                return Status::UnsupportedInstruction;
            }
            if (other->type == ZYDIS_OPERAND_TYPE_REGISTER) {
                if (emit_vector_load(a, instruction.mnemonic, *other, mem)) {
                    break;
                }
                a.mov(zydis_to_gp(other->reg.value), mem);
            } else if (other->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                if (other->imm.is_signed) {
                    a.mov(mem, other->imm.value.s);
                } else {
                    a.mov(mem, other->imm.value.u);
                }
            } else {
                a.pop(addr_scratch);
                return Status::UnsupportedInstruction;
            }
            break;
        }
        case ZYDIS_MNEMONIC_CMPXCHG: {
            if (!other || other->type != ZYDIS_OPERAND_TYPE_REGISTER) {
                a.pop(addr_scratch);
                return Status::UnsupportedInstruction;
            }
            a.lock();
            a.cmpxchg(mem, zydis_to_gp(other->reg.value));
            break;
        }
        case ZYDIS_MNEMONIC_CMP: {
            if (!other) {
                a.pop(addr_scratch);
                return Status::UnsupportedInstruction;
            }
            if (other->type == ZYDIS_OPERAND_TYPE_REGISTER) {
                a.cmp(mem, zydis_to_gp(other->reg.value));
            } else if (other->imm.is_signed) {
                a.cmp(mem, other->imm.value.s);
            } else {
                a.cmp(mem, other->imm.value.u);
            }
            break;
        }
        case ZYDIS_MNEMONIC_TEST: {
            if (!other) {
                a.pop(addr_scratch);
                return Status::UnsupportedInstruction;
            }
            if (other->type == ZYDIS_OPERAND_TYPE_REGISTER) {
                a.test(mem, zydis_to_gp(other->reg.value));
            } else if (other->imm.is_signed) {
                a.test(mem, other->imm.value.s);
            } else {
                a.test(mem, other->imm.value.u);
            }
            break;
        }
        default:
            a.pop(addr_scratch);
            return Status::UnsupportedInstruction;
        }
    }

    a.pop(addr_scratch);
    return Status::Ok;
}

Status emit_raw_with_rip_fixup(
    asmjit::x86::Assembler& a,
    const uint8_t* bytes,
    const ZydisDecodedInstruction& instruction,
    const ZydisDecodedOperand* operands,
    uint64_t old_runtime_ip,
    uint64_t emit_runtime_base) {
    std::vector<uint8_t> copy(bytes, bytes + instruction.length);

    const uint64_t new_runtime_ip = emit_runtime_base + static_cast<uint64_t>(a.offset());

    Status status = Status::Ok;
    const ZydisDecodedOperand* rip_operand = nullptr;
    if (!instruction_has_rip_relative_memory(instruction, operands, &rip_operand)) {
        a.embed(bytes, instruction.length);
        return Status::Ok;
    }

    if (patch_rip_relative(
            copy, instruction, *rip_operand, old_runtime_ip, new_runtime_ip, status)) {
        if (status == Status::DispOverflow) {
            return emit_rip_memory_translation(
                a, instruction, operands, old_runtime_ip);
        }
        if (status != Status::Ok) {
            return status;
        }
        a.embed(copy.data(), copy.size());
        return Status::Ok;
    }

    a.embed(bytes, instruction.length);
    return Status::Ok;
}

Status emit_external_branch(
    asmjit::x86::Assembler& a,
    CondCode cond,
    uint64_t absolute_target,
    BranchSlotTable& slots) {
    using namespace asmjit::x86;
    asmjit::Label skip = a.newLabel();
    slots.slot_for(a, absolute_target);
    a.j(reverseCond(cond), skip);
    slots.emit_jump(a, absolute_target);
    a.bind(skip);
    return Status::Ok;
}

Status emit_relative_control_flow(
    asmjit::x86::Assembler& a,
    const ZydisDecodedInstruction& instruction,
    const ZydisDecodedOperand& operand,
    uint64_t old_runtime_ip,
    uint64_t stolen_runtime_base,
    size_t stolen_size,
    std::unordered_map<size_t, asmjit::Label>& internal_labels,
    BranchSlotTable& branch_slots) {
    using namespace asmjit::x86;
    uint64_t absolute_target = 0;
    if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(
            &instruction, &operand, old_runtime_ip, &absolute_target))) {
        return Status::UnsupportedInstruction;
    }

    if (is_internal_target(absolute_target, stolen_runtime_base, stolen_size)) {
        const size_t offset = internal_offset(absolute_target, stolen_runtime_base);
        asmjit::Label& target = internal_labels[offset];

        if (instruction.meta.category == ZYDIS_CATEGORY_CALL) {
            a.call(target);
            return Status::Ok;
        }

        if (instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR) {
            a.jmp(target);
            return Status::Ok;
        }

        const auto cond = mnemonic_to_cond(instruction.mnemonic);
        if (!cond) {
            return Status::UnsupportedInstruction;
        }

        a.j(*cond, target);
        return Status::Ok;
    }

    if (instruction.meta.category == ZYDIS_CATEGORY_CALL) {
        branch_slots.slot_for(a, absolute_target);
        branch_slots.emit_call(a, absolute_target);
        return Status::Ok;
    }

    if (instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR) {
        branch_slots.slot_for(a, absolute_target);
        branch_slots.emit_jump(a, absolute_target);
        return Status::Ok;
    }

    const auto cond = mnemonic_to_cond(instruction.mnemonic);
    if (!cond) {
        return Status::UnsupportedInstruction;
    }

    return emit_external_branch(a, *cond, absolute_target, branch_slots);
}

} // namespace

asmjit::Label BranchSlotTable::slot_for(asmjit::x86::Assembler& a, uint64_t destination) {
    const auto found = slots_.find(destination);
    if (found != slots_.end()) {
        return found->second;
    }

    const asmjit::Label holder = a.newLabel();
    slots_.emplace(destination, holder);
    order_.push_back({holder, destination});
    return holder;
}

void BranchSlotTable::emit_jump(asmjit::x86::Assembler& a, uint64_t destination) const {
    using namespace asmjit::x86;
    const auto found = slots_.find(destination);
    if (found == slots_.end()) {
        return;
    }
    a.jmp(qword_ptr(found->second));
}

void BranchSlotTable::emit_call(asmjit::x86::Assembler& a, uint64_t destination) const {
    using namespace asmjit::x86;
    const auto found = slots_.find(destination);
    if (found == slots_.end()) {
        return;
    }
    a.call(qword_ptr(found->second));
}

void BranchSlotTable::emit_data(asmjit::x86::Assembler& a) const {
    for (const auto& [label, destination] : order_) {
        a.bind(label);
        a.embedUInt64(destination);
    }
}

void emit_branch_slot_data(asmjit::x86::Assembler& a, BranchSlotTable& table) {
    table.emit_data(a);
}

void emit_absolute_jump(asmjit::x86::Assembler& a, uint64_t destination) {
    using namespace asmjit::x86;
    a.push(rax);
    a.mov(rax, destination);
    a.xchg(ptr(rsp), rax);
    a.ret();
}

void emit_absolute_call(
    asmjit::x86::Assembler& a,
    uint64_t destination,
    BranchSlotTable& slots) {
    slots.slot_for(a, destination);
    slots.emit_call(a, destination);
}

uint64_t translate_runtime_ip(
    uint64_t runtime_rip,
    uint64_t stolen_runtime_base,
    size_t stolen_size,
    uint64_t trampoline_runtime_base,
    const std::vector<InstSite>& sites) {
    if (runtime_rip < stolen_runtime_base || runtime_rip >= stolen_runtime_base + stolen_size) {
        return runtime_rip;
    }

    const size_t source_offset = static_cast<size_t>(runtime_rip - stolen_runtime_base);

    for (const InstSite& site : sites) {
        if (source_offset < site.source_offset ||
            source_offset >= site.source_offset + site.source_length) {
            continue;
        }

        size_t intra = source_offset - site.source_offset;
        if (site.emit_length != site.source_length) {
            intra = 0;
        }

        return trampoline_runtime_base + site.emit_offset + intra;
    }

    return trampoline_runtime_base + source_offset;
}

uint64_t translate_emit_ip_to_source(
    uint64_t runtime_rip,
    uint64_t emit_runtime_base,
    size_t emit_size,
    uint64_t stolen_runtime_base,
    const std::vector<InstSite>& sites) {
    if (runtime_rip < emit_runtime_base || runtime_rip >= emit_runtime_base + emit_size) {
        return runtime_rip;
    }

    const size_t emit_offset = static_cast<size_t>(runtime_rip - emit_runtime_base);

    for (const InstSite& site : sites) {
        if (emit_offset < site.emit_offset ||
            emit_offset >= site.emit_offset + site.emit_length) {
            continue;
        }

        size_t intra = emit_offset - site.emit_offset;
        if (site.emit_length != site.source_length) {
            intra = 0;
        }

        return stolen_runtime_base + site.source_offset + intra;
    }

    return stolen_runtime_base + emit_offset;
}

Status emit_stolen_range(
    asmjit::x86::Assembler& a,
    ZydisDecoder& decoder,
    const uint8_t* stolen,
    size_t stolen_size,
    uint64_t stolen_runtime_base,
    uint64_t emit_runtime_base,
    std::vector<InstSite>* sites_out,
    BranchSlotTable* branch_slots_out) {
    using Label = asmjit::Label;
    if (!stolen || stolen_size == 0) {
        return Status::DecodeFailed;
    }

    BranchSlotTable local_slots;
    BranchSlotTable& branch_slots = branch_slots_out ? *branch_slots_out : local_slots;
    branch_slots.reset();

    std::unordered_map<size_t, Label> internal_labels;
  {
        size_t offset = 0;
        while (offset < stolen_size) {
            internal_labels.emplace(offset, a.newLabel());

            ZydisDecodedInstruction instruction{};
            if (ZYAN_FAILED(ZydisDecoderDecodeInstruction(
                    &decoder, nullptr, stolen + offset, stolen_size - offset, &instruction)) ||
                instruction.length == 0) {
                return Status::DecodeFailed;
            }

            offset += instruction.length;
        }
    }

    size_t offset = 0;
    while (offset < stolen_size) {
        a.bind(internal_labels[offset]);

        const size_t emit_start = static_cast<size_t>(a.offset());
        const uint8_t* current = stolen + offset;
        ZydisDecodedInstruction instruction{};
        ZydisDecoderContext context{};
        if (ZYAN_FAILED(ZydisDecoderDecodeInstruction(
                &decoder, &context, current, stolen_size - offset, &instruction)) ||
            instruction.length == 0) {
            return Status::DecodeFailed;
        }

        std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};
        if (instruction.operand_count > 0 &&
            ZYAN_FAILED(ZydisDecoderDecodeOperands(
                &decoder, &context, &instruction, operands.data(), instruction.operand_count))) {
            return Status::DecodeFailed;
        }

        const uint64_t old_runtime_ip = stolen_runtime_base + offset;
        bool emitted = false;

        if (instruction.meta.category == ZYDIS_CATEGORY_CALL ||
            instruction.meta.category == ZYDIS_CATEGORY_COND_BR ||
            instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR) {
            for (ZyanU8 i = 0; i < instruction.operand_count_visible; ++i) {
                if (operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operands[i].imm.is_relative) {
                    const Status status = emit_relative_control_flow(
                        a,
                        instruction,
                        operands[i],
                        old_runtime_ip,
                        stolen_runtime_base,
                        stolen_size,
                        internal_labels,
                        branch_slots);
                    if (status != Status::Ok) {
                        return status;
                    }
                    emitted = true;
                    break;
                }
            }
        }

        if (!emitted) {
            const Status status = emit_raw_with_rip_fixup(
                a, current, instruction, operands.data(), old_runtime_ip, emit_runtime_base);
            if (status != Status::Ok) {
                return status;
            }
        }

        if (sites_out) {
            sites_out->push_back(InstSite{
                offset,
                instruction.length,
                emit_start,
                static_cast<size_t>(a.offset()) - emit_start,
            });
        }

        offset += instruction.length;
    }

    return Status::Ok;
}

} // namespace veilhook::reloc
