#include <veilhook/decode.hpp>
#include <cstring>

namespace veilhook::decode {

std::vector<Instruction> decode_range(InstructionView& view, uint8_t* start, size_t max_bytes) {
    std::vector<Instruction> out;
    uint8_t* current = start;
    size_t processed = 0;

    while (processed < max_bytes) {
        Instruction inst = view.decode_fast(current);
        if (inst.length == 0) {
            break;
        }

        out.push_back(inst);
        current += inst.length;
        processed += inst.length;
    }

    return out;
}

EntryPatchInfo detect_entry_patch(InstructionView& view, uintptr_t address) {
    uint8_t* code = reinterpret_cast<uint8_t*>(address);
    Instruction inst = view.decode_fast(code);

    if (inst.length == 1 && code[0] == 0xCC) {
        return {EntryPatch::Int3, 0};
    }

    if (inst.length >= 5 && code[0] == 0xE9) {
        const int32_t rel = *reinterpret_cast<const int32_t*>(code + 1);
        return {EntryPatch::NearJmp, address + 5 + rel};
    }

    if (inst.length >= 6 && code[0] == 0xFF && code[1] == 0x25) {
        const int32_t rel = *reinterpret_cast<const int32_t*>(code + 2);
        const uintptr_t ptr_address = address + 6 + rel;
        const uintptr_t destination = *reinterpret_cast<const uintptr_t*>(ptr_address);
        return {EntryPatch::FarJmp, destination};
    }

    return {};
}

uintptr_t follow_jump_chain(InstructionView& view, uintptr_t start, int max_depth) {
    uintptr_t current = start;

    for (int depth = 0; current && depth < max_depth; ++depth) {
        uint8_t* code = reinterpret_cast<uint8_t*>(current);
        Instruction inst = view.decode_fast(code);

        if (inst.length >= 5 && code[0] == 0xE9) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(code + 1);
            current = current + 5 + rel;
            continue;
        }

        if (inst.length >= 6 && code[0] == 0xFF && code[1] == 0x25) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(code + 2);
            const uintptr_t ptr_address = current + 6 + rel;
            current = *reinterpret_cast<const uintptr_t*>(ptr_address);
            continue;
        }

        break;
    }

    return current;
}

} // namespace veilhook::decode
