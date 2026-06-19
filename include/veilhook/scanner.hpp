#pragma once

#include <cstdint>
#include <cstddef>
#include <string_view>
#include <array>
#include <span>
#include <optional>
#include <immintrin.h>
#include <windows.h>
#include <stdexcept>

namespace veilhook::scanner {

namespace detail {

// Helper to determine the number of bytes/wildcards in a pattern string at compile time
constexpr size_t count_elements(std::string_view pattern) {
    size_t count = 0;
    bool in_space = true;
    for (char c : pattern) {
        if (c == ' ') {
            in_space = true;
        } else {
            if (in_space) {
                count++;
                in_space = false;
            }
        }
    }
    return count;
}

constexpr uint8_t hex_to_val(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    return 0;
}

struct PatternElement {
    uint8_t value;
    bool is_wildcard;
};

// Parse compile-time pattern string into array
template <size_t N>
constexpr std::array<PatternElement, N> parse_pattern(std::string_view pattern) {
    std::array<PatternElement, N> result{};
    size_t index = 0;
    size_t i = 0;
    while (i < pattern.length() && index < N) {
        while (i < pattern.length() && pattern[i] == ' ') {
            i++;
        }
        if (i >= pattern.length()) break;

        if (pattern[i] == '?') {
            result[index++] = {0, true};
            i++;
            if (i < pattern.length() && pattern[i] == '?') i++;
        } else {
            uint8_t val = 0;
            val = static_cast<uint8_t>(hex_to_val(pattern[i]) << 4);
            i++;
            if (i < pattern.length() && pattern[i] != ' ') {
                val |= hex_to_val(pattern[i]);
                i++;
            }
            result[index++] = {val, false};
        }
    }
    return result;
}

} // namespace detail

template <size_t N>
struct Pattern {
    std::array<detail::PatternElement, N> elements;
    uint8_t first_byte;
    bool has_first_byte;

    constexpr explicit Pattern(std::string_view pattern_str) 
        : elements(detail::parse_pattern<N>(pattern_str)), first_byte(0), has_first_byte(false) {
        
        if (N > 0 && !elements[0].is_wildcard) {
            first_byte = elements[0].value;
            has_first_byte = true;
        }
    }
};

// SIMD optimized scanner for x64 architecture (AVX2/SSE2)
template <size_t N>
inline std::optional<uint8_t*> scan(std::span<const uint8_t> memory, const Pattern<N>& pattern) {
    if (memory.size() < N || N == 0) return std::nullopt;

    const uint8_t* const begin = memory.data();
    const uint8_t* const end = begin + memory.size() - N + 1;
    const uint8_t* current = begin;

    if (pattern.has_first_byte) {
        const uint8_t first_byte = pattern.first_byte;
        __m128i target_vec = _mm_set1_epi8(static_cast<char>(first_byte));

        // Scan 16 bytes at a time
        while (current + 16 <= end) {
            __m128i data_vec = _mm_loadu_si128(reinterpret_cast<const __m128i*>(current));
            __m128i cmp_res = _mm_cmpeq_epi8(data_vec, target_vec);
            int mask = _mm_movemask_epi8(cmp_res);

            while (mask != 0) {
                // Find index of first matched byte in the 16-byte chunk
                unsigned long index;
                _BitScanForward(&index, mask);
                
                const uint8_t* candidate = current + index;
                
                // Scalar check for the rest of the pattern
                bool match = true;
                for (size_t i = 1; i < N; ++i) {
                    if (!pattern.elements[i].is_wildcard && candidate[i] != pattern.elements[i].value) {
                        match = false;
                        break;
                    }
                }

                if (match) {
                    return const_cast<uint8_t*>(candidate);
                }

                // Clear the bit and check next match in the chunk
                mask &= mask - 1;
            }
            current += 16;
        }
    }

    // Scalar fallback for remaining bytes (or if first byte is a wildcard)
    while (current < end) {
        bool match = true;
        for (size_t i = 0; i < N; ++i) {
            if (!pattern.elements[i].is_wildcard && current[i] != pattern.elements[i].value) {
                match = false;
                break;
            }
        }
        if (match) {
            return const_cast<uint8_t*>(current);
        }
        current++;
    }

    return std::nullopt;
}

// Scans an entire loaded module (.text execution section)
template <size_t N>
inline std::optional<uint8_t*> scan_module(HMODULE module, const Pattern<N>& pattern) {
    if (!module) return std::nullopt;

    auto base = reinterpret_cast<const uint8_t*>(module);
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return std::nullopt;

    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return std::nullopt;

    auto section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            const uint8_t* start = base + section->VirtualAddress;
            size_t size = section->Misc.VirtualSize;
            
            if (auto match = scan(std::span{start, size}, pattern)) {
                return match;
            }
        }
    }

    return std::nullopt;
}

// Resolve relative addressing (RIP-relative usually found in jmp/call/lea)
// offset: index in the matched pattern where the int32_t relative offset starts
// instruction_size: total size of the instruction to calculate RIP from
inline std::optional<uint8_t*> resolve_rip(uint8_t* instruction, size_t offset, size_t instruction_size) {
    if (!instruction) return std::nullopt;
    int32_t rel = *reinterpret_cast<int32_t*>(instruction + offset);
    return instruction + instruction_size + rel;
}

} // namespace veilhook::scanner

// Helper macro to define patterns easily
#define VEIL_PATTERN(str) \
    veilhook::scanner::Pattern<veilhook::scanner::detail::count_elements(str)>(str)
