#pragma once

#include <veilhook/xorstr.hpp>
#include <veilhook/mutation_seed.hpp>

// Helper to concatenate compiler tokens safely
#define VEIL_CONCAT_INNER(x, y) x##y
#define VEIL_CONCAT(x, y) VEIL_CONCAT_INNER(x, y)

// Generates a random array padding per structure instance.
// Using CMake-configured build-wide seeds to satisfy ODR (One Definition Rule) across translation units.
#define VEIL_STRUCT_PADDING_1 char VEIL_CONCAT(junk_pad_1_, __COUNTER__)[VEIL_MUTATE_SEED_1];
#define VEIL_STRUCT_PADDING_2 char VEIL_CONCAT(junk_pad_2_, __COUNTER__)[VEIL_MUTATE_SEED_2];
#define VEIL_STRUCT_PADDING_3 char VEIL_CONCAT(junk_pad_3_, __COUNTER__)[VEIL_MUTATE_SEED_3];

// Compile-time polymorphic junk operations.
// These operations are marked volatile and use (void) to satisfy /W4 /WX compiler warnings.
// They execute in non-performance-critical blocks (like install / uninstall) to guarantee
// no performance degradation on hot paths (callbacks, trampolines).
#define VEIL_JUNK_CODE() \
    do { \
        volatile int _veil_junk_val = static_cast<int>(veilhook::MetaRandom<__COUNTER__, true>::Value); \
        _veil_junk_val = (_veil_junk_val * 1103515245 + 12345) ^ 0xDEADBEEF; \
        (void)_veil_junk_val; \
    } while (0)
