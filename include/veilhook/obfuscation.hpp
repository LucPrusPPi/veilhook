#pragma once

// Random padding bytes baked in at configure time (mutation_seed.hpp.in).
// Not security, just layout noise between hook structs.

#include <veilhook/xorstr.hpp>
#include <veilhook/mutation_seed.hpp>

#define VEIL_CONCAT_INNER(x, y) x##y
#define VEIL_CONCAT(x, y) VEIL_CONCAT_INNER(x, y)

#define VEIL_STRUCT_PADDING_1 char VEIL_CONCAT(junk_pad_1_, __COUNTER__)[VEIL_MUTATE_SEED_1];
#define VEIL_STRUCT_PADDING_2 char VEIL_CONCAT(junk_pad_2_, __COUNTER__)[VEIL_MUTATE_SEED_2];
#define VEIL_STRUCT_PADDING_3 char VEIL_CONCAT(junk_pad_3_, __COUNTER__)[VEIL_MUTATE_SEED_3];

// Called on install/uninstall only, not in trampolines.
#define VEIL_JUNK_CODE() \
    do { \
        volatile int _veil_junk_val = static_cast<int>(veilhook::MetaRandom<__COUNTER__, true>::Value); \
        _veil_junk_val = (_veil_junk_val * 1103515245 + 12345) ^ 0xDEADBEEF; \
        (void)_veil_junk_val; \
    } while (0)
