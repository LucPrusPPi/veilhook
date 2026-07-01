#pragma once

#include <string>
#include <array>
#include <cstdarg>

namespace veilhook {

template <class T, int I, bool B>
struct MetaRandomGenerator {
    static const unsigned int Value =
        (MetaRandomGenerator<T, I - 1, B>::Value * 214013 + 2531011);
};

template <class T, bool B>
struct MetaRandomGenerator<T, 0, B> {
    static const unsigned int Value = (unsigned int)(
        (__TIME__[7] - '0') * 1 +
        (__TIME__[6] - '0') * 10 +
        (__TIME__[4] - '0') * 60 +
        (__TIME__[3] - '0') * 600 +
        (__TIME__[1] - '0') * 3600 +
        (__TIME__[0] - '0') * 36000
    );
};

template <int I, bool B>
struct MetaRandom {
    static const unsigned int Value = MetaRandomGenerator<void, I, B>::Value;
};

template <int N>
struct MetaString {
    std::array<char, N> buffer;
    unsigned int key;
    
    constexpr MetaString(const char* str, unsigned int key) : buffer{}, key(key) {
        for (int i = 0; i < N; i++) {
            buffer[i] = static_cast<char>(str[i] ^ (key + i));
        }
    }
};

template <int N>
class XorString {
private:
    std::array<char, N> buffer;
    unsigned int key;
public:
    constexpr explicit XorString(const MetaString<N>& meta_str)
        : buffer(meta_str.buffer), key(meta_str.key) {}

    std::string decrypt() const {
        std::string result(N - 1, '\0');
        for (int i = 0; i < N - 1; i++) {
            result[i] = static_cast<char>(buffer[i] ^ (key + i));
        }
        return result;
    }
};

} // namespace veilhook

#define _XOR(str) \
    veilhook::XorString<sizeof(str)>( \
        veilhook::MetaString<sizeof(str)>(str, veilhook::MetaRandom<__COUNTER__, true>::Value) \
    ).decrypt().c_str()
