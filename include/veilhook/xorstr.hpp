#pragma once

#include <array>
#include <cstddef>

namespace veilhook {

template <class T, int I, bool B>
struct MetaRandomGenerator {
    static const unsigned int Value =
        (MetaRandomGenerator<T, I - 1, B>::Value * 214013 + 2531011);
};

template <class T, bool B>
struct MetaRandomGenerator<T, 0, B> {
    static const unsigned int Value = static_cast<unsigned int>(
        (__TIME__[7] - '0') * 1 +
        (__TIME__[6] - '0') * 10 +
        (__TIME__[4] - '0') * 60 +
        (__TIME__[3] - '0') * 600 +
        (__TIME__[1] - '0') * 3600 +
        (__TIME__[0] - '0') * 36000);
};

template <int I, bool B>
struct MetaRandom {
    static const unsigned int Value = MetaRandomGenerator<void, I, B>::Value;
};

template <int N>
struct MetaString {
    std::array<char, N> buffer{};
    unsigned int key = 0;

    constexpr MetaString(const char* str, unsigned int k) : key(k) {
        for (int i = 0; i < N; ++i) {
            buffer[i] = static_cast<char>(str[i] ^ (key + static_cast<unsigned int>(i)));
        }
    }
};

template <int N>
struct MetaWString {
    std::array<wchar_t, N> buffer{};
    unsigned int key = 0;

    constexpr MetaWString(const wchar_t* str, unsigned int k) : key(k) {
        for (int i = 0; i < N; ++i) {
            buffer[i] = static_cast<wchar_t>(str[i] ^ (key + static_cast<unsigned int>(i)));
        }
    }
};

template <int N>
class XorString {
public:
    constexpr explicit XorString(const MetaString<N>& meta)
        : buffer_(meta.buffer), key_(meta.key) {}

    void decrypt_to(char* out) const {
        for (int i = 0; i < N - 1; ++i) {
            out[i] = static_cast<char>(buffer_[i] ^ (key_ + static_cast<unsigned int>(i)));
        }
        out[N - 1] = '\0';
    }

private:
    std::array<char, N> buffer_;
    unsigned int key_;
};

template <int N>
class XorWString {
public:
    constexpr explicit XorWString(const MetaWString<N>& meta)
        : buffer_(meta.buffer), key_(meta.key) {}

    void decrypt_to(wchar_t* out) const {
        for (int i = 0; i < N - 1; ++i) {
            out[i] = static_cast<wchar_t>(buffer_[i] ^ (key_ + static_cast<unsigned int>(i)));
        }
        out[N - 1] = L'\0';
    }

private:
    std::array<wchar_t, N> buffer_;
    unsigned int key_;
};

} // namespace veilhook

#define VEIL_XOR_DECRYPT(out, literal)                                                     \
    do {                                                                                   \
        constexpr veilhook::XorString<sizeof(literal)> _veil_xs{                           \
            veilhook::MetaString<sizeof(literal)>(                                         \
                literal, veilhook::MetaRandom<__COUNTER__, true>::Value)};                 \
        _veil_xs.decrypt_to(out);                                                          \
    } while (0)

#define VEIL_XORW_DECRYPT(out, literal)                                                    \
    do {                                                                                   \
        constexpr veilhook::XorWString<sizeof(literal) / sizeof(wchar_t)> _veil_xws{       \
            veilhook::MetaWString<sizeof(literal) / sizeof(wchar_t)>(                      \
                literal, veilhook::MetaRandom<__COUNTER__, true>::Value)};                 \
        _veil_xws.decrypt_to(out);                                                         \
    } while (0)
