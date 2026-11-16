#include "SHA256.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace crypto::standard
{
    namespace
    {
        constexpr std::array<std::uint32_t, 64> K{
            0x428A2F98U, 0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U,
            0x3956C25BU, 0x59F111F1U, 0x923F82A4U, 0xAB1C5ED5U,
            0xD807AA98U, 0x12835B01U, 0x243185BEU, 0x550C7DC3U,
            0x72BE5D74U, 0x80DEB1FEU, 0x9BDC06A7U, 0xC19BF174U,
            0xE49B69C1U, 0xEFBE4786U, 0x0FC19DC6U, 0x240CA1CCU,
            0x2DE92C6FU, 0x4A7484AAU, 0x5CB0A9DCU, 0x76F988DAU,
            0x983E5152U, 0xA831C66DU, 0xB00327C8U, 0xBF597FC7U,
            0xC6E00BF3U, 0xD5A79147U, 0x06CA6351U, 0x14292967U,
            0x27B70A85U, 0x2E1B2138U, 0x4D2C6DFCU, 0x53380D13U,
            0x650A7354U, 0x766A0ABBU, 0x81C2C92EU, 0x92722C85U,
            0xA2BFE8A1U, 0xA81A664BU, 0xC24B8B70U, 0xC76C51A3U,
            0xD192E819U, 0xD6990624U, 0xF40E3585U, 0x106AA070U,
            0x19A4C116U, 0x1E376C08U, 0x2748774CU, 0x34B0BCB5U,
            0x391C0CB3U, 0x4ED8AA4AU, 0x5B9CCA4FU, 0x682E6FF3U,
            0x748F82EEU, 0x78A5636FU, 0x84C87814U, 0x8CC70208U,
            0x90BEFFFAU, 0xA4506CEBU, 0xBEF9A3F7U, 0xC67178F2U
        };

        constexpr std::uint32_t rotr(const std::uint32_t value, const unsigned int shift)
        {
            return (value >> shift) | (value << (32U - shift));
        }

        void transform(std::array<std::uint32_t, 8>& state, const std::uint8_t* block)
        {
            std::array<std::uint32_t, 64> words{};
            for (std::size_t i = 0; i < 16; ++i)
            {
                const std::size_t offset = i * 4U;
                words[i] = (static_cast<std::uint32_t>(block[offset]) << 24U) |
                           (static_cast<std::uint32_t>(block[offset + 1U]) << 16U) |
                           (static_cast<std::uint32_t>(block[offset + 2U]) << 8U) |
                           static_cast<std::uint32_t>(block[offset + 3U]);
            }

            for (std::size_t i = 16; i < 64; ++i)
            {
                const std::uint32_t s0 = rotr(words[i - 15U], 7U) ^
                                         rotr(words[i - 15U], 18U) ^
                                         (words[i - 15U] >> 3U);
                const std::uint32_t s1 = rotr(words[i - 2U], 17U) ^
                                         rotr(words[i - 2U], 19U) ^
                                         (words[i - 2U] >> 10U);
                words[i] = words[i - 16U] + s0 + words[i - 7U] + s1;
            }

            auto a = state[0];
            auto b = state[1];
            auto c = state[2];
            auto d = state[3];
            auto e = state[4];
            auto f = state[5];
            auto g = state[6];
            auto h = state[7];

            for (std::size_t i = 0; i < 64; ++i)
            {
                const std::uint32_t sum1 = rotr(e, 6U) ^ rotr(e, 11U) ^ rotr(e, 25U);
                const std::uint32_t choose = (e & f) ^ (~e & g);
                const std::uint32_t temp1 = h + sum1 + choose + K[i] + words[i];
                const std::uint32_t sum0 = rotr(a, 2U) ^ rotr(a, 13U) ^ rotr(a, 22U);
                const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
                const std::uint32_t temp2 = sum0 + majority;

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            state[0] += a; state[1] += b; state[2] += c; state[3] += d;
            state[4] += e; state[5] += f; state[6] += g; state[7] += h;
        }
    }

    Sha256Digest sha256(const std::span<const std::uint8_t> input)
    {
        if (input.size() > (std::numeric_limits<std::uint64_t>::max() / 8U))
        {
            throw std::length_error("SHA-256 input is too large.");
        }

        std::array<std::uint32_t, 8> state{
            0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
            0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U
        };

        std::size_t offset = 0;
        while (input.size() - offset >= 64U)
        {
            transform(state, input.data() + offset);
            offset += 64U;
        }

        std::array<std::uint8_t, 128> tail{};
        const std::size_t remaining = input.size() - offset;
        if (remaining > 0U)
        {
            std::memcpy(tail.data(), input.data() + offset, remaining);
        }
        tail[remaining] = 0x80U;

        const std::size_t paddedSize = remaining < 56U ? 64U : 128U;
        const std::uint64_t bitLength = static_cast<std::uint64_t>(input.size()) * 8U;
        for (std::size_t i = 0; i < 8U; ++i)
        {
            tail[paddedSize - 1U - i] = static_cast<std::uint8_t>(bitLength >> (i * 8U));
        }

        transform(state, tail.data());
        if (paddedSize == 128U)
        {
            transform(state, tail.data() + 64U);
        }

        Sha256Digest digest{};
        for (std::size_t i = 0; i < state.size(); ++i)
        {
            digest[i * 4U] = static_cast<std::uint8_t>(state[i] >> 24U);
            digest[i * 4U + 1U] = static_cast<std::uint8_t>(state[i] >> 16U);
            digest[i * 4U + 2U] = static_cast<std::uint8_t>(state[i] >> 8U);
            digest[i * 4U + 3U] = static_cast<std::uint8_t>(state[i]);
        }
        return digest;
    }

    Sha256Digest sha256(const std::string_view input)
    {
        const auto* ptr = reinterpret_cast<const std::uint8_t*>(input.data());
        return sha256(std::span<const std::uint8_t>(ptr, input.size()));
    }

    std::vector<std::uint8_t> mgf1_sha256(
        const std::span<const std::uint8_t> seed,
        const std::size_t output_size)
    {
        constexpr std::uint64_t maxCounter = 0xFFFFFFFFULL;
        const std::uint64_t blocks = static_cast<std::uint64_t>((output_size + 31U) / 32U);
        if (blocks > maxCounter + 1ULL)
        {
            throw std::length_error("MGF1 output is too large.");
        }

        std::vector<std::uint8_t> output;
        output.reserve(output_size);
        std::vector<std::uint8_t> input(seed.begin(), seed.end());
        input.resize(seed.size() + 4U);

        for (std::uint64_t counter = 0; output.size() < output_size; ++counter)
        {
            const std::size_t base = seed.size();
            input[base] = static_cast<std::uint8_t>(counter >> 24U);
            input[base + 1U] = static_cast<std::uint8_t>(counter >> 16U);
            input[base + 2U] = static_cast<std::uint8_t>(counter >> 8U);
            input[base + 3U] = static_cast<std::uint8_t>(counter);
            const auto digest = sha256(input);
            const std::size_t remaining = output_size - output.size();
            const std::size_t take = std::min(remaining, digest.size());
            output.insert(output.end(), digest.begin(), digest.begin() + static_cast<std::ptrdiff_t>(take));
        }
        return output;
    }
}
