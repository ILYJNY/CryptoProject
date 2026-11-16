#pragma once

#include "BigInteger/BigInteger.h"
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace crypto
{
    class SecureRandom final
    {
    public:
        SecureRandom() = delete;
        static void fill(std::span<std::uint8_t> output);
        [[nodiscard]] static std::vector<std::uint8_t> bytes(std::size_t count);
        [[nodiscard]] static std::uint64_t u64();
        [[nodiscard]] static std::uint64_t uniform_u64(std::uint64_t minimum, std::uint64_t maximum);
        [[nodiscard]] static BigInt below(const BigInt& exclusive_upper_bound);
    };
}
