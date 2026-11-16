#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace crypto::educational
{
    struct TruncatedHashCollision
    {
        bool found = false;
        std::size_t output_bits = 0;
        std::uint32_t first_input = 0;
        std::uint32_t second_input = 0;
        std::uint32_t truncated_digest = 0;
        std::uint64_t attempts = 0;
    };

    [[nodiscard]] std::uint32_t truncated_sha256(
        const std::string& message,
        std::size_t output_bits);

    [[nodiscard]] TruncatedHashCollision find_truncated_sha256_collision(
        std::size_t output_bits = 16U,
        std::uint64_t maximum_attempts = 200000U);
}
