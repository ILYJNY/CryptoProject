#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

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

    // ---------------------------------------------------------------------------------
    // Message families and a classical preimage search (added in 2.3.5).
    // A message family is the set { prefix + decimal(counter) }. The collision search
    // above uses the family with ToyShaDefaultMessagePrefix.
    // ---------------------------------------------------------------------------------

    inline constexpr std::string_view ToyShaDefaultMessagePrefix = "CryptoProject truncated SHA-256 demo:";

    [[nodiscard]] std::string toy_sha_family_message(std::string_view prefix, std::uint64_t counter);

    // Classical birthday search over the family with the given prefix.
    [[nodiscard]] TruncatedHashCollision find_truncated_sha256_collision(
        std::size_t output_bits,
        std::uint64_t maximum_attempts,
        std::string_view message_prefix);

    struct TruncatedHashPreimage
    {
        bool found = false;
        std::size_t output_bits = 0;
        std::uint32_t target_digest = 0;
        std::uint64_t input_counter = 0;
        std::uint64_t attempts = 0;
    };

    // Classical exhaustive preimage search: scans counters 0, 1, 2, ... of the family
    // until the truncated digest equals target_digest. This is a preimage search and is
    // deliberately separate from the collision search.
    [[nodiscard]] TruncatedHashPreimage find_truncated_sha256_preimage(
        std::uint32_t target_digest,
        std::size_t output_bits,
        std::uint64_t maximum_attempts,
        std::string_view message_prefix = ToyShaDefaultMessagePrefix);
}
