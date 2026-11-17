#include "ToySha256.h"

#include "SHA/SHA256.h"

#include <cstdint>
#include <stdexcept>
#include <unordered_map>

namespace crypto::educational
{
    std::uint32_t truncated_sha256(const std::string& message, const std::size_t output_bits)
    {
        if (output_bits < 4U || output_bits > 16U)
        {
            throw std::invalid_argument("Truncated SHA-256 output must be between 4 and 16 bits.");
        }

        const auto digest = standard::sha256(message);
        const std::uint32_t first =
            (static_cast<std::uint32_t>(digest[0]) << 16U) |
            (static_cast<std::uint32_t>(digest[1]) << 8U) |
            static_cast<std::uint32_t>(digest[2]);
        return first >> static_cast<unsigned int>(24U - output_bits);
    }

    std::string toy_sha_family_message(const std::string_view prefix, const std::uint64_t counter)
    {
        std::string message(prefix);
        message += std::to_string(counter);
        return message;
    }

    TruncatedHashCollision find_truncated_sha256_collision(
        const std::size_t output_bits,
        const std::uint64_t maximum_attempts)
    {
        return find_truncated_sha256_collision(output_bits, maximum_attempts, ToyShaDefaultMessagePrefix);
    }

    TruncatedHashPreimage find_truncated_sha256_preimage(
        const std::uint32_t target_digest,
        const std::size_t output_bits,
        const std::uint64_t maximum_attempts,
        const std::string_view message_prefix)
    {
        if (output_bits < 4U || output_bits > 16U)
        {
            throw std::invalid_argument("Truncated SHA-256 output must be between 4 and 16 bits.");
        }

        TruncatedHashPreimage result;
        result.output_bits = output_bits;
        result.target_digest = target_digest;
        for (std::uint64_t counter = 0; counter < maximum_attempts; ++counter)
        {
            ++result.attempts;
            if (truncated_sha256(toy_sha_family_message(message_prefix, counter), output_bits) == target_digest)
            {
                result.found = true;
                result.input_counter = counter;
                return result;
            }
        }
        return result;
    }

    TruncatedHashCollision find_truncated_sha256_collision(
        const std::size_t output_bits,
        const std::uint64_t maximum_attempts,
        const std::string_view message_prefix)
    {
        if (output_bits < 4U || output_bits > 16U)
        {
            throw std::invalid_argument("Truncated SHA-256 output must be between 4 and 16 bits.");
        }

        TruncatedHashCollision result;
        result.output_bits = output_bits;
        std::unordered_map<std::uint32_t, std::uint32_t> seen;
        seen.reserve(static_cast<std::size_t>(maximum_attempts));

        for (std::uint64_t counter = 0; counter < maximum_attempts; ++counter)
        {
            const std::string input = toy_sha_family_message(message_prefix, counter);
            const std::uint32_t digest = truncated_sha256(input, output_bits);
            ++result.attempts;

            const auto [iterator, inserted] = seen.emplace(digest, static_cast<std::uint32_t>(counter));
            if (!inserted)
            {
                result.found = true;
                result.first_input = iterator->second;
                result.second_input = static_cast<std::uint32_t>(counter);
                result.truncated_digest = digest;
                return result;
            }
        }

        return result;
    }
}
