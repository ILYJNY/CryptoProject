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

    TruncatedHashCollision find_truncated_sha256_collision(
        const std::size_t output_bits,
        const std::uint64_t maximum_attempts)
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
            const std::string input = "CryptoProject truncated SHA-256 demo:" + std::to_string(counter);
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
