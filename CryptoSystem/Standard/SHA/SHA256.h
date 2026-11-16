#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace crypto::standard
{
    using Sha256Digest = std::array<std::uint8_t, 32>;

    [[nodiscard]] Sha256Digest sha256(std::span<const std::uint8_t> input);
    [[nodiscard]] Sha256Digest sha256(std::string_view input);
    [[nodiscard]] std::vector<std::uint8_t> mgf1_sha256(
        std::span<const std::uint8_t> seed,
        std::size_t output_size);
}
