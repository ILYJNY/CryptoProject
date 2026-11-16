#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace crypto
{
    [[nodiscard]] std::string hex_encode(std::span<const std::uint8_t> input, bool uppercase = false);
    [[nodiscard]] std::vector<std::uint8_t> hex_decode(std::string_view input);
    [[nodiscard]] bool is_valid_utf8(std::span<const std::uint8_t> input) noexcept;
    [[nodiscard]] std::vector<std::uint8_t> utf8_to_bytes(std::string_view input);
    [[nodiscard]] std::string bytes_to_utf8(std::span<const std::uint8_t> input);
}
