#include "Encoding/Encoding.h"
#include "ErrorHandling/CryptoException.h"

namespace crypto
{
    std::string hex_encode(const std::span<const std::uint8_t> input, const bool uppercase)
    {
        constexpr char lower[] = "0123456789abcdef";
        constexpr char upper[] = "0123456789ABCDEF";
        const char* digits = uppercase ? upper : lower;
        std::string result(input.size() * 2U, '\0');
        for (std::size_t i = 0; i < input.size(); ++i)
        {
            result[i * 2U] = digits[input[i] >> 4U];
            result[i * 2U + 1U] = digits[input[i] & 0x0FU];
        }
        return result;
    }

    std::vector<std::uint8_t> hex_decode(const std::string_view input)
    {
        if ((input.size() % 2U) != 0U)
            raise_error(ErrorCode::InvalidLength, "Hexadecimal input must have an even number of characters.");

        const auto digit = [](const char c) -> std::uint8_t
        {
            if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<std::uint8_t>(c - 'A' + 10);
            raise_error(ErrorCode::InvalidEncoding, "Invalid character in hexadecimal input.");
        };

        std::vector<std::uint8_t> result;
        result.reserve(input.size() / 2U);
        for (std::size_t i = 0; i < input.size(); i += 2U)
            result.push_back(static_cast<std::uint8_t>((digit(input[i]) << 4U) | digit(input[i + 1U])));
        return result;
    }

    bool is_valid_utf8(const std::span<const std::uint8_t> input) noexcept
    {
        std::size_t i = 0;
        while (i < input.size())
        {
            const std::uint8_t a = input[i];
            if (a <= 0x7FU) { ++i; continue; }

            if (a >= 0xC2U && a <= 0xDFU)
            {
                if (i + 1U >= input.size() || input[i + 1U] < 0x80U || input[i + 1U] > 0xBFU) return false;
                i += 2U; continue;
            }

            if (a >= 0xE0U && a <= 0xEFU)
            {
                if (i + 2U >= input.size()) return false;
                const auto b = input[i + 1U];
                const auto c = input[i + 2U];
                if (c < 0x80U || c > 0xBFU) return false;
                if (a == 0xE0U) { if (b < 0xA0U || b > 0xBFU) return false; }
                else if (a == 0xEDU) { if (b < 0x80U || b > 0x9FU) return false; }
                else if (b < 0x80U || b > 0xBFU) return false;
                i += 3U; continue;
            }

            if (a >= 0xF0U && a <= 0xF4U)
            {
                if (i + 3U >= input.size()) return false;
                const auto b = input[i + 1U];
                const auto c = input[i + 2U];
                const auto d = input[i + 3U];
                if (c < 0x80U || c > 0xBFU || d < 0x80U || d > 0xBFU) return false;
                if (a == 0xF0U) { if (b < 0x90U || b > 0xBFU) return false; }
                else if (a == 0xF4U) { if (b < 0x80U || b > 0x8FU) return false; }
                else if (b < 0x80U || b > 0xBFU) return false;
                i += 4U; continue;
            }
            return false;
        }
        return true;
    }

    std::vector<std::uint8_t> utf8_to_bytes(const std::string_view input)
    {
        const auto* pointer = reinterpret_cast<const std::uint8_t*>(input.data());
        const std::span<const std::uint8_t> bytes(pointer, input.size());
        if (!is_valid_utf8(bytes)) raise_error(ErrorCode::InvalidEncoding, "Input string is not valid UTF-8.");
        return {bytes.begin(), bytes.end()};
    }

    std::string bytes_to_utf8(const std::span<const std::uint8_t> input)
    {
        if (!is_valid_utf8(input)) raise_error(ErrorCode::InvalidEncoding, "Byte sequence is not valid UTF-8.");
        if (input.empty()) return {};
        return {reinterpret_cast<const char*>(input.data()), input.size()};
    }
}
