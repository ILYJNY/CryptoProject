#pragma once

#include "Encoding/Encoding.h"
#include "ErrorHandling/CryptoException.h"

#include <cstdint>
#include <limits>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace crypto
{
    class ByteWriter final
    {
    public:
        void write_u8(const std::uint8_t value) { write_unsigned(value); }
        void write_u16(const std::uint16_t value) { write_unsigned(value); }
        void write_u32(const std::uint32_t value) { write_unsigned(value); }
        void write_u64(const std::uint64_t value) { write_unsigned(value); }

        void write_bytes(const std::span<const std::uint8_t> bytes)
        {
            data_.insert(data_.end(), bytes.begin(), bytes.end());
        }

        void write_length_prefixed_bytes(const std::span<const std::uint8_t> bytes)
        {
            if (bytes.size() > std::numeric_limits<std::uint64_t>::max())
                raise_error(ErrorCode::OutOfRange, "Byte sequence is too large to serialize.");
            write_u64(static_cast<std::uint64_t>(bytes.size()));
            write_bytes(bytes);
        }

        void write_string(const std::string_view text)
        {
            const auto bytes = utf8_to_bytes(text);
            write_length_prefixed_bytes(bytes);
        }

        [[nodiscard]] const std::vector<std::uint8_t>& data() const noexcept { return data_; }
        [[nodiscard]] std::vector<std::uint8_t> release() && { return std::move(data_); }
        [[nodiscard]] std::size_t size() const noexcept { return data_.size(); }

    private:
        template <typename T>
        void write_unsigned(const T value)
        {
            static_assert(std::is_unsigned_v<T>);
            for (std::size_t i = 0; i < sizeof(T); ++i)
            {
                const auto shift = static_cast<unsigned int>(i * 8U);
                data_.push_back(static_cast<std::uint8_t>((value >> shift) & static_cast<T>(0xFFU)));
            }
        }

        std::vector<std::uint8_t> data_;
    };
}
