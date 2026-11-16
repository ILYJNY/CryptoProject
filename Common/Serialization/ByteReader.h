#pragma once

#include "Encoding/Encoding.h"
#include "ErrorHandling/CryptoException.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

namespace crypto
{
    class ByteReader final
    {
    public:
        explicit ByteReader(const std::span<const std::uint8_t> input) : input_(input) {}

        [[nodiscard]] std::uint8_t read_u8() { return read_unsigned<std::uint8_t>(); }
        [[nodiscard]] std::uint16_t read_u16() { return read_unsigned<std::uint16_t>(); }
        [[nodiscard]] std::uint32_t read_u32() { return read_unsigned<std::uint32_t>(); }
        [[nodiscard]] std::uint64_t read_u64() { return read_unsigned<std::uint64_t>(); }

        [[nodiscard]] std::span<const std::uint8_t> read_view(const std::size_t count)
        {
            ensure_available(count);
            const auto result = input_.subspan(position_, count);
            position_ += count;
            return result;
        }

        [[nodiscard]] std::vector<std::uint8_t> read_bytes(const std::size_t count)
        {
            const auto view = read_view(count);
            return {view.begin(), view.end()};
        }

        [[nodiscard]] std::vector<std::uint8_t> read_length_prefixed_bytes(
            const std::size_t maximum_size = 64U * 1024U * 1024U)
        {
            const std::uint64_t size = read_u64();
            if (size > static_cast<std::uint64_t>(maximum_size))
                raise_error(ErrorCode::OutOfRange, "Serialized byte sequence exceeds the configured size limit.");
            return read_bytes(static_cast<std::size_t>(size));
        }

        [[nodiscard]] std::string read_string(const std::size_t maximum_size = 16U * 1024U * 1024U)
        {
            return bytes_to_utf8(read_length_prefixed_bytes(maximum_size));
        }

        [[nodiscard]] std::size_t position() const noexcept { return position_; }
        [[nodiscard]] std::size_t remaining() const noexcept { return input_.size() - position_; }
        [[nodiscard]] bool empty() const noexcept { return position_ == input_.size(); }

    private:
        void ensure_available(const std::size_t count) const
        {
            if (count > remaining())
                raise_error(ErrorCode::SerializationError, "Serialized input ended unexpectedly.");
        }

        template <typename T>
        [[nodiscard]] T read_unsigned()
        {
            static_assert(std::is_unsigned_v<T>);
            ensure_available(sizeof(T));
            std::uint64_t accumulator = 0;
            for (std::size_t i = 0; i < sizeof(T); ++i)
            {
                const auto shift = static_cast<unsigned int>(i * 8U);
                accumulator |= static_cast<std::uint64_t>(input_[position_ + i]) << shift;
            }
            position_ += sizeof(T);
            return static_cast<T>(accumulator);
        }

        std::span<const std::uint8_t> input_;
        std::size_t position_ = 0;
    };
}
