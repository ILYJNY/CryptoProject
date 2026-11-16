#pragma once

#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace crypto
{
    enum class ErrorCode
    {
        InvalidArgument, InvalidEncoding, InvalidFormat, InvalidLength,
        OutOfRange, RandomGenerationFailed, UnsupportedPlatform,
        IoError, SerializationError, ArithmeticError, InternalError
    };

    class CryptoException final : public std::runtime_error
    {
    public:
        CryptoException(const ErrorCode code, std::string message)
            : std::runtime_error(std::move(message)), code_(code) {}

        [[nodiscard]] ErrorCode code() const noexcept { return code_; }

    private:
        ErrorCode code_;
    };

    [[noreturn]] inline void raise_error(const ErrorCode code, const std::string_view message)
    {
        throw CryptoException(code, std::string(message));
    }
}
