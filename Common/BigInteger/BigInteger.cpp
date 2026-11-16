#include "BigInteger/BigInteger.h"
#include "ErrorHandling/CryptoException.h"

#include <algorithm>

namespace crypto
{
    std::size_t bit_length(const BigInt& value)
    {
        BigInt magnitude = value < 0 ? -value : value;
        if (magnitude == 0) return 0;
        return static_cast<std::size_t>(boost::multiprecision::msb(magnitude)) + 1U;
    }

    BigInt gcd(BigInt a, BigInt b)
    {
        if (a < 0) a = -a;
        if (b < 0) b = -b;
        while (b != 0)
        {
            BigInt remainder = a % b;
            a = std::move(b);
            b = std::move(remainder);
        }
        return a;
    }

    BigInt normalize_mod(const BigInt& value, const BigInt& modulus)
    {
        if (modulus <= 0) raise_error(ErrorCode::InvalidArgument, "Modulus must be positive.");
        BigInt result = value % modulus;
        if (result < 0) result += modulus;
        return result;
    }

    BigInt mod_pow(BigInt base, BigInt exponent, const BigInt& modulus)
    {
        if (modulus <= 0) raise_error(ErrorCode::InvalidArgument, "Modulus must be positive.");
        if (exponent < 0) raise_error(ErrorCode::InvalidArgument, "Exponent must not be negative.");
        base = normalize_mod(base, modulus);
        BigInt result = BigInt(1) % modulus;
        while (exponent > 0)
        {
            if ((exponent & 1) != 0) result = (result * base) % modulus;
            exponent >>= 1;
            if (exponent > 0) base = (base * base) % modulus;
        }
        return result;
    }

    std::string to_decimal(const BigInt& value) { return value.convert_to<std::string>(); }

    BigInt from_decimal(const std::string_view text)
    {
        if (text.empty()) raise_error(ErrorCode::InvalidFormat, "Decimal integer must not be empty.");
        std::size_t index = 0;
        bool negative = false;
        if (text.front() == '-' || text.front() == '+')
        {
            negative = text.front() == '-';
            index = 1;
        }
        if (index == text.size()) raise_error(ErrorCode::InvalidFormat, "Decimal integer has no digits.");
        BigInt value = 0;
        for (; index < text.size(); ++index)
        {
            const char c = text[index];
            if (c < '0' || c > '9') raise_error(ErrorCode::InvalidFormat, "Invalid character in decimal integer.");
            value *= 10;
            value += static_cast<unsigned int>(c - '0');
        }
        return negative ? -value : value;
    }

    std::string to_hex(const BigInt& value, const bool uppercase)
    {
        if (value == 0) return "0";
        constexpr char lower[] = "0123456789abcdef";
        constexpr char upper[] = "0123456789ABCDEF";
        const char* digits = uppercase ? upper : lower;
        BigInt magnitude = value;
        const bool negative = magnitude < 0;
        if (negative) magnitude = -magnitude;
        std::string result;
        while (magnitude > 0)
        {
            const auto digit = (magnitude & 0x0F).convert_to<unsigned int>();
            result.push_back(digits[digit]);
            magnitude >>= 4;
        }
        if (negative) result.push_back('-');
        std::reverse(result.begin(), result.end());
        return result;
    }

    BigInt from_hex(const std::string_view text)
    {
        if (text.empty()) raise_error(ErrorCode::InvalidFormat, "Hexadecimal integer must not be empty.");
        std::size_t index = 0;
        bool negative = false;
        if (text.front() == '-' || text.front() == '+')
        {
            negative = text.front() == '-';
            index = 1;
        }
        if (index + 2 <= text.size() && text[index] == '0' &&
            (text[index + 1] == 'x' || text[index + 1] == 'X')) index += 2;
        if (index == text.size()) raise_error(ErrorCode::InvalidFormat, "Hexadecimal integer has no digits.");

        BigInt value = 0;
        for (; index < text.size(); ++index)
        {
            const char c = text[index];
            unsigned int digit = 0;
            if (c >= '0' && c <= '9') digit = static_cast<unsigned int>(c - '0');
            else if (c >= 'a' && c <= 'f') digit = static_cast<unsigned int>(c - 'a') + 10U;
            else if (c >= 'A' && c <= 'F') digit = static_cast<unsigned int>(c - 'A') + 10U;
            else raise_error(ErrorCode::InvalidFormat, "Invalid character in hexadecimal integer.");
            value <<= 4;
            value += digit;
        }
        return negative ? -value : value;
    }
}
