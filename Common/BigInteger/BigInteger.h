#pragma once

#include <boost/multiprecision/cpp_int.hpp>
#include <cstddef>
#include <string>
#include <string_view>

namespace crypto
{
    using BigInt = boost::multiprecision::cpp_int;

    [[nodiscard]] std::size_t bit_length(const BigInt& value);
    [[nodiscard]] BigInt gcd(BigInt a, BigInt b);
    [[nodiscard]] BigInt normalize_mod(const BigInt& value, const BigInt& modulus);
    [[nodiscard]] BigInt mod_pow(BigInt base, BigInt exponent, const BigInt& modulus);
    [[nodiscard]] std::string to_decimal(const BigInt& value);
    [[nodiscard]] BigInt from_decimal(std::string_view text);
    [[nodiscard]] std::string to_hex(const BigInt& value, bool uppercase = false);
    [[nodiscard]] BigInt from_hex(std::string_view text);
}
