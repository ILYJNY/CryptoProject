#include "ToyRSA.h"

#include "BigInteger/BigInteger.h"
#include "ErrorHandling/CryptoException.h"
#include "Random/SecureRandom.h"

#include <cstdint>
#include <limits>

namespace crypto::educational
{
    namespace
    {
        [[nodiscard]] std::uint64_t modular_power(
            std::uint64_t base,
            std::uint64_t exponent,
            const std::uint64_t modulus)
        {
            std::uint64_t result = 1U;
            base %= modulus;
            while (exponent > 0U)
            {
                if ((exponent & 1U) != 0U)
                {
                    result = (result * base) % modulus;
                }
                exponent >>= 1U;
                base = (base * base) % modulus;
            }
            return result;
        }

        [[nodiscard]] std::uint64_t modular_inverse(
            const std::uint64_t value,
            const std::uint64_t modulus)
        {
            std::int64_t t = 0;
            std::int64_t newT = 1;
            std::int64_t r = static_cast<std::int64_t>(modulus);
            std::int64_t newR = static_cast<std::int64_t>(value);

            while (newR != 0)
            {
                const std::int64_t quotient = r / newR;
                const std::int64_t nextT = t - quotient * newT;
                t = newT;
                newT = nextT;
                const std::int64_t nextR = r - quotient * newR;
                r = newR;
                newR = nextR;
            }
            if (r != 1)
            {
                raise_error(ErrorCode::ArithmeticError, "Toy RSA modular inverse does not exist.");
            }
            if (t < 0)
            {
                t += static_cast<std::int64_t>(modulus);
            }
            return static_cast<std::uint64_t>(t);
        }

        [[nodiscard]] bool is_prime(const std::uint64_t value)
        {
            if (value < 2U) return false;
            for (std::uint64_t divisor = 2U; divisor * divisor <= value; ++divisor)
            {
                if (value % divisor == 0U) return false;
            }
            return true;
        }

        [[nodiscard]] std::uint64_t random_prime(const std::size_t bits)
        {
            const std::uint64_t lower = std::uint64_t{1} << (bits - 1U);
            const std::uint64_t upper = (std::uint64_t{1} << bits) - 1U;
            while (true)
            {
                std::uint64_t candidate = SecureRandom::uniform_u64(lower, upper) | 1U;
                candidate |= lower;
                if (candidate > upper) candidate -= 2U;
                if (is_prime(candidate)) return candidate;
            }
        }
    }

    ToyRsaSample generate_toy_rsa_sample(const std::size_t modulus_bits)
    {
        if (modulus_bits < 16U || modulus_bits > 32U)
        {
            raise_error(ErrorCode::InvalidArgument, "Toy RSA modulus size must be between 16 and 32 bits.");
        }
        const std::size_t pBits = modulus_bits / 2U;
        const std::size_t qBits = modulus_bits - pBits;
        std::uint64_t p = 0U;
        std::uint64_t q = 0U;
        std::uint64_t n = 0U;
        do
        {
            p = random_prime(pBits);
            q = random_prime(qBits);
            n = p * q;
        }
        while (p == q || bit_length(BigInt(n)) != modulus_bits);

        const std::uint64_t phi = (p - 1U) * (q - 1U);
        std::uint64_t e = 65537U;
        if (e >= phi || gcd(BigInt(e), BigInt(phi)) != 1)
        {
            e = 3U;
            while (e < phi && gcd(BigInt(e), BigInt(phi)) != 1) e += 2U;
        }
        if (e >= phi)
        {
            raise_error(ErrorCode::ArithmeticError, "Unable to choose a valid toy RSA public exponent.");
        }
        const std::uint64_t d = modular_inverse(e, phi);
        constexpr std::uint64_t plaintext = 4242U;
        if (plaintext >= n)
        {
            raise_error(ErrorCode::InternalError, "Toy RSA generated an undersized modulus.");
        }

        const std::uint64_t ciphertext = modular_power(plaintext, e, n);
        return {{n, e, ciphertext}, {p, q, d, plaintext}, modulus_bits};
    }

    ToyRsaAnalysis analyze_toy_rsa(const ToyRsaPublicInstance& instance)
    {
        ToyRsaAnalysis result;
        if (instance.modulus < 4U || instance.public_exponent < 3U ||
            instance.ciphertext >= instance.modulus)
        {
            result.status = "INVALID_INPUT";
            return result;
        }

        std::uint64_t p = 0;
        for (std::uint64_t divisor = 2U;
             divisor <= instance.modulus / divisor;
             ++divisor)
        {
            ++result.trial_divisions;
            if (instance.modulus % divisor == 0U)
            {
                p = divisor;
                break;
            }
        }

        if (p == 0U)
        {
            result.status = "FACTOR_NOT_FOUND";
            return result;
        }

        const std::uint64_t q = instance.modulus / p;
        if (!is_prime(p) || !is_prime(q))
        {
            result.status = "INVALID_TOY_RSA_MODULUS";
            return result;
        }

        const std::uint64_t phi = (p - 1U) * (q - 1U);
        if (gcd(BigInt(instance.public_exponent), BigInt(phi)) != 1)
        {
            result.status = "INVALID_EXPONENT";
            return result;
        }

        const std::uint64_t d = modular_inverse(instance.public_exponent, phi);
        const std::uint64_t plaintext = modular_power(instance.ciphertext, d, instance.modulus);

        result.success = true;
        result.recovered_p = p;
        result.recovered_q = q;
        result.recovered_private_exponent = d;
        result.recovered_plaintext = plaintext;
        result.status = "BOTH_RECOVERED";
        return result;
    }
}
