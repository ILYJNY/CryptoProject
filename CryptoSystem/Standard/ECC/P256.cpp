#include "P256.h"

#include "ErrorHandling/CryptoException.h"
#include "Random/SecureRandom.h"
#include "SHA/SHA256.h"

#include <algorithm>
#include <array>
#include <cstdint>

namespace crypto::standard
{
    namespace
    {
        struct Point
        {
            BigInt x = 0;
            BigInt y = 0;
            bool infinity = true;
        };

        const BigInt& prime()
        {
            static const BigInt value = from_hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
            return value;
        }

        const BigInt& order()
        {
            static const BigInt value = from_hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
            return value;
        }

        const BigInt& curve_a()
        {
            static const BigInt value = prime() - 3;
            return value;
        }

        const BigInt& curve_b()
        {
            static const BigInt value = from_hex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
            return value;
        }

        const Point& generator()
        {
            static const Point value{
                from_hex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
                from_hex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
                false
            };
            return value;
        }

        [[nodiscard]] BigInt inverse(const BigInt& value, const BigInt& modulus)
        {
            if (normalize_mod(value, modulus) == 0)
            {
                raise_error(ErrorCode::ArithmeticError, "Cannot invert zero in a finite field.");
            }
            return mod_pow(normalize_mod(value, modulus), modulus - 2, modulus);
        }

        [[nodiscard]] Point add_points(const Point& p, const Point& q)
        {
            if (p.infinity) return q;
            if (q.infinity) return p;

            const BigInt& mod = prime();
            if (p.x == q.x && normalize_mod(p.y + q.y, mod) == 0)
            {
                return {};
            }

            BigInt slope;
            if (p.x == q.x && p.y == q.y)
            {
                if (p.y == 0)
                {
                    return {};
                }
                slope = normalize_mod(
                    (3 * p.x * p.x + curve_a()) * inverse(2 * p.y, mod), mod);
            }
            else
            {
                slope = normalize_mod(
                    (q.y - p.y) * inverse(q.x - p.x, mod), mod);
            }

            const BigInt x3 = normalize_mod(slope * slope - p.x - q.x, mod);
            const BigInt y3 = normalize_mod(slope * (p.x - x3) - p.y, mod);
            return {x3, y3, false};
        }

        [[nodiscard]] Point scalar_multiply(BigInt scalar, Point point)
        {
            Point result{};
            while (scalar > 0)
            {
                if ((scalar & 1) != 0)
                {
                    result = add_points(result, point);
                }
                scalar >>= 1;
                if (scalar > 0)
                {
                    point = add_points(point, point);
                }
            }
            return result;
        }

        [[nodiscard]] BigInt hash_to_integer(const std::span<const std::uint8_t> message)
        {
            const auto digest = sha256(message);
            BigInt value = 0;
            for (const std::uint8_t byte : digest)
            {
                value <<= 8;
                value += byte;
            }
            return value;
        }

        [[nodiscard]] std::array<std::uint8_t, 32> fixed_bytes(BigInt value)
        {
            std::array<std::uint8_t, 32> result{};
            for (std::size_t i = 0; i < result.size(); ++i)
            {
                result[result.size() - 1U - i] =
                    static_cast<std::uint8_t>((value & 0xFF).convert_to<unsigned int>());
                value >>= 8;
            }
            return result;
        }

        [[nodiscard]] Point to_point(const P256PublicKey& key)
        {
            return {key.x, key.y, false};
        }
    }

    bool P256::is_valid_public_key(const P256PublicKey& public_key)
    {
        if (public_key.x < 0 || public_key.x >= prime() ||
            public_key.y < 0 || public_key.y >= prime())
        {
            return false;
        }
        const BigInt left = normalize_mod(public_key.y * public_key.y, prime());
        const BigInt right = normalize_mod(
            public_key.x * public_key.x * public_key.x +
            curve_a() * public_key.x + curve_b(), prime());
        return left == right;
    }

    P256PublicKey P256::derive_public_key(const P256PrivateKey& private_key)
    {
        if (private_key.scalar <= 0 || private_key.scalar >= order())
        {
            raise_error(ErrorCode::InvalidArgument, "P-256 private scalar is out of range.");
        }
        const Point point = scalar_multiply(private_key.scalar, generator());
        if (point.infinity)
        {
            raise_error(ErrorCode::ArithmeticError, "P-256 public key derivation failed.");
        }
        return {point.x, point.y};
    }

    P256KeyPair P256::generate_key_pair()
    {
        const BigInt scalar = SecureRandom::below(order() - 1) + 1;
        P256PrivateKey privateKey{scalar};
        return {derive_public_key(privateKey), privateKey};
    }

    std::array<std::uint8_t, 32> P256::ecdh(
        const P256PrivateKey& private_key,
        const P256PublicKey& peer_public_key)
    {
        if (private_key.scalar <= 0 || private_key.scalar >= order() ||
            !is_valid_public_key(peer_public_key))
        {
            raise_error(ErrorCode::InvalidArgument, "Invalid P-256 key supplied to ECDH.");
        }
        const Point shared = scalar_multiply(private_key.scalar, to_point(peer_public_key));
        if (shared.infinity)
        {
            raise_error(ErrorCode::ArithmeticError, "P-256 ECDH produced the point at infinity.");
        }
        return fixed_bytes(shared.x);
    }

    EcdsaSignature P256::sign_sha256(
        const P256PrivateKey& private_key,
        const std::span<const std::uint8_t> message)
    {
        if (private_key.scalar <= 0 || private_key.scalar >= order())
        {
            raise_error(ErrorCode::InvalidArgument, "P-256 private scalar is out of range.");
        }

        const BigInt z = hash_to_integer(message);
        while (true)
        {
            const BigInt k = SecureRandom::below(order() - 1) + 1;
            const Point point = scalar_multiply(k, generator());
            const BigInt r = normalize_mod(point.x, order());
            if (r == 0)
            {
                continue;
            }
            const BigInt s = normalize_mod(inverse(k, order()) * (z + r * private_key.scalar), order());
            if (s != 0)
            {
                return {r, s};
            }
        }
    }

    bool P256::verify_sha256(
        const P256PublicKey& public_key,
        const std::span<const std::uint8_t> message,
        const EcdsaSignature& signature)
    {
        if (!is_valid_public_key(public_key) ||
            signature.r <= 0 || signature.r >= order() ||
            signature.s <= 0 || signature.s >= order())
        {
            return false;
        }

        const BigInt z = hash_to_integer(message);
        const BigInt w = inverse(signature.s, order());
        const BigInt u1 = normalize_mod(z * w, order());
        const BigInt u2 = normalize_mod(signature.r * w, order());
        const Point p1 = scalar_multiply(u1, generator());
        const Point p2 = scalar_multiply(u2, to_point(public_key));
        const Point sum = add_points(p1, p2);
        if (sum.infinity)
        {
            return false;
        }
        return normalize_mod(sum.x, order()) == signature.r;
    }
}
