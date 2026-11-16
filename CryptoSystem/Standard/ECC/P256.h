#pragma once

#include "BigInteger/BigInteger.h"

#include <array>
#include <cstdint>
#include <span>

namespace crypto::standard
{
    struct P256PublicKey
    {
        BigInt x;
        BigInt y;
    };

    struct P256PrivateKey
    {
        BigInt scalar;
    };

    struct P256KeyPair
    {
        P256PublicKey public_key;
        P256PrivateKey private_key;
    };

    struct EcdsaSignature
    {
        BigInt r;
        BigInt s;
    };

    class P256 final
    {
    public:
        [[nodiscard]] static P256KeyPair generate_key_pair();
        [[nodiscard]] static P256PublicKey derive_public_key(const P256PrivateKey& private_key);
        [[nodiscard]] static std::array<std::uint8_t, 32> ecdh(
            const P256PrivateKey& private_key,
            const P256PublicKey& peer_public_key);
        [[nodiscard]] static EcdsaSignature sign_sha256(
            const P256PrivateKey& private_key,
            std::span<const std::uint8_t> message);
        [[nodiscard]] static bool verify_sha256(
            const P256PublicKey& public_key,
            std::span<const std::uint8_t> message,
            const EcdsaSignature& signature);
        [[nodiscard]] static bool is_valid_public_key(const P256PublicKey& public_key);
    };
}
