#pragma once

#include "BigInteger/BigInteger.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace crypto::standard
{
    struct RsaPublicKey
    {
        BigInt modulus;
        BigInt public_exponent;
    };

    struct RsaPrivateKey
    {
        BigInt modulus;
        BigInt private_exponent;
    };

    struct RsaKeyPair
    {
        RsaPublicKey public_key;
        RsaPrivateKey private_key;
    };

    class RSA final
    {
    public:
        [[nodiscard]] static RsaKeyPair generate_key_pair(
            std::size_t modulus_bits = 4096,
            std::uint32_t public_exponent = 65537U);

        [[nodiscard]] static std::vector<std::uint8_t> encrypt_oaep_sha256(
            const RsaPublicKey& key,
            std::span<const std::uint8_t> plaintext,
            std::span<const std::uint8_t> label = {});

        [[nodiscard]] static std::vector<std::uint8_t> decrypt_oaep_sha256(
            const RsaPrivateKey& key,
            std::span<const std::uint8_t> ciphertext,
            std::span<const std::uint8_t> label = {});

        [[nodiscard]] static std::vector<std::uint8_t> sign_pss_sha256(
            const RsaPrivateKey& key,
            std::span<const std::uint8_t> message,
            std::size_t salt_length = 32U);

        [[nodiscard]] static bool verify_pss_sha256(
            const RsaPublicKey& key,
            std::span<const std::uint8_t> message,
            std::span<const std::uint8_t> signature,
            std::size_t salt_length = 32U);
    };
}
