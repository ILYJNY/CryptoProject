#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace crypto::standard
{
    using Aes128Key = std::array<std::uint8_t, 16>;
    using GcmNonce = std::array<std::uint8_t, 12>;
    using GcmTag = std::array<std::uint8_t, 16>;

    struct AesGcmCiphertext
    {
        GcmNonce nonce{};
        std::vector<std::uint8_t> ciphertext;
        GcmTag tag{};
    };

    class AES128GCM final
    {
    public:
        [[nodiscard]] static AesGcmCiphertext encrypt(
            const Aes128Key& key,
            std::span<const std::uint8_t> plaintext,
            std::span<const std::uint8_t> associated_data = {});

        [[nodiscard]] static AesGcmCiphertext encrypt_with_nonce(
            const Aes128Key& key,
            const GcmNonce& nonce,
            std::span<const std::uint8_t> plaintext,
            std::span<const std::uint8_t> associated_data = {});

        [[nodiscard]] static std::vector<std::uint8_t> decrypt(
            const Aes128Key& key,
            const AesGcmCiphertext& input,
            std::span<const std::uint8_t> associated_data = {});
    };
}
