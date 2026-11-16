#include "../CryptoSetAnalysis.h"
#include "../Detail/QuantumAttackAnalysis.h"

#include "AES/AES128GCM.h"
#include "ECC/P256.h"
#include "Encoding/Encoding.h"
#include "Random/SecureRandom.h"
#include "SHA/SHA256.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace crypto::set_analysis
{
    namespace
    {
        using Bytes = std::vector<std::uint8_t>;
        using Clock = std::chrono::steady_clock;

        template<class Function>
        double measure_ms(Function&& function)
        {
            const auto start = Clock::now();
            function();
            return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
        }

        std::array<std::uint8_t, 32> hmac_sha256(
            std::span<const std::uint8_t> key, std::span<const std::uint8_t> message)
        {
            constexpr std::size_t block_size = 64U;
            std::array<std::uint8_t, block_size> normalized{};
            if (key.size() > block_size)
            {
                const auto digest = standard::sha256(key);
                std::copy(digest.begin(), digest.end(), normalized.begin());
            }
            else
            {
                std::copy(key.begin(), key.end(), normalized.begin());
            }
            Bytes inner(block_size + message.size());
            Bytes outer(block_size + 32U);
            for (std::size_t i = 0; i < block_size; ++i)
            {
                inner[i] = static_cast<std::uint8_t>(normalized[i] ^ 0x36U);
                outer[i] = static_cast<std::uint8_t>(normalized[i] ^ 0x5CU);
            }
            std::copy(message.begin(), message.end(), inner.begin() + static_cast<std::ptrdiff_t>(block_size));
            const auto inner_digest = standard::sha256(inner);
            std::copy(inner_digest.begin(), inner_digest.end(), outer.begin() + static_cast<std::ptrdiff_t>(block_size));
            const auto result = standard::sha256(outer);
            return result;
        }

        standard::Aes128Key derive_aes_key(
            std::span<const std::uint8_t> shared_secret,
            std::span<const std::uint8_t> salt,
            std::string_view info)
        {
            const auto prk = hmac_sha256(salt, shared_secret);
            Bytes info_bytes(info.begin(), info.end());
            info_bytes.push_back(0x01U);
            const auto okm = hmac_sha256(prk, info_bytes);
            standard::Aes128Key key{};
            std::copy_n(okm.begin(), key.size(), key.begin());
            return key;
        }

        Bytes make_signature_payload(
            std::string_view label,
            const standard::Sha256Digest& digest,
            const standard::AesGcmCiphertext& encrypted)
        {
            Bytes payload(label.begin(), label.end());
            payload.insert(payload.end(), digest.begin(), digest.end());
            payload.insert(payload.end(), encrypted.nonce.begin(), encrypted.nonce.end());
            payload.insert(payload.end(), encrypted.ciphertext.begin(), encrypted.ciphertext.end());
            payload.insert(payload.end(), encrypted.tag.begin(), encrypted.tag.end());
            return payload;
        }
    }

    SetRunResult run_aes_sha_ecdsa(const std::string_view plaintext, const bool run_quantum_demo)
    {
        SetRunResult result;
        result.id = SetId::AesShaEcdsa;
        result.name = "AES-SHA-ECDSA";
        result.key_establishment = "P-256 ECDH";
        result.authentication = "P-256 ECDSA with SHA-256";
        result.public_key_parameter_bits = 256U;
        const auto total_start = Clock::now();

        try
        {
            standard::P256KeyPair recipient_key;
            standard::P256KeyPair sender_signing_key;
            result.timings.key_generation_ms = measure_ms([&]
            {
                recipient_key = standard::P256::generate_key_pair();
                sender_signing_key = standard::P256::generate_key_pair();
            });

            standard::P256KeyPair ephemeral_key;
            std::array<std::uint8_t, 32> sender_shared{};
            std::array<std::uint8_t, 32> recipient_shared{};
            result.timings.key_establishment_ms = measure_ms([&]
            {
                ephemeral_key = standard::P256::generate_key_pair();
                sender_shared = standard::P256::ecdh(ephemeral_key.private_key, recipient_key.public_key);
                recipient_shared = standard::P256::ecdh(recipient_key.private_key, ephemeral_key.public_key);
            });
            result.shared_secret_match = sender_shared == recipient_shared;
            if (!result.shared_secret_match) throw std::runtime_error("P-256 ECDH shared secrets did not match.");

            const Bytes message = utf8_to_bytes(plaintext);
            standard::Sha256Digest message_digest{};
            result.timings.sha256_ms = measure_ms([&] { message_digest = standard::sha256(message); });
            result.plaintext_sha256 = hex_encode(message_digest);

            const Bytes salt = SecureRandom::bytes(32U);
            standard::Aes128Key sender_aes_key{};
            standard::Aes128Key recipient_aes_key{};
            result.timings.hkdf_ms = measure_ms([&]
            {
                sender_aes_key = derive_aes_key(sender_shared, salt, "CryptoProject/AES-SHA-ECDSA/v1");
                recipient_aes_key = derive_aes_key(recipient_shared, salt, "CryptoProject/AES-SHA-ECDSA/v1");
            });

            constexpr std::string_view aad_text = "CryptoProject/AES-SHA-ECDSA/v1";
            const Bytes aad(aad_text.begin(), aad_text.end());
            standard::AesGcmCiphertext encrypted;
            result.timings.aes_encrypt_ms = measure_ms([&]
            {
                encrypted = standard::AES128GCM::encrypt(sender_aes_key, message, aad);
            });
            result.ciphertext_bytes = encrypted.ciphertext.size();

            const Bytes signed_payload = make_signature_payload(aad_text, message_digest, encrypted);
            standard::EcdsaSignature signature;
            result.timings.signature_ms = measure_ms([&]
            {
                signature = standard::P256::sign_sha256(sender_signing_key.private_key, signed_payload);
            });
            result.signature_present = true;
            result.timings.signature_verify_ms = measure_ms([&]
            {
                result.signature_verified = standard::P256::verify_sha256(
                    sender_signing_key.public_key, signed_payload, signature);
            });

            Bytes recovered;
            result.timings.aes_decrypt_ms = measure_ms([&]
            {
                recovered = standard::AES128GCM::decrypt(recipient_aes_key, encrypted, aad);
            });
            result.passed = result.shared_secret_match && result.signature_verified && recovered == message;
            result.detail = result.passed
                ? "P-256 ECDH shared-secret agreement, AES-128-GCM authentication/decryption, SHA-256 and ECDSA signature verification succeeded."
                : "One or more ECDH, signature, or AES-GCM checks failed.";

            volatile std::uint8_t* p = sender_shared.data();
            for (std::size_t i = 0; i < sender_shared.size(); ++i) p[i] = 0U;
            p = recipient_shared.data();
            for (std::size_t i = 0; i < recipient_shared.size(); ++i) p[i] = 0U;
            p = sender_aes_key.data();
            for (std::size_t i = 0; i < sender_aes_key.size(); ++i) p[i] = 0U;
            p = recipient_aes_key.data();
            for (std::size_t i = 0; i < recipient_aes_key.size(); ++i) p[i] = 0U;
        }
        catch (const std::exception& exception)
        {
            result.passed = false;
            result.detail = std::string("AES-SHA-ECDSA failed: ") + exception.what();
        }

        result.timings.total_ms = std::chrono::duration<double, std::milli>(Clock::now() - total_start).count();
        detail::attach_quantum_analysis(result, run_quantum_demo);
        return result;
    }
}
