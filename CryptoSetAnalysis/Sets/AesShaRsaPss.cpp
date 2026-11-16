#include "../CryptoSetAnalysis.h"
#include "../Detail/QuantumAttackAnalysis.h"

#include "AES/AES128GCM.h"
#include "Encoding/Encoding.h"
#include "Random/SecureRandom.h"
#include "RSA/RSA.h"
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
            else std::copy(key.begin(), key.end(), normalized.begin());

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
            return standard::sha256(outer);
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

        Bytes make_signature_payload(std::string_view label,
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

    SetRunResult run_aes_sha_rsa_pss(const std::string_view plaintext,
                                     const std::size_t rsa_modulus_bits,
                                     const bool run_quantum_demo)
    {
        SetRunResult result;
        result.id = SetId::AesShaRsaPss;
        result.name = "AES-SHA-RSAPSS";
        result.key_establishment = "RSA-OAEP-SHA-256 key transport";
        result.authentication = "RSA-PSS-SHA-256 signature";
        result.public_key_parameter_bits = rsa_modulus_bits;
        const auto total_start = Clock::now();

        try
        {
            standard::RsaKeyPair rsa_key;
            result.timings.key_generation_ms = measure_ms([&]
            {
                rsa_key = standard::RSA::generate_key_pair(rsa_modulus_bits);
            });

            Bytes sender_secret = SecureRandom::bytes(32U);
            Bytes recipient_secret;
            Bytes wrapped_secret;
            result.timings.key_establishment_ms = measure_ms([&]
            {
                wrapped_secret = standard::RSA::encrypt_oaep_sha256(rsa_key.public_key, sender_secret);
                recipient_secret = standard::RSA::decrypt_oaep_sha256(rsa_key.private_key, wrapped_secret);
            });
            result.shared_secret_match = sender_secret == recipient_secret;
            if (!result.shared_secret_match) throw std::runtime_error("RSA-OAEP key transport did not recover the original secret.");

            const Bytes message = utf8_to_bytes(plaintext);
            standard::Sha256Digest message_digest{};
            result.timings.sha256_ms = measure_ms([&] { message_digest = standard::sha256(message); });
            result.plaintext_sha256 = hex_encode(message_digest);

            const Bytes salt = SecureRandom::bytes(32U);
            standard::Aes128Key sender_aes_key{};
            standard::Aes128Key recipient_aes_key{};
            result.timings.hkdf_ms = measure_ms([&]
            {
                sender_aes_key = derive_aes_key(sender_secret, salt, "CryptoProject/AES-SHA-RSAPSS/v1");
                recipient_aes_key = derive_aes_key(recipient_secret, salt, "CryptoProject/AES-SHA-RSAPSS/v1");
            });

            constexpr std::string_view aad_text = "CryptoProject/AES-SHA-RSAPSS/v1";
            const Bytes aad(aad_text.begin(), aad_text.end());
            standard::AesGcmCiphertext encrypted;
            result.timings.aes_encrypt_ms = measure_ms([&]
            {
                encrypted = standard::AES128GCM::encrypt(sender_aes_key, message, aad);
            });
            result.ciphertext_bytes = encrypted.ciphertext.size();

            const Bytes signed_payload = make_signature_payload(aad_text, message_digest, encrypted);
            Bytes signature;
            result.timings.signature_ms = measure_ms([&]
            {
                signature = standard::RSA::sign_pss_sha256(rsa_key.private_key, signed_payload);
            });
            result.signature_present = true;
            result.timings.signature_verify_ms = measure_ms([&]
            {
                result.signature_verified = standard::RSA::verify_pss_sha256(
                    rsa_key.public_key, signed_payload, signature);
            });

            Bytes recovered;
            result.timings.aes_decrypt_ms = measure_ms([&]
            {
                recovered = standard::AES128GCM::decrypt(recipient_aes_key, encrypted, aad);
            });
            result.passed = result.shared_secret_match && result.signature_verified && recovered == message;
            result.detail = result.passed
                ? "RSA-OAEP key transport, SHA-256, AES-128-GCM authentication/decryption and RSA-PSS signature verification succeeded."
                : "One or more RSA-OAEP, signature, or AES-GCM checks failed.";

            volatile std::uint8_t* p = sender_secret.data();
            for (std::size_t i = 0; i < sender_secret.size(); ++i) p[i] = 0U;
            p = recipient_secret.data();
            for (std::size_t i = 0; i < recipient_secret.size(); ++i) p[i] = 0U;
            p = sender_aes_key.data();
            for (std::size_t i = 0; i < sender_aes_key.size(); ++i) p[i] = 0U;
            p = recipient_aes_key.data();
            for (std::size_t i = 0; i < recipient_aes_key.size(); ++i) p[i] = 0U;
        }
        catch (const std::exception& exception)
        {
            result.passed = false;
            result.detail = std::string("AES-SHA-RSAPSS failed: ") + exception.what();
        }

        result.timings.total_ms = std::chrono::duration<double, std::milli>(Clock::now() - total_start).count();
        detail::attach_quantum_analysis(result, run_quantum_demo);
        return result;
    }
}
