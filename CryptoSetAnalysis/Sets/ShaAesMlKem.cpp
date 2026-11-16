#include "../CryptoSetAnalysis.h"
#include "../Detail/QuantumAttackAnalysis.h"

#include "AES/AES128GCM.h"
#include "Encoding/Encoding.h"
#include "ModuleLWE/MLKEM768.h"
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
    }

    SetRunResult run_sha_aes_mlkem(const std::string_view plaintext, const bool run_quantum_demo)
    {
        SetRunResult result;
        result.id = SetId::ShaAesMlKem;
        result.name = "SHA-AES-MLKEM";
        result.key_establishment = "ML-KEM-768 encapsulation/decapsulation";
        result.authentication = "AES-128-GCM authentication tag (no sender digital signature)";
        result.public_key_parameter_bits = 768U;
        const auto total_start = Clock::now();

        try
        {
            const auto key_generation_start = Clock::now();
            standard::MlKem768KeyPair key_pair = standard::mlkem768_generate_keypair();
            result.timings.key_generation_ms = std::chrono::duration<double, std::milli>(
                Clock::now() - key_generation_start).count();

            const auto key_establishment_start = Clock::now();
            standard::MlKem768Encapsulation encapsulation =
                standard::mlkem768_encapsulate(key_pair.encapsulation_key);
            std::array<std::uint8_t, standard::MLKEM768_SHARED_SECRET_BYTES> recipient_secret =
                standard::mlkem768_decapsulate(key_pair.decapsulation_key, encapsulation.ciphertext);
            result.timings.key_establishment_ms = std::chrono::duration<double, std::milli>(
                Clock::now() - key_establishment_start).count();
            result.shared_secret_match = encapsulation.shared_secret == recipient_secret;
            if (!result.shared_secret_match) throw std::runtime_error("ML-KEM-768 decapsulation did not reproduce the encapsulated shared secret.");

            const Bytes message = utf8_to_bytes(plaintext);
            standard::Sha256Digest message_digest{};
            result.timings.sha256_ms = measure_ms([&] { message_digest = standard::sha256(message); });
            result.plaintext_sha256 = hex_encode(message_digest);

            const Bytes salt = SecureRandom::bytes(32U);
            standard::Aes128Key sender_aes_key{};
            standard::Aes128Key recipient_aes_key{};
            result.timings.hkdf_ms = measure_ms([&]
            {
                sender_aes_key = derive_aes_key(encapsulation.shared_secret, salt, "CryptoProject/SHA-AES-MLKEM/v1");
                recipient_aes_key = derive_aes_key(recipient_secret, salt, "CryptoProject/SHA-AES-MLKEM/v1");
            });

            constexpr std::string_view aad_text = "CryptoProject/SHA-AES-MLKEM/v1";
            Bytes aad(aad_text.begin(), aad_text.end());
            aad.insert(aad.end(), message_digest.begin(), message_digest.end());
            standard::AesGcmCiphertext encrypted;
            result.timings.aes_encrypt_ms = measure_ms([&]
            {
                encrypted = standard::AES128GCM::encrypt(sender_aes_key, message, aad);
            });
            result.ciphertext_bytes = encrypted.ciphertext.size();

            Bytes recovered;
            result.timings.aes_decrypt_ms = measure_ms([&]
            {
                recovered = standard::AES128GCM::decrypt(recipient_aes_key, encrypted, aad);
            });
            result.signature_present = false;
            result.signature_verified = false;
            result.passed = result.shared_secret_match && recovered == message;
            result.detail = result.passed
                ? "ML-KEM-768 shared-secret agreement, SHA-256, AES-128-GCM authentication and decryption succeeded. No digital signature is included in this set."
                : "ML-KEM-768 shared-secret agreement or AES-GCM verification failed.";

            volatile std::uint8_t* p = encapsulation.shared_secret.data();
            for (std::size_t i = 0; i < encapsulation.shared_secret.size(); ++i) p[i] = 0U;
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
            result.detail = std::string("SHA-AES-MLKEM failed: ") + exception.what();
        }

        result.timings.total_ms = std::chrono::duration<double, std::milli>(Clock::now() - total_start).count();
        detail::attach_quantum_analysis(result, run_quantum_demo);
        return result;
    }
}
