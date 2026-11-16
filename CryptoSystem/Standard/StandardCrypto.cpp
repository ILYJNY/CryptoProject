#include "StandardCrypto.h"

#include "AES/AES128GCM.h"
#include "ECC/P256.h"
#include "Encoding/Encoding.h"
#include "ErrorHandling/CryptoException.h"
#include "RSA/RSA.h"
#include "Random/SecureRandom.h"
#include "SHA/SHA256.h"
#include "PerformanceMonitor/PerformanceMonitor.h"

#include <algorithm>
#include <filesystem>
#include <sstream>
#include <string>
#include <vector>

namespace crypto::standard
{
    namespace
    {
        void export_performance(const PerformanceMonitor& monitor, const std::string& prefix)
        {
            std::filesystem::create_directories("Output");
            monitor.export_csv("Output/" + prefix + "_performance.csv");
            monitor.export_summary_csv("Output/" + prefix + "_performance_summary.csv");
        }
    }

    std::string run_sha256_demo(const std::string_view message)
    {
        PerformanceMonitor monitor;
        Sha256Digest digest{};
        monitor.measure("Standard.SHA256.Hash", "CPU", [&]()
        {
            digest = sha256(message);
        });
        export_performance(monitor, "standard_sha256");
        return "SHA-256: " + hex_encode(digest) +
               "\nPerformance: Output/standard_sha256_performance.csv";
    }

    std::string run_aes_gcm_demo(const std::string_view message)
    {
        PerformanceMonitor monitor;
        Aes128Key key{};
        const auto randomKey = SecureRandom::bytes(key.size());
        std::copy(randomKey.begin(), randomKey.end(), key.begin());

        const auto plaintext = utf8_to_bytes(message);
        AesGcmCiphertext encrypted;
        monitor.measure("Standard.AES128GCM.Encrypt", "CPU", [&]()
        {
            encrypted = AES128GCM::encrypt(key, plaintext);
        });
        std::vector<std::uint8_t> decrypted;
        monitor.measure("Standard.AES128GCM.Decrypt", "CPU", [&]()
        {
            decrypted = AES128GCM::decrypt(key, encrypted);
        });
        export_performance(monitor, "standard_aes_gcm");

        std::ostringstream output;
        output << "AES-128-GCM encryption: PASS\n"
               << "Nonce: " << hex_encode(encrypted.nonce) << '\n'
               << "Ciphertext: " << hex_encode(encrypted.ciphertext) << '\n'
               << "Authentication tag: " << hex_encode(encrypted.tag) << '\n'
               << "Decryption round-trip: "
               << (decrypted == plaintext ? "PASS" : "FAIL") << '\n'
               << "Performance: Output/standard_aes_gcm_performance.csv";
        return output.str();
    }

    std::string run_p256_demo(const std::string_view message)
    {
        PerformanceMonitor monitor;
        P256KeyPair alice;
        P256KeyPair bob;
        monitor.measure("Standard.P256.KeyGeneration", "CPU", [&]()
        {
            alice = P256::generate_key_pair();
            bob = P256::generate_key_pair();
        });

        std::array<std::uint8_t, 32> aliceSecret{};
        std::array<std::uint8_t, 32> bobSecret{};
        monitor.measure("Standard.P256.ECDH", "CPU", [&]()
        {
            aliceSecret = P256::ecdh(alice.private_key, bob.public_key);
            bobSecret = P256::ecdh(bob.private_key, alice.public_key);
        });
        const bool sharedSecretMatches = aliceSecret == bobSecret;

        const auto* data = reinterpret_cast<const std::uint8_t*>(message.data());
        const std::span<const std::uint8_t> bytes(data, message.size());
        EcdsaSignature signature;
        monitor.measure("Standard.P256.ECDSA.Sign", "CPU", [&]()
        {
            signature = P256::sign_sha256(alice.private_key, bytes);
        });
        bool signatureValid = false;
        monitor.measure("Standard.P256.ECDSA.Verify", "CPU", [&]()
        {
            signatureValid = P256::verify_sha256(alice.public_key, bytes, signature);
        });
        export_performance(monitor, "standard_p256");

        std::ostringstream output;
        output << "P-256 ECDH shared secret agreement: "
               << (sharedSecretMatches ? "PASS" : "FAIL") << '\n'
               << "P-256 ECDSA signature verification: "
               << (signatureValid ? "PASS" : "FAIL") << '\n'
               << "Performance: Output/standard_p256_performance.csv";
        return output.str();
    }

    std::string run_rsa_demo(const std::string_view message, const std::size_t modulus_bits)
    {
        PerformanceMonitor monitor;
        RsaKeyPair pair;
        monitor.measure("Standard.RSA.KeyGeneration", "CPU", [&]()
        {
            pair = RSA::generate_key_pair(modulus_bits);
        });

        const auto* data = reinterpret_cast<const std::uint8_t*>(message.data());
        const std::span<const std::uint8_t> bytes(data, message.size());
        std::vector<std::uint8_t> ciphertext;
        monitor.measure("Standard.RSA.OAEP.Encrypt", "CPU", [&]()
        {
            ciphertext = RSA::encrypt_oaep_sha256(pair.public_key, bytes);
        });
        std::vector<std::uint8_t> plaintext;
        monitor.measure("Standard.RSA.OAEP.Decrypt", "CPU", [&]()
        {
            plaintext = RSA::decrypt_oaep_sha256(pair.private_key, ciphertext);
        });
        std::vector<std::uint8_t> signature;
        monitor.measure("Standard.RSA.PSS.Sign", "CPU", [&]()
        {
            signature = RSA::sign_pss_sha256(pair.private_key, bytes);
        });
        bool valid = false;
        monitor.measure("Standard.RSA.PSS.Verify", "CPU", [&]()
        {
            valid = RSA::verify_pss_sha256(pair.public_key, bytes, signature);
        });
        export_performance(monitor, "standard_rsa");

        std::ostringstream output;
        output << "RSA modulus size: " << bit_length(pair.public_key.modulus) << " bits\n"
               << "RSA-OAEP encryption/decryption: "
               << (std::vector<std::uint8_t>(bytes.begin(), bytes.end()) == plaintext ? "PASS" : "FAIL") << '\n'
               << "RSA-PSS signature verification: " << (valid ? "PASS" : "FAIL") << '\n'
               << "Performance: Output/standard_rsa_performance.csv";
        return output.str();
    }
}
