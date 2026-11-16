#include "AES/AES128GCM.h"
#include "ECC/P256.h"
#include "Encoding/Encoding.h"
#include "RSA/RSA.h"
#include "SHA/SHA256.h"
#include "CryptoAnalyzer/Standard/StandardAnalyzer.h"
#include "CryptoAnalyzer/Educational/EducationalAnalyzer.h"
#include "CryptoSystem/Educational/ECC/ToyECC.h"
#include "CryptoSystem/Educational/AES/ToyAESKeySearch.h"
#include "CryptoSystem/Educational/SHA/ToySha256.h"
#include "CryptoSystem/Educational/ModuleLWE/ToyModuleLWE.h"
#include "CryptoSystem/Educational/RSA/ToyRSA.h"
#include "IntegratedMode/IntegratedRunner.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
    void require(const bool condition, const char* message)
    {
        if (!condition) throw std::runtime_error(message);
    }

    void test_standard_known_answer_tests()
    {
        const auto results = crypto::analyzer::StandardAnalyzer::run_known_answer_tests();
        require(!results.empty(), "No known-answer tests were executed.");
        for (const auto& result : results)
        {
            require(result.passed, result.name.c_str());
        }
    }

    void test_rsa_round_trip()
    {
        const auto pair = crypto::standard::RSA::generate_key_pair(1024U);
        const std::string message = "RSA OAEP and PSS smoke test";
        const auto* ptr = reinterpret_cast<const std::uint8_t*>(message.data());
        const std::span<const std::uint8_t> bytes(ptr, message.size());
        const auto ciphertext = crypto::standard::RSA::encrypt_oaep_sha256(pair.public_key, bytes);
        const auto plaintext = crypto::standard::RSA::decrypt_oaep_sha256(pair.private_key, ciphertext);
        require(std::string(plaintext.begin(), plaintext.end()) == message, "RSA-OAEP round-trip failed.");
        const auto signature = crypto::standard::RSA::sign_pss_sha256(pair.private_key, bytes);
        require(crypto::standard::RSA::verify_pss_sha256(pair.public_key, bytes, signature),
                "RSA-PSS signature verification failed.");
    }

    void test_p256()
    {
        const auto alice = crypto::standard::P256::generate_key_pair();
        const auto bob = crypto::standard::P256::generate_key_pair();
        require(crypto::standard::P256::ecdh(alice.private_key, bob.public_key) ==
                crypto::standard::P256::ecdh(bob.private_key, alice.public_key),
                "P-256 ECDH shared secret mismatch.");

        const std::string message = "P-256 ECDSA smoke test";
        const auto* ptr = reinterpret_cast<const std::uint8_t*>(message.data());
        const std::span<const std::uint8_t> bytes(ptr, message.size());
        const auto signature = crypto::standard::P256::sign_sha256(alice.private_key, bytes);
        require(crypto::standard::P256::verify_sha256(alice.public_key, bytes, signature),
                "P-256 ECDSA verification failed.");
    }

    void test_educational_analyzers()
    {
        for (const std::size_t modulusBits : {16U, 24U, 32U})
        {
            const auto rsa = crypto::educational::generate_toy_rsa_sample(modulusBits);
            require(rsa.modulus_bits == modulusBits, "Toy RSA modulus-size configuration was not retained.");
            const auto rsaResult = crypto::analyzer::EducationalAnalyzer::analyze(rsa.public_instance);
            require(rsaResult.success && rsaResult.recovered_plaintext == rsa.ground_truth.plaintext,
                    "Toy RSA recovery failed.");
        }

        const auto ecc = crypto::educational::generate_toy_ecc_sample();
        const auto eccResult = crypto::analyzer::EducationalAnalyzer::analyze(ecc.public_instance);
        require(eccResult.success && eccResult.recovered_scalar == ecc.ground_truth.private_scalar,
                "Toy elliptic-curve recovery failed.");

        const auto lwe = crypto::educational::generate_toy_lwe_sample();
        const auto lweResult = crypto::analyzer::EducationalAnalyzer::analyze(lwe.public_instance);
        require(lweResult.success && lweResult.recovered_secret == lwe.ground_truth.secret,
                "Toy Module-LWE secret recovery failed.");

        const auto smallAes = crypto::educational::generate_toy_aes_sample(4U);
        const auto smallAesResult = crypto::analyzer::EducationalAnalyzer::analyze(smallAes.public_instance);
        require(smallAesResult.success && smallAesResult.recovered_key == smallAes.ground_truth.key,
                "Toy AES 4-bit keyspace analysis failed.");

        const auto aes = crypto::educational::generate_toy_aes_sample(16U);
        const auto aesResult = crypto::analyzer::EducationalAnalyzer::analyze(aes.public_instance);
        require(aesResult.success && aesResult.recovered_key == aes.ground_truth.key,
                "Toy AES 16-bit keyspace analysis failed.");

        const auto collision = crypto::educational::find_truncated_sha256_collision(16U, 200000U);
        require(collision.found, "Truncated SHA-256 collision demo did not find a collision.");
    }

    void test_integrated_mode()
    {
        const auto result = crypto::integrated::run_educational_integrated_demo();
        require(result.passed, "Integrated educational workflow failed.");
    }
}

int main()
{
    try
    {
        test_standard_known_answer_tests();
        test_rsa_round_trip();
        test_p256();
        test_educational_analyzers();
        test_integrated_mode();
        std::cout << "[PASS] Project smoke tests completed successfully.\n";
        return 0;
    }
    catch (const std::exception& exception)
    {
        std::cerr << "[FAIL] " << exception.what() << '\n';
        return 1;
    }
}
