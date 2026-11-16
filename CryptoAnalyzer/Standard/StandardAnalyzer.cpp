#include "StandardAnalyzer.h"

#include "Encoding/Encoding.h"
#include "AES/AES128GCM.h"
#include "SHA/SHA256.h"
#include "PerformanceMonitor/PerformanceMonitor.h"

#include <array>
#include <cstdint>
#include <filesystem>
#include <string_view>
#include <vector>

namespace crypto::analyzer
{
    namespace
    {
        PerformanceMonitor& analyzer_monitor()
        {
            static PerformanceMonitor monitor;
            return monitor;
        }

        void export_performance()
        {
            std::filesystem::create_directories("Output");
            analyzer_monitor().export_csv("Output/standard_analyzer_performance.csv");
            analyzer_monitor().export_summary_csv("Output/standard_analyzer_performance_summary.csv");
        }
    }

    std::vector<CheckResult> StandardAnalyzer::run_known_answer_tests()
    {
        std::vector<CheckResult> results;
        auto& monitor = analyzer_monitor();

        standard::Sha256Digest digest{};
        monitor.measure("Analyzer.Standard.SHA256.KAT", "CPU", [&]()
        {
            digest = standard::sha256(std::string_view{});
        });
        const auto digestHex = hex_encode(digest);
        results.push_back({
            "SHA-256 empty-message KAT",
            digestHex == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            digestHex
        });

        standard::Aes128Key key{};
        standard::GcmNonce nonce{};
        std::array<std::uint8_t, 16> plaintext{};
        standard::AesGcmCiphertext encrypted;
        monitor.measure("Analyzer.Standard.AES128GCM.KAT", "CPU", [&]()
        {
            encrypted = standard::AES128GCM::encrypt_with_nonce(key, nonce, plaintext);
        });
        const std::string ciphertextHex = hex_encode(encrypted.ciphertext);
        const std::string tagHex = hex_encode(encrypted.tag);
        const bool aesPassed =
            ciphertextHex == "0388dace60b6a392f328c2b971b2fe78" &&
            tagHex == "ab6e47d42cec13bdf53a67b21257bddf";
        results.push_back({
            "AES-128-GCM NIST example vector",
            aesPassed,
            "ciphertext=" + ciphertextHex + "; tag=" + tagHex
        });

        export_performance();
        return results;
    }

    RsaAuditResult StandardAnalyzer::audit_rsa_public_key(
        const standard::RsaPublicKey& public_key)
    {
        RsaAuditResult result;
        result.modulus_bits = bit_length(public_key.modulus);

        if (public_key.modulus <= 0 || public_key.public_exponent < 3 ||
            (public_key.public_exponent & 1) == 0)
        {
            result.recommendation = "The RSA public key parameters are invalid.";
            return result;
        }

        if (result.modulus_bits < 3072U)
        {
            result.recommendation = "The modulus is below the configured 3072-bit policy threshold.";
            return result;
        }

        result.acceptable_for_policy = true;
        result.recommendation = "The public key meets this project's basic RSA key-size policy. This is not a certification.";
        return result;
    }
}
