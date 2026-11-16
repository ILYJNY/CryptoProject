#pragma once

#include <cstddef>
#include <cstdint>

namespace crypto::educational
{
    struct ToyRsaPublicInstance
    {
        std::uint64_t modulus = 0;
        std::uint64_t public_exponent = 0;
        std::uint64_t ciphertext = 0;
    };

    struct ToyRsaGroundTruth
    {
        std::uint64_t p = 0;
        std::uint64_t q = 0;
        std::uint64_t private_exponent = 0;
        std::uint64_t plaintext = 0;
    };

    struct ToyRsaSample
    {
        ToyRsaPublicInstance public_instance;
        ToyRsaGroundTruth ground_truth;
        std::size_t modulus_bits = 0;
    };

    struct ToyRsaAnalysis
    {
        bool success = false;
        std::uint64_t recovered_p = 0;
        std::uint64_t recovered_q = 0;
        std::uint64_t recovered_private_exponent = 0;
        std::uint64_t recovered_plaintext = 0;
        std::uint64_t trial_divisions = 0;
        const char* status = "FAILED";
    };

    [[nodiscard]] ToyRsaSample generate_toy_rsa_sample(std::size_t modulus_bits = 32U);
    [[nodiscard]] ToyRsaAnalysis analyze_toy_rsa(const ToyRsaPublicInstance& instance);
}
