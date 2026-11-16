#pragma once

#include "AES/AES128GCM.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace crypto::educational
{
    struct ToyAesPublicInstance
    {
        standard::AesGcmCiphertext ciphertext;
        std::vector<std::uint8_t> associated_data;
        std::size_t unknown_bits = 16U;
    };

    struct ToyAesGroundTruth
    {
        standard::Aes128Key key{};
        std::string plaintext;
    };

    struct ToyAesSample
    {
        ToyAesPublicInstance public_instance;
        ToyAesGroundTruth ground_truth;
    };

    struct ToyAesAnalysis
    {
        bool success = false;
        standard::Aes128Key recovered_key{};
        std::uint64_t candidates_tested = 0;
        const char* status = "FAILED";
    };

    // This deliberately restricts the keyspace to 4-16 unknown bits for a self-generated demonstration.
    [[nodiscard]] ToyAesSample generate_toy_aes_sample(std::size_t unknown_bits = 16U);
    [[nodiscard]] ToyAesSample generate_toy_aes_sample(
        std::size_t unknown_bits, const std::string& plaintext);
    [[nodiscard]] ToyAesAnalysis analyze_toy_aes(const ToyAesPublicInstance& instance);
}
