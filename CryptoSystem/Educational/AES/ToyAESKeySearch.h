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

    // ---------------------------------------------------------------------------------
    // Candidate-key mapping and verification predicate (exposed in 2.3.5).
    // analyze_toy_aes() enumerates exactly these candidates with exactly this predicate.
    // ---------------------------------------------------------------------------------

    // Maps a candidate index in [0, 2^unknown_bits) to the AES-128 key it denotes: the
    // unknown bits fill the low-order end of the key and every other key bit is zero.
    [[nodiscard]] standard::Aes128Key toy_aes_candidate_key(std::uint32_t candidate, std::size_t unknown_bits);

    // True when AES-128-GCM authenticates the public record under the candidate key.
    [[nodiscard]] bool toy_aes_candidate_matches(const ToyAesPublicInstance& instance, std::uint32_t candidate);
}
