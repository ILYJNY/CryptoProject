#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace crypto::educational
{
    // Tiny Module-LWE teaching instance over R_q = Z_q[x] / (x^n + 1).
    // These parameters are intentionally insecure and are not ML-KEM parameters.
    inline constexpr std::size_t ToyModuleDegree = 4U;
    inline constexpr std::size_t ToyModuleRank = 2U;
    inline constexpr std::uint16_t ToyModuleQ = 257U;

    using ToyModulePolynomial = std::array<std::uint16_t, ToyModuleDegree>;
    using ToyModuleSmallPolynomial = std::array<std::int8_t, ToyModuleDegree>;
    using ToyModuleSmallVector = std::array<ToyModuleSmallPolynomial, ToyModuleRank>;
    using ToyModuleVector = std::array<ToyModulePolynomial, ToyModuleRank>;
    using ToyModuleMatrix = std::array<std::array<ToyModulePolynomial, ToyModuleRank>, ToyModuleRank>;

    struct ToyLwePublicInstance
    {
        ToyModuleMatrix matrix{};
        ToyModuleVector vector{};
    };

    struct ToyLweGroundTruth
    {
        ToyModuleSmallVector secret{};
    };

    struct ToyLweSample
    {
        ToyLwePublicInstance public_instance;
        ToyLweGroundTruth ground_truth;
    };

    struct ToyLweAnalysis
    {
        bool success = false;
        ToyModuleSmallVector recovered_secret{};
        std::uint64_t candidates_tested = 0;
        const char* status = "FAILED";
    };

    [[nodiscard]] ToyLweSample generate_toy_lwe_sample();
    [[nodiscard]] ToyLweAnalysis analyze_toy_lwe(const ToyLwePublicInstance& instance);

    // ---------------------------------------------------------------------------------
    // Candidate enumeration and the secret-verification predicate (exposed in 2.3.5).
    // analyze_toy_lwe() enumerates exactly these candidates with exactly this predicate.
    // ---------------------------------------------------------------------------------

    // 3^(rank * degree) = 3^8 small-coefficient secret candidates.
    inline constexpr std::uint64_t ToyModuleSecretCandidateCount = 6561ULL;

    // Decodes a base-3 candidate index in [0, ToyModuleSecretCandidateCount) into a
    // secret vector with coefficients in {-1, 0, 1} (least significant trit first).
    [[nodiscard]] ToyModuleSmallVector decode_toy_lwe_candidate(std::uint64_t encoded);

    // True when b - A*s has every centered coefficient in {-1, 0, 1}.
    [[nodiscard]] bool toy_lwe_candidate_matches(
        const ToyLwePublicInstance& instance,
        const ToyModuleSmallVector& candidate);
}
