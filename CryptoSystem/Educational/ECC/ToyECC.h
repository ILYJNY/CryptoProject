#pragma once

#include <cstdint>

namespace crypto::educational
{
    struct ToyEccPublicInstance
    {
        std::uint32_t public_x = 0;
        std::uint32_t public_y = 0;
    };

    struct ToyEccGroundTruth
    {
        std::uint32_t private_scalar = 0;
    };

    struct ToyEccSample
    {
        ToyEccPublicInstance public_instance;
        ToyEccGroundTruth ground_truth;
    };

    struct ToyEccAnalysis
    {
        bool success = false;
        std::uint32_t recovered_scalar = 0;
        std::uint32_t attempts = 0;
        const char* status = "FAILED";
    };

    [[nodiscard]] ToyEccSample generate_toy_ecc_sample();
    [[nodiscard]] ToyEccAnalysis analyze_toy_ecc(const ToyEccPublicInstance& instance);
}
