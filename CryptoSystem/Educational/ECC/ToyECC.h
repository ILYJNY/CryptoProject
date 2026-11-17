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

    // ---------------------------------------------------------------------------------
    // Public curve description and group law (added in 2.3.5).
    // These expose the fixed teaching curve that the functions above already use, so
    // that other modules can work with the real curve parameters instead of copies.
    // ---------------------------------------------------------------------------------

    // y^2 = x^3 + coefficient_a * x + coefficient_b over F_field_prime, with a base
    // point whose declared order is base_point_order.
    struct ToyEccCurveParameters
    {
        std::uint32_t field_prime = 0;
        std::uint32_t coefficient_a = 0;
        std::uint32_t coefficient_b = 0;
        std::uint32_t base_x = 0;
        std::uint32_t base_y = 0;
        std::uint32_t base_point_order = 0;
    };

    struct ToyEccPoint
    {
        std::uint32_t x = 0;
        std::uint32_t y = 0;
        bool infinity = true;
    };

    [[nodiscard]] bool operator==(const ToyEccPoint& left, const ToyEccPoint& right) noexcept;

    [[nodiscard]] ToyEccCurveParameters toy_ecc_curve_parameters() noexcept;
    [[nodiscard]] ToyEccPoint toy_ecc_base_point() noexcept;
    [[nodiscard]] bool toy_ecc_is_on_curve(const ToyEccPoint& point) noexcept;
    [[nodiscard]] ToyEccPoint toy_ecc_add(const ToyEccPoint& left, const ToyEccPoint& right);
    [[nodiscard]] ToyEccPoint toy_ecc_multiply(std::uint32_t scalar, const ToyEccPoint& point);
}
