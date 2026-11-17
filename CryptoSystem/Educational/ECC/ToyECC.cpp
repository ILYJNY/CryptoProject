#include "ToyECC.h"

#include "ErrorHandling/CryptoException.h"
#include "Random/SecureRandom.h"

#include <cstdint>

namespace crypto::educational
{
    namespace
    {
        constexpr std::uint32_t P = 97U;
        constexpr std::uint32_t A = 2U;
        constexpr std::uint32_t B = 3U;
        constexpr std::uint32_t ORDER = 50U;

        // The public ToyEccPoint has the same shape as the original private point type.
        using Point = ToyEccPoint;

        [[nodiscard]] std::uint32_t inverse(const std::uint32_t value)
        {
            for (std::uint32_t candidate = 1U; candidate < P; ++candidate)
            {
                if ((value * candidate) % P == 1U) return candidate;
            }
            raise_error(ErrorCode::ArithmeticError, "Toy elliptic-curve inverse does not exist.");
        }

        [[nodiscard]] Point add(const Point& left, const Point& right)
        {
            if (left.infinity) return right;
            if (right.infinity) return left;
            if (left.x == right.x && (left.y + right.y) % P == 0U) return {};

            std::uint32_t slope = 0;
            if (left.x == right.x && left.y == right.y)
            {
                if (left.y == 0U) return {};
                const std::uint32_t numerator = (3U * left.x * left.x + A) % P;
                const std::uint32_t denominator = inverse((2U * left.y) % P);
                slope = (numerator * denominator) % P;
            }
            else
            {
                const std::uint32_t numerator = (right.y + P - left.y) % P;
                const std::uint32_t denominator = inverse((right.x + P - left.x) % P);
                slope = (numerator * denominator) % P;
            }

            const std::uint32_t x = (slope * slope + 2U * P - left.x - right.x) % P;
            const std::uint32_t y = (slope * ((left.x + P - x) % P) + P - left.y) % P;
            return {x, y, false};
        }

        constexpr std::uint32_t BASE_X = 0U;
        constexpr std::uint32_t BASE_Y = 10U;

        [[nodiscard]] Point multiply_point(std::uint32_t scalar, Point base)
        {
            Point result{};
            while (scalar > 0U)
            {
                if ((scalar & 1U) != 0U) result = add(result, base);
                scalar >>= 1U;
                if (scalar > 0U) base = add(base, base);
            }
            return result;
        }

        [[nodiscard]] Point multiply(const std::uint32_t scalar)
        {
            return multiply_point(scalar, Point{BASE_X, BASE_Y, false});
        }
    }

    bool operator==(const ToyEccPoint& left, const ToyEccPoint& right) noexcept
    {
        if (left.infinity || right.infinity) return left.infinity == right.infinity;
        return left.x == right.x && left.y == right.y;
    }

    ToyEccCurveParameters toy_ecc_curve_parameters() noexcept
    {
        return {P, A, B, BASE_X, BASE_Y, ORDER};
    }

    ToyEccPoint toy_ecc_base_point() noexcept
    {
        return {BASE_X, BASE_Y, false};
    }

    bool toy_ecc_is_on_curve(const ToyEccPoint& point) noexcept
    {
        if (point.infinity) return true;
        if (point.x >= P || point.y >= P) return false;
        return (point.y * point.y) % P ==
            (point.x * point.x * point.x + A * point.x + B) % P;
    }

    ToyEccPoint toy_ecc_add(const ToyEccPoint& left, const ToyEccPoint& right)
    {
        if (!toy_ecc_is_on_curve(left) || !toy_ecc_is_on_curve(right))
            raise_error(ErrorCode::InvalidArgument, "Toy elliptic-curve addition requires points on the curve.");
        return add(left, right);
    }

    ToyEccPoint toy_ecc_multiply(const std::uint32_t scalar, const ToyEccPoint& point)
    {
        if (!toy_ecc_is_on_curve(point))
            raise_error(ErrorCode::InvalidArgument, "Toy elliptic-curve multiplication requires a point on the curve.");
        return multiply_point(scalar, point);
    }

    ToyEccSample generate_toy_ecc_sample()
    {
        const std::uint32_t scalar = static_cast<std::uint32_t>(SecureRandom::uniform_u64(1U, ORDER - 1U));
        const Point publicPoint = multiply(scalar);
        return {{publicPoint.x, publicPoint.y}, {scalar}};
    }

    ToyEccAnalysis analyze_toy_ecc(const ToyEccPublicInstance& instance)
    {
        ToyEccAnalysis result;
        if (instance.public_x >= P || instance.public_y >= P ||
            (instance.public_y * instance.public_y) % P !=
                (instance.public_x * instance.public_x * instance.public_x +
                 A * instance.public_x + B) % P)
        {
            result.status = "INVALID_POINT";
            return result;
        }

        for (std::uint32_t scalar = 1U; scalar < ORDER; ++scalar)
        {
            ++result.attempts;
            const Point candidate = multiply(scalar);
            if (!candidate.infinity && candidate.x == instance.public_x && candidate.y == instance.public_y)
            {
                result.success = true;
                result.recovered_scalar = scalar;
                result.status = "PRIVATE_SCALAR_RECOVERED";
                return result;
            }
        }
        result.status = "INCONCLUSIVE";
        return result;
    }
}
