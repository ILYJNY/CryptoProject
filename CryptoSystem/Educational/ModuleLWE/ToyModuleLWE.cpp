#include "ToyModuleLWE.h"

#include "Random/SecureRandom.h"

#include <array>
#include <cstdint>
#include <stdexcept>

namespace crypto::educational
{
    namespace
    {
        using AccumulatorPolynomial = std::array<std::int32_t, ToyModuleDegree>;

        [[nodiscard]] std::uint16_t reduce(const std::int64_t value)
        {
            std::int64_t result = value % static_cast<std::int64_t>(ToyModuleQ);
            if (result < 0) result += static_cast<std::int64_t>(ToyModuleQ);
            return static_cast<std::uint16_t>(result);
        }

        [[nodiscard]] std::int32_t centered_residual(const std::uint16_t value)
        {
            const std::int32_t raw = static_cast<std::int32_t>(value);
            return raw > static_cast<std::int32_t>(ToyModuleQ / 2U)
                ? raw - static_cast<std::int32_t>(ToyModuleQ)
                : raw;
        }

        // Multiplication in R_q = Z_q[x] / (x^n + 1).
        // Terms whose degree reaches n wrap around with a minus sign because x^n = -1.
        void multiply_accumulate(
            AccumulatorPolynomial& accumulator,
            const ToyModulePolynomial& left,
            const ToyModuleSmallPolynomial& right)
        {
            for (std::size_t i = 0; i < ToyModuleDegree; ++i)
            {
                for (std::size_t j = 0; j < ToyModuleDegree; ++j)
                {
                    const std::size_t degree = i + j;
                    const std::size_t destination = degree < ToyModuleDegree
                        ? degree : degree - ToyModuleDegree;
                    const std::int32_t sign = degree < ToyModuleDegree ? 1 : -1;
                    accumulator[destination] += sign *
                        static_cast<std::int32_t>(left[i]) *
                        static_cast<std::int32_t>(right[j]);
                }
            }
        }

        [[nodiscard]] ToyModulePolynomial finish_polynomial(
            const AccumulatorPolynomial& accumulator,
            const ToyModuleSmallPolynomial* error = nullptr)
        {
            ToyModulePolynomial result{};
            for (std::size_t i = 0; i < ToyModuleDegree; ++i)
            {
                const std::int32_t noise = error == nullptr
                    ? 0 : static_cast<std::int32_t>((*error)[i]);
                result[i] = reduce(static_cast<std::int64_t>(accumulator[i]) + noise);
            }
            return result;
        }

        [[nodiscard]] ToyModuleSmallPolynomial random_small_polynomial()
        {
            ToyModuleSmallPolynomial result{};
            for (auto& coefficient : result)
            {
                coefficient = static_cast<std::int8_t>(
                    static_cast<std::int32_t>(SecureRandom::uniform_u64(0U, 2U)) - 1);
            }
            return result;
        }

        [[nodiscard]] bool candidate_matches(
            const ToyLwePublicInstance& instance,
            const ToyModuleSmallVector& candidate)
        {
            for (std::size_t row = 0; row < ToyModuleRank; ++row)
            {
                AccumulatorPolynomial accumulated{};
                for (std::size_t column = 0; column < ToyModuleRank; ++column)
                {
                    multiply_accumulate(accumulated,
                        instance.matrix[row][column], candidate[column]);
                }

                const ToyModulePolynomial predicted = finish_polynomial(accumulated);
                for (std::size_t coefficient = 0; coefficient < ToyModuleDegree; ++coefficient)
                {
                    const std::uint16_t residual = reduce(
                        static_cast<std::int64_t>(instance.vector[row][coefficient]) -
                        static_cast<std::int64_t>(predicted[coefficient]));
                    const std::int32_t error = centered_residual(residual);
                    if (error < -1 || error > 1) return false;
                }
            }
            return true;
        }
    }

    ToyLweSample generate_toy_lwe_sample()
    {
        ToyLweSample sample;
        sample.ground_truth.secret = {
            random_small_polynomial(),
            random_small_polynomial()
        };

        ToyModuleSmallVector error{
            random_small_polynomial(),
            random_small_polynomial()
        };

        for (std::size_t row = 0; row < ToyModuleRank; ++row)
        {
            AccumulatorPolynomial accumulated{};
            for (std::size_t column = 0; column < ToyModuleRank; ++column)
            {
                ToyModulePolynomial& matrix_polynomial = sample.public_instance.matrix[row][column];
                for (auto& coefficient : matrix_polynomial)
                {
                    coefficient = static_cast<std::uint16_t>(
                        SecureRandom::uniform_u64(0U, ToyModuleQ - 1U));
                }
                multiply_accumulate(accumulated, matrix_polynomial,
                    sample.ground_truth.secret[column]);
            }
            sample.public_instance.vector[row] = finish_polynomial(
                accumulated, &error[row]);
        }

        return sample;
    }

    ToyModuleSmallVector decode_toy_lwe_candidate(const std::uint64_t encoded)
    {
        if (encoded >= ToyModuleSecretCandidateCount)
            throw std::out_of_range("The toy Module-LWE candidate index is outside the 3^8 candidate space.");
        std::uint64_t state = encoded;
        ToyModuleSmallVector candidate{};
        for (std::size_t module_index = 0; module_index < ToyModuleRank; ++module_index)
        {
            for (std::size_t coefficient = 0; coefficient < ToyModuleDegree; ++coefficient)
            {
                const auto trit = static_cast<std::int8_t>(state % 3ULL);
                candidate[module_index][coefficient] = static_cast<std::int8_t>(trit - 1);
                state /= 3ULL;
            }
        }
        return candidate;
    }

    bool toy_lwe_candidate_matches(
        const ToyLwePublicInstance& instance,
        const ToyModuleSmallVector& candidate)
    {
        return candidate_matches(instance, candidate);
    }

    ToyLweAnalysis analyze_toy_lwe(const ToyLwePublicInstance& instance)
    {
        ToyLweAnalysis result;
        constexpr std::uint64_t candidate_count = ToyModuleSecretCandidateCount; // 3^(rank * degree) = 3^8.

        for (std::uint64_t encoded = 0; encoded < candidate_count; ++encoded)
        {
            const ToyModuleSmallVector candidate = decode_toy_lwe_candidate(encoded);

            ++result.candidates_tested;
            if (candidate_matches(instance, candidate))
            {
                result.success = true;
                result.recovered_secret = candidate;
                result.status = "SECRET_RECOVERED";
                return result;
            }
        }

        result.status = "INCONCLUSIVE";
        return result;
    }
}
