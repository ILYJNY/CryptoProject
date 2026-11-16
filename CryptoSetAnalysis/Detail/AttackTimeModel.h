#pragma once

#include <cmath>
#include <cstddef>
#include <iomanip>
#include <sstream>
#include <string>

namespace crypto::set_analysis::detail::attack_time_model
{
    // Explicit, editable scenario assumptions. These are not measured hardware rates.
    // Change these two values to explore a different idealized logical-computer scenario.
    inline constexpr long double kSecondsPerGroverOracleIteration = 1.0e-6L;
    inline constexpr long double kSecondsPerSerialToffoliGate = 1.0e-6L;
    inline constexpr long double kSecondsPerYear = 365.25L * 24.0L * 60.0L * 60.0L;

    // Roetteler et al. (ASIACRYPT 2017), approximate upper resource model for Shor ECDLP:
    // 448*n^3*log2(n) + 4090*n^3 Toffoli gates.
    [[nodiscard]] inline long double estimate_ecc_shor_toffoli_gates(const std::size_t field_bits)
    {
        const long double n = static_cast<long double>(field_bits);
        if (field_bits < 2U) return 0.0L;
        return 448.0L * n * n * n * std::log2(n) + 4090.0L * n * n * n;
    }

    // Roetteler et al. (ASIACRYPT 2017), interpolation for Shor factoring:
    // (64*(log2(n)-2) + 29.46)*n^3 Toffoli gates.
    [[nodiscard]] inline long double estimate_rsa_shor_toffoli_gates(const std::size_t modulus_bits)
    {
        const long double n = static_cast<long double>(modulus_bits);
        if (modulus_bits < 8U) return 0.0L;
        return (64.0L * (std::log2(n) - 2.0L) + 29.46L) * n * n * n;
    }

    [[nodiscard]] inline std::string format_duration(const long double seconds)
    {
        if (!std::isfinite(seconds) || seconds < 0.0L) return "N/A";
        std::ostringstream out;
        if (seconds < 1.0e-3L)
        {
            out << std::fixed << std::setprecision(3) << seconds * 1.0e6L << " microseconds";
        }
        else if (seconds < 1.0L)
        {
            out << std::fixed << std::setprecision(3) << seconds * 1.0e3L << " ms";
        }
        else if (seconds < 60.0L)
        {
            out << std::fixed << std::setprecision(2) << seconds << " seconds";
        }
        else if (seconds < 3600.0L)
        {
            out << std::fixed << std::setprecision(2) << seconds / 60.0L << " minutes";
        }
        else if (seconds < 86400.0L)
        {
            out << std::fixed << std::setprecision(2) << seconds / 3600.0L << " hours";
        }
        else if (seconds < kSecondsPerYear)
        {
            out << std::fixed << std::setprecision(2) << seconds / 86400.0L << " days";
        }
        else
        {
            const long double years = seconds / kSecondsPerYear;
            if (years < 1.0e6L) out << std::fixed << std::setprecision(2) << years << " years";
            else out << std::scientific << std::setprecision(5) << years << " years";
        }
        return out.str();
    }
}
