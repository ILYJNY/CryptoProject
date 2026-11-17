#include "ShorFactoring.h"

#include "EducationalQuantumAttack/Common/QuantumAttackSupport.h"
#include "EducationalQuantumAttack/Engine/PhaseEstimationEngine.h"

#include <cmath>
#include <numeric>
#include <stdexcept>

namespace crypto::educational_quantum_attack
{
    namespace
    {
        // Candidate orders recovered from one measurement y/2^t by continued fractions. The
        // standard Shor post-processing: every convergent denominator q < N is a candidate for
        // the order (or a divisor of it), so each q and a few small multiples m*q are returned.
        // Testing small multiples repairs the common case where the measured fraction reduced
        // s/r to lowest terms and the true order is a small multiple of the denominator.
        [[nodiscard]] std::vector<std::uint64_t> order_candidates(
            const std::uint64_t measured, const std::size_t phase_bits, const std::uint64_t modulus)
        {
            std::vector<std::uint64_t> candidates;
            long double remainder = static_cast<long double>(measured) / std::ldexp(1.0L, static_cast<int>(phase_bits));
            // Convergent-denominator recurrence k_i = a_i * k_{i-1} + k_{i-2}, starting from
            // k_{-1} = 0 and k_{-2} = 1 so that the first convergent denominator is 1.
            std::uint64_t k_prev = 1U;      // k_{i-2}
            std::uint64_t k_curr = 0U;      // k_{i-1}
            for (int iteration = 0; iteration < 64; ++iteration)
            {
                const auto term = static_cast<std::uint64_t>(std::floor(remainder));
                const std::uint64_t k_next = term * k_curr + k_prev;
                k_prev = k_curr;
                k_curr = k_next;
                if (k_curr == 0U) { /* a0 = 0 for x < 1; keep scanning */ }
                else if (k_curr < modulus)
                {
                    for (std::uint64_t multiple = 1U; multiple <= 6U; ++multiple)
                        candidates.push_back(multiple * k_curr);
                }
                else break;
                const long double fractional = remainder - static_cast<long double>(term);
                if (fractional < 1.0e-12L) break;
                remainder = 1.0L / fractional;
            }
            return candidates;
        }

        // The largest convergent denominator < N, kept for reporting the recovered order.
        [[nodiscard]] std::uint64_t reported_denominator(
            const std::uint64_t measured, const std::size_t phase_bits, const std::uint64_t modulus)
        {
            std::uint64_t best = 0U;
            for (const std::uint64_t candidate : order_candidates(measured, phase_bits, modulus))
                if (candidate < modulus) best = std::max(best, candidate);
            return best;
        }

        [[nodiscard]] PhaseEstimationStage modular_multiplication_stage(
            const std::uint64_t base, const std::uint64_t modulus, const std::size_t work_qubits)
        {
            PhaseEstimationStage stage;
            stage.bits = 2U * work_qubits;      // 2n phase bits for reliable order recovery
            stage.label = "controlled modular multiplication by a^(2^j) mod N";
            stage.controlled_power = [base, modulus](const std::size_t power, std::vector<std::size_t>& permutation)
            {
                std::uint64_t multiplier = base % modulus;
                for (std::size_t i = 0; i < power; ++i) multiplier = mod_mul(multiplier, multiplier, modulus);
                for (std::size_t state = 0; state < permutation.size(); ++state)
                {
                    permutation[state] = state < modulus
                        ? static_cast<std::size_t>(mod_mul(state, multiplier, modulus))
                        : state;
                }
            };
            return stage;
        }

        void accumulate_backend(
            quantum::QuantumBackendStatistics& total, const quantum::QuantumBackendStatistics& run)
        {
            total.cpu_operations += run.cpu_operations;
            total.gpu_operations += run.gpu_operations;
            total.cpu_fallback_operations += run.cpu_fallback_operations;
            total.cpu_wall_time_ms += run.cpu_wall_time_ms;
            total.gpu_kernel_time_ms += run.gpu_kernel_time_ms;
            total.gpu_transfer_time_ms += run.gpu_transfer_time_ms;
            total.cpu_threads_used = run.cpu_threads_used;
            total.gpu_device_used = run.gpu_device_used;
            total.gpu_devices_used = run.gpu_devices_used;
        }

        [[nodiscard]] bool try_factor_from_order(
            const std::uint64_t base, const std::uint64_t order, const std::uint64_t modulus,
            std::uint64_t& factor_p, std::uint64_t& factor_q)
        {
            if (order == 0U || order >= 4U * modulus) return false;
            if (mod_pow(base, order, modulus) != 1U) return false;
            if ((order & 1U) != 0U) return false;
            const std::uint64_t half = mod_pow(base, order / 2U, modulus);
            if (half == modulus - 1U) return false;
            for (const std::uint64_t candidate : {gcd_u64(half + 1U, modulus), gcd_u64(half - 1U, modulus)})
            {
                if (candidate > 1U && candidate < modulus)
                {
                    factor_p = candidate;
                    factor_q = modulus / candidate;
                    return true;
                }
            }
            return false;
        }
    }

    ShorFactoringResult run_shor_factoring(const std::uint64_t modulus, const ShorFactoringOptions& options)
    {
        if (modulus < 3U || (modulus & 1U) == 0U)
            throw std::invalid_argument("Shor factoring expects an odd composite modulus of at least 3.");

        ShorFactoringResult result;
        result.modulus = modulus;
        result.modulus_bits = bit_length(modulus);
        result.work_qubits = result.modulus_bits;
        result.total_qubits = result.modulus_bits + 1U;        // one reused control qubit
        result.phase_bits = 2U * result.modulus_bits;

        if (result.total_qubits > options.qubit_budget)
        {
            result.executed = false;
            result.status = "NOT EXECUTED (circuit exceeds the simulation budget)";
            result.failure_reason = "Shor's order-finding circuit for this modulus needs " +
                std::to_string(result.total_qubits) + " qubits, above the configured budget of " +
                std::to_string(options.qubit_budget) + " qubits.";
            return result;
        }
        result.executed = true;

        PhaseEstimationRequest base_request;
        base_request.work_qubits = result.work_qubits;
        base_request.initial_work_state = 1U;                  // |1>, a superposition of eigenvectors
        base_request.execution = options.execution;
        base_request.simulator_qubit_limit = options.qubit_budget;

        for (std::uint64_t base = 2U; base < modulus && result.attempts.size() / std::max<std::size_t>(1U, options.shots_per_base) < options.max_bases; ++base)
        {
            // A lucky common factor ends it classically; report it honestly as such.
            const std::uint64_t common = gcd_u64(base, modulus);
            if (common > 1U)
            {
                result.factored = true;
                result.factor_p = common;
                result.factor_q = modulus / common;
                result.winning_base = base;
                result.status = "FACTORED (a shared factor with the base was found before order finding)";
                return result;
            }

            std::uint64_t combined_order = 0U;
            for (std::size_t shot = 0; shot < options.shots_per_base; ++shot)
            {
                PhaseEstimationRequest request = base_request;
                request.seed = options.seed + 1009U * base + 7U * shot;
                request.stages = {modular_multiplication_stage(base, modulus, result.work_qubits)};

                const PhaseEstimationResult run = run_iterative_phase_estimation(request);
                result.total_simulator_ms += run.simulation_wall_ms;
                result.permutation_table_ms += run.permutation_table_ms;
                result.controlled_modular_multiplications += run.controlled_permutations;
                result.measurements += run.measurements;
                result.simulator_gate_operations += run.simulator_gate_count;
                result.state_vector_bytes = run.state_vector_bytes;
                accumulate_backend(result.backend, run.backend);

                const std::uint64_t measured = run.phase_integers.front();
                const std::uint64_t divisor = reported_denominator(measured, result.phase_bits, modulus);

                ShorFactoringAttempt attempt;
                attempt.base = base;
                attempt.measured_phase = measured;
                attempt.candidate_order = divisor;
                if (divisor > 0U && divisor < modulus)
                    combined_order = combined_order == 0U ? divisor
                        : (std::lcm(combined_order, divisor) < 4U * modulus ? std::lcm(combined_order, divisor) : divisor);
                attempt.combined_order = combined_order;
                attempt.simulator_ms = run.simulation_wall_ms;

                // Test every convergent-derived candidate order (and the lcm across shots).
                std::uint64_t factor_p = 0U;
                std::uint64_t factor_q = 0U;
                std::uint64_t used_order = 0U;
                std::vector<std::uint64_t> candidates = order_candidates(measured, result.phase_bits, modulus);
                candidates.push_back(combined_order);
                for (const std::uint64_t candidate_order : candidates)
                {
                    if (try_factor_from_order(base, candidate_order, modulus, factor_p, factor_q))
                    {
                        used_order = candidate_order;
                        break;
                    }
                }
                if (used_order != 0U)
                {
                    attempt.yielded_factor = true;
                    result.attempts.push_back(attempt);
                    result.factored = true;
                    result.factor_p = factor_p;
                    result.factor_q = factor_q;
                    result.winning_base = base;
                    result.recovered_order = used_order;
                    result.status = "FACTORED by quantum order finding";
                    return result;
                }
                result.attempts.push_back(attempt);
            }
        }

        result.status = "NOT FACTORED within the attempt budget";
        result.failure_reason =
            "No tried base produced a usable even order with a non-trivial square root of unity. "
            "Shor's algorithm is probabilistic; more bases or shots may succeed.";
        return result;
    }

    ShorFactoringSingleRun run_shor_factoring_single_circuit(
        const std::uint64_t modulus, const std::uint64_t base,
        const quantum::QuantumExecutionOptions& execution,
        const std::uint64_t seed, const std::size_t qubit_budget)
    {
        if (modulus < 3U) throw std::invalid_argument("Shor factoring expects a modulus of at least 3.");
        const std::size_t work_qubits = bit_length(modulus);

        PhaseEstimationRequest request;
        request.work_qubits = work_qubits;
        request.initial_work_state = 1U;
        request.execution = execution;
        request.simulator_qubit_limit = qubit_budget;
        request.seed = seed;
        request.stages = {modular_multiplication_stage(base % modulus == 0U ? 2U : base, modulus, work_qubits)};

        const PhaseEstimationResult run = run_iterative_phase_estimation(request);
        ShorFactoringSingleRun single;
        single.measured_phase = run.phase_integers.front();
        single.simulator_ms = run.simulation_wall_ms;
        single.total_qubits = run.qubits;
        single.backend = run.backend;
        return single;
    }
}
