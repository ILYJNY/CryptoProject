#include "GroverEngine.h"

#include "EducationalQuantumAttack/Common/QuantumAttackSupport.h"
#include "QuantumAttack/Standard/Core/QuantumSimulator.h"

#include <algorithm>
#include <cmath>
#include <numbers>
#include <random>
#include <sstream>
#include <stdexcept>

namespace crypto::educational_quantum_attack
{
    namespace
    {
        void accumulate(quantum::QuantumBackendStatistics& total, const quantum::QuantumBackendStatistics& run)
        {
            total.cpu_operations += run.cpu_operations;
            total.gpu_operations += run.gpu_operations;
            total.cpu_fallback_operations += run.cpu_fallback_operations;
            total.cpu_wall_time_ms += run.cpu_wall_time_ms;
            total.gpu_kernel_time_ms += run.gpu_kernel_time_ms;
            total.gpu_transfer_time_ms += run.gpu_transfer_time_ms;
            total.gpu_initialization_time_ms += run.gpu_initialization_time_ms;
            total.cpu_threads_used = run.cpu_threads_used;
            total.gpu_device_used = run.gpu_device_used;
            total.gpu_devices_used = run.gpu_devices_used;
            total.gpu_inter_gpu_transfer_time_ms += run.gpu_inter_gpu_transfer_time_ms;
            total.gpu_parallel_kernel_wall_time_ms += run.gpu_parallel_kernel_wall_time_ms;
            total.gpu_peer_copy_count += run.gpu_peer_copy_count;
            total.gpu_host_staged_copy_count += run.gpu_host_staged_copy_count;
            total.gpu_pinned_host_memory_used =
                total.gpu_pinned_host_memory_used || run.gpu_pinned_host_memory_used;
        }

        // The simulator labels a basis state with its most significant qubit first.
        [[nodiscard]] std::size_t index_from_label(const std::string& label)
        {
            std::size_t index = 0U;
            for (const char bit : label)
                index = (index << 1U) | (bit == '1' ? std::size_t{1} : std::size_t{0});
            return index;
        }

        // Builds the circuit from scratch, applies `iterations` Grover iterations and
        // measures the search register once.
        [[nodiscard]] GroverAttempt execute_circuit(
            const GroverSearchRequest& request,
            const std::vector<std::size_t>& marked,
            const std::uint64_t iterations,
            const std::uint64_t measurement_seed,
            GroverSearchResult& totals)
        {
            const Stopwatch stopwatch;
            quantum::QuantumSimulator simulator(
                request.search_qubits, request.simulator_qubit_limit, request.execution);

            for (std::size_t qubit = 0U; qubit < request.search_qubits; ++qubit)
                simulator.apply_hadamard(qubit);
            for (std::uint64_t iteration = 0U; iteration < iterations; ++iteration)
            {
                // One oracle call: flip the phase of every marked candidate.
                for (const std::size_t index : marked) simulator.apply_phase_flip(index);
                simulator.apply_diffusion();
            }

            GroverAttempt attempt;
            attempt.iterations = iterations;
            const std::vector<double> probabilities = simulator.probabilities();
            for (const std::size_t index : marked) attempt.success_probability += probabilities[index];

            const quantum::MeasurementResult measurement = simulator.measure_all(1U, measurement_seed);
            if (measurement.counts.empty())
                throw std::runtime_error("The simulator returned no measurement outcome.");
            attempt.measured_index = index_from_label(measurement.counts.begin()->first);

            ++totals.circuit_runs;
            totals.hadamard_gates += request.search_qubits;
            totals.phase_flip_operations += iterations * static_cast<std::uint64_t>(marked.size());
            totals.diffusion_operations += iterations;
            ++totals.measurements;
            totals.total_grover_iterations += iterations;
            totals.simulator_gate_count += simulator.gate_count();
            totals.deepest_run_operation_depth = std::max<std::uint64_t>(
                totals.deepest_run_operation_depth, simulator.operation_depth());
            totals.qubits = simulator.qubit_count();
            totals.state_vector_bytes = simulator.state_vector_bytes();
            accumulate(totals.backend, simulator.backend_statistics());
            totals.simulation_wall_ms += stopwatch.elapsed_ms();
            return attempt;
        }
    }

    std::uint64_t optimal_grover_iterations(const double search_space, const double solutions)
    {
        if (!(search_space > 0.0) || !(solutions > 0.0)) return 0U;
        if (solutions >= search_space) return 0U;
        const double angle = std::asin(std::sqrt(solutions / search_space));
        return static_cast<std::uint64_t>(std::floor(std::numbers::pi / (4.0 * angle)));
    }

    double grover_success_probability(
        const double search_space, const double solutions, const std::uint64_t iterations)
    {
        if (!(search_space > 0.0) || !(solutions > 0.0)) return 0.0;
        if (solutions >= search_space) return 1.0;
        const double angle = std::asin(std::sqrt(solutions / search_space));
        const double amplitude = std::sin((2.0 * static_cast<double>(iterations) + 1.0) * angle);
        return amplitude * amplitude;
    }

    GroverSearchResult run_grover_search(const GroverSearchRequest& request)
    {
        if (request.search_qubits == 0U || request.search_qubits >= 63U)
            throw std::invalid_argument("The Grover search register must have between 1 and 62 qubits.");
        if (!request.classical_verifier)
            throw std::invalid_argument("A classical verifier is required to check measured candidates.");
        if (request.max_attempts == 0U)
            throw std::invalid_argument("At least one quantum attempt must be allowed.");
        const std::size_t dimension = std::size_t{1} << request.search_qubits;

        std::vector<std::size_t> marked = request.marked_indices;
        std::sort(marked.begin(), marked.end());
        marked.erase(std::unique(marked.begin(), marked.end()), marked.end());
        for (const std::size_t index : marked)
        {
            if (index >= dimension)
                throw std::invalid_argument("A marked index lies outside the Grover search register.");
        }

        GroverSearchResult result;
        std::mt19937_64 generator(request.seed);
        const double space = static_cast<double>(dimension);

        const auto verify = [&](GroverAttempt& attempt)
        {
            ++result.classical_verifications;
            attempt.verified = request.classical_verifier(attempt.measured_index);
            result.attempts.push_back(attempt);
            if (attempt.verified)
            {
                result.found = true;
                result.found_index = attempt.measured_index;
            }
            return attempt.verified;
        };

        std::ostringstream description;
        bool run_unknown_schedule = request.strategy == GroverStrategy::UnknownSolutionCount;

        if (request.strategy == GroverStrategy::KnownSolutionCount)
        {
            if (!(request.assumed_solution_count > 0.0))
                throw std::invalid_argument("The assumed number of solutions must be positive.");
            result.planned_iterations = optimal_grover_iterations(space, request.assumed_solution_count);
            description << "Known-solution-count Grover: R = floor(pi / (4 * asin(sqrt(M/N)))) = "
                        << result.planned_iterations << " iterations for N = " << dimension
                        << ", assumed M = " << request.assumed_solution_count
                        << "; one measurement per run, classical verification, up to "
                        << request.max_attempts << " runs";
            for (std::size_t attempt_index = 0U; attempt_index < request.max_attempts; ++attempt_index)
            {
                GroverAttempt attempt = execute_circuit(
                    request, marked, result.planned_iterations, generator(), result);
                if (verify(attempt)) break;
            }
            if (!result.found && request.fall_back_to_unknown_count)
            {
                description << "; then the unknown-solution-count schedule";
                run_unknown_schedule = true;
            }
        }

        if (!result.found && run_unknown_schedule)
        {
            // Boyer, Brassard, Hoyer, Tapp (1998): choose the iteration count uniformly
            // below a bound m that grows by lambda = 6/5 and is capped at sqrt(N).
            constexpr double lambda = 6.0 / 5.0;
            const double root = std::sqrt(space);
            const double timeout = std::max(1.0, request.unknown_count_timeout_factor) * root;
            if (request.strategy == GroverStrategy::UnknownSolutionCount)
            {
                description << "Unknown-solution-count Grover (Boyer-Brassard-Hoyer-Tapp): iteration count "
                               "drawn uniformly from [0, m), m multiplied by 6/5 after each failure and capped "
                               "at sqrt(N) = " << root << "; time-out after " << timeout
                            << " Grover iterations";
            }
            double bound = 1.0;
            std::uint64_t schedule_iterations = 0U;
            constexpr std::size_t hard_attempt_limit = 4096U;
            for (std::size_t attempt_index = 0U; attempt_index < hard_attempt_limit; ++attempt_index)
            {
                const auto exclusive_upper = static_cast<std::uint64_t>(std::ceil(bound));
                std::uniform_int_distribution<std::uint64_t> distribution(
                    0U, exclusive_upper == 0U ? 0U : exclusive_upper - 1U);
                const std::uint64_t iterations = distribution(generator);
                GroverAttempt attempt = execute_circuit(request, marked, iterations, generator(), result);
                schedule_iterations += iterations;
                if (verify(attempt)) break;
                if (bound >= root && static_cast<double>(schedule_iterations) > timeout)
                {
                    result.failure_reason =
                        "The unknown-solution-count schedule timed out without a verified candidate; "
                        "the searched domain may contain no solution.";
                    break;
                }
                bound = std::min(lambda * bound, root);
            }
            if (!result.found && result.failure_reason.empty())
                result.failure_reason = "The attempt limit was reached without a verified candidate.";
        }

        if (!result.found && result.failure_reason.empty())
            result.failure_reason = "No measured candidate passed classical verification.";
        result.strategy_description = description.str();
        return result;
    }
}
