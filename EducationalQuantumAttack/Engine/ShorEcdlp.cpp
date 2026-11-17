#include "ShorEcdlp.h"

#include "EducationalQuantumAttack/Common/QuantumAttackSupport.h"
#include "EducationalQuantumAttack/Engine/PhaseEstimationEngine.h"

#include <cmath>
#include <stdexcept>
#include <unordered_map>

namespace crypto::educational_quantum_attack
{
    namespace
    {
        // A canonical key for a curve point, used to map coordinates to a register index.
        [[nodiscard]] std::uint64_t point_key(const educational::ToyEccPoint& point)
        {
            if (point.infinity) return 1ULL << 40U;
            return (static_cast<std::uint64_t>(point.x) << 20U) | static_cast<std::uint64_t>(point.y);
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

        // Enumerates <G> by repeated addition (coordinate arithmetic only) and returns the
        // point list indexed 0..r-1 together with a coordinate->index map. The enumeration
        // computes multiples of G to lay out the state space; the attack itself never uses
        // the secret, and every translation is recomputed from coordinates.
        struct PointTable
        {
            std::vector<educational::ToyEccPoint> points;        // index -> point
            std::unordered_map<std::uint64_t, std::size_t> index; // point key -> index
            std::size_t index_of(const educational::ToyEccPoint& point) const
            {
                const auto found = index.find(point_key(point));
                return found == index.end() ? 0U : found->second;
            }
        };

        [[nodiscard]] PointTable build_point_table(
            const educational::ToyEccPoint& generator, const std::uint32_t order)
        {
            PointTable table;
            table.points.resize(order);
            educational::ToyEccPoint running{};
            for (std::uint32_t step = 0; step < order; ++step)
            {
                running = educational::toy_ecc_add(running, generator); // running = (step+1) * G
                table.points[step] = running;
                table.index.emplace(point_key(running), step);
            }
            return table;
        }

        // Builds the controlled-power provider for "+S": index x (point P_x) maps to the
        // index of P_x + (2^power) * S, computed by coordinate arithmetic.
        [[nodiscard]] PhaseEstimationStage translation_stage(
            const char* label, const educational::ToyEccPoint& summand,
            const PointTable& table, const std::size_t register_qubits)
        {
            PhaseEstimationStage stage;
            stage.bits = 2U * register_qubits;
            stage.label = label;
            stage.controlled_power = [summand, &table](const std::size_t power, std::vector<std::size_t>& permutation)
            {
                const educational::ToyEccPoint multiple =
                    educational::toy_ecc_multiply(static_cast<std::uint32_t>(1U) << power, summand);
                for (std::size_t x = 0; x < permutation.size(); ++x)
                {
                    permutation[x] = x < table.points.size()
                        ? table.index_of(educational::toy_ecc_add(table.points[x], multiple))
                        : x;
                }
            };
            return stage;
        }

        // The integer k in [1, order) whose multiple of y_generator best matches y_public,
        // on the circular scale of 2^phase_bits.
        [[nodiscard]] std::uint32_t best_scalar(
            const std::uint64_t phase_generator, const std::uint64_t phase_public,
            const std::size_t phase_bits, const std::uint32_t order)
        {
            if (phase_generator == 0U) return 0U;
            const std::uint64_t modulus = std::uint64_t{1} << phase_bits;
            std::uint32_t best = 0U;
            long double best_distance = 1.0e30L;
            for (std::uint32_t candidate = 1U; candidate < order; ++candidate)
            {
                const std::uint64_t predicted = (static_cast<std::uint64_t>(candidate) * phase_generator) % modulus;
                long double distance = std::fabs(static_cast<long double>(predicted) - static_cast<long double>(phase_public));
                distance = std::min(distance, static_cast<long double>(modulus) - distance);
                if (distance < best_distance)
                {
                    best_distance = distance;
                    best = candidate;
                }
            }
            return best;
        }
    }

    ShorEcdlpResult run_shor_ecdlp(
        const educational::ToyEccPublicInstance& instance, const ShorEcdlpOptions& options)
    {
        const educational::ToyEccCurveParameters curve = educational::toy_ecc_curve_parameters();
        const educational::ToyEccPoint generator = educational::toy_ecc_base_point();
        const educational::ToyEccPoint public_point{instance.public_x, instance.public_y, false};

        ShorEcdlpResult result;
        result.field_prime = curve.field_prime;
        result.coefficient_a = curve.coefficient_a;
        result.coefficient_b = curve.coefficient_b;
        result.base_x = curve.base_x;
        result.base_y = curve.base_y;
        result.base_point_order = curve.base_point_order;
        result.public_x = instance.public_x;
        result.public_y = instance.public_y;
        result.register_qubits = ceil_log2(curve.base_point_order);
        result.total_qubits = result.register_qubits + 1U;
        result.phase_bits = 2U * result.register_qubits;

        if (!educational::toy_ecc_is_on_curve(public_point))
        {
            result.executed = false;
            result.status = "NOT EXECUTED (the public point is not on the curve)";
            result.failure_reason = "The supplied public point does not satisfy the curve equation.";
            return result;
        }
        if (result.total_qubits > options.qubit_budget)
        {
            result.executed = false;
            result.status = "NOT EXECUTED (circuit exceeds the simulation budget)";
            result.failure_reason = "The ECDLP circuit needs " + std::to_string(result.total_qubits) +
                " qubits, above the configured budget of " + std::to_string(options.qubit_budget) + " qubits.";
            return result;
        }
        result.executed = true;

        const Stopwatch table_timer;
        const PointTable table = build_point_table(generator, curve.base_point_order);
        result.permutation_table_ms += table_timer.elapsed_ms();
        result.point_table_size = table.points.size();
        const std::size_t generator_index = table.index_of(generator);

        for (std::size_t shot = 0; shot < options.max_shots && !result.recovered; ++shot)
        {
            PhaseEstimationRequest request;
            request.work_qubits = result.register_qubits;
            request.initial_work_state = generator_index;
            request.execution = options.execution;
            request.simulator_qubit_limit = options.qubit_budget;
            request.seed = options.seed + 101U * shot;
            request.stages = {
                translation_stage("controlled translation by 2^j * G", generator, table, result.register_qubits),
                translation_stage("controlled translation by 2^j * Q", public_point, table, result.register_qubits)};

            const PhaseEstimationResult run = run_iterative_phase_estimation(request);
            result.total_simulator_ms += run.simulation_wall_ms;
            result.permutation_table_ms += run.permutation_table_ms;
            result.controlled_point_additions += run.controlled_permutations;
            result.measurements += run.measurements;
            result.simulator_gate_operations += run.simulator_gate_count;
            result.state_vector_bytes = run.state_vector_bytes;
            accumulate_backend(result.backend, run.backend);

            ShorEcdlpAttempt attempt;
            attempt.phase_generator = run.phase_integers.at(0);
            attempt.phase_public = run.phase_integers.at(1);
            attempt.simulator_ms = run.simulation_wall_ms;
            const std::uint32_t candidate =
                best_scalar(attempt.phase_generator, attempt.phase_public, result.phase_bits, curve.base_point_order);
            attempt.candidate_scalar = candidate;
            // Honest verification by coordinate arithmetic: candidate * G must equal Q.
            attempt.verified = candidate != 0U &&
                educational::toy_ecc_multiply(candidate, generator) == public_point;
            result.attempts.push_back(attempt);
            if (attempt.verified)
            {
                result.recovered = true;
                result.recovered_scalar = candidate;
                result.status = "RECOVERED the discrete logarithm by quantum phase estimation";
            }
        }

        if (!result.recovered)
        {
            result.status = "NOT RECOVERED within the shot budget";
            result.failure_reason =
                "No measured phase pair yielded a scalar k with k*G = Q. Phase estimation is "
                "probabilistic; more shots may succeed.";
        }
        return result;
    }

    ShorEcdlpSingleRun run_shor_ecdlp_single_circuit(
        const educational::ToyEccPublicInstance& instance,
        const quantum::QuantumExecutionOptions& execution,
        const std::uint64_t seed, const std::size_t qubit_budget)
    {
        const educational::ToyEccCurveParameters curve = educational::toy_ecc_curve_parameters();
        const educational::ToyEccPoint generator = educational::toy_ecc_base_point();
        const educational::ToyEccPoint public_point{instance.public_x, instance.public_y, false};
        const std::size_t register_qubits = ceil_log2(curve.base_point_order);

        const PointTable table = build_point_table(generator, curve.base_point_order);
        PhaseEstimationRequest request;
        request.work_qubits = register_qubits;
        request.initial_work_state = table.index_of(generator);
        request.execution = execution;
        request.simulator_qubit_limit = qubit_budget;
        request.seed = seed;
        request.stages = {
            translation_stage("controlled translation by 2^j * G", generator, table, register_qubits),
            translation_stage("controlled translation by 2^j * Q", public_point, table, register_qubits)};

        const PhaseEstimationResult run = run_iterative_phase_estimation(request);
        ShorEcdlpSingleRun single;
        single.phase_generator = run.phase_integers.at(0);
        single.phase_public = run.phase_integers.at(1);
        single.simulator_ms = run.simulation_wall_ms;
        single.total_qubits = run.qubits;
        single.backend = run.backend;
        return single;
    }
}
