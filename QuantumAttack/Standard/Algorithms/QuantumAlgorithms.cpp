#include "QuantumAlgorithms.h"

#include "../Core/QuantumSimulator.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <numeric>
#include <numbers>
#include <sstream>
#include <stdexcept>

namespace crypto::quantum
{
    namespace
    {
        using Clock = std::chrono::steady_clock;

        [[nodiscard]] double elapsed_ms(const Clock::time_point start)
        {
            return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
        }

        [[nodiscard]] const char* backend_name(const QuantumBackendType backend)
        {
            switch (backend)
            {
                case QuantumBackendType::CpuSingleThread: return "CPU-SINGLE";
                case QuantumBackendType::CpuMultiThread: return "CPU-MULTI";
                case QuantumBackendType::CudaGpu: return "CUDA-GPU";
                case QuantumBackendType::CudaMultiGpu: return "CUDA-MULTI-GPU";
            }
            return "UNKNOWN";
        }

        void fill_common(ExperimentResult& result, const QuantumSimulator& simulator,
                         const Clock::time_point start)
        {
            result.qubits = simulator.qubit_count();
            result.gate_count = simulator.gate_count();
            result.operation_depth = simulator.operation_depth();
            result.state_vector_bytes = simulator.state_vector_bytes();
            result.elapsed_ms = elapsed_ms(start);
            result.probabilities = simulator.probabilities();
            result.backend = backend_name(simulator.execution_options().backend);
            const auto& metrics = simulator.backend_statistics();
            result.cpu_threads = metrics.cpu_threads_used;
            result.cpu_operations = static_cast<std::size_t>(metrics.cpu_operations);
            result.gpu_operations = static_cast<std::size_t>(metrics.gpu_operations);
            result.cpu_fallback_operations = static_cast<std::size_t>(metrics.cpu_fallback_operations);
            result.cpu_wall_time_ms = metrics.cpu_wall_time_ms;
            result.gpu_kernel_time_ms = metrics.gpu_kernel_time_ms;
            result.gpu_transfer_time_ms = metrics.gpu_transfer_time_ms;
            result.gpu_initialization_time_ms = metrics.gpu_initialization_time_ms;
            result.gpu_device = metrics.gpu_device_used;
            result.gpu_devices = metrics.gpu_devices_used;
            result.gpu_inter_gpu_transfer_time_ms = metrics.gpu_inter_gpu_transfer_time_ms;
            result.gpu_parallel_kernel_wall_time_ms = metrics.gpu_parallel_kernel_wall_time_ms;
            result.gpu_peer_copy_count = static_cast<std::size_t>(metrics.gpu_peer_copy_count);
            result.gpu_host_staged_copy_count = static_cast<std::size_t>(metrics.gpu_host_staged_copy_count);
            result.gpu_qft_fused_stage_count = static_cast<std::size_t>(metrics.gpu_qft_fused_stage_count);
            result.gpu_qft_swap_count = static_cast<std::size_t>(metrics.gpu_qft_swap_count);
            result.gpu_pinned_host_memory_used = metrics.gpu_pinned_host_memory_used;
        }

        void fill_shor_backend_metrics(ShorToyResult& result, const QuantumSimulator& simulator)
        {
            const auto& metrics = simulator.backend_statistics();
            result.backend = backend_name(simulator.execution_options().backend);
            result.cpu_threads = metrics.cpu_threads_used;
            result.cpu_operations = static_cast<std::size_t>(metrics.cpu_operations);
            result.gpu_operations = static_cast<std::size_t>(metrics.gpu_operations);
            result.cpu_fallback_operations = static_cast<std::size_t>(metrics.cpu_fallback_operations);
            result.cpu_wall_time_ms = metrics.cpu_wall_time_ms;
            result.gpu_kernel_time_ms = metrics.gpu_kernel_time_ms;
            result.gpu_transfer_time_ms = metrics.gpu_transfer_time_ms;
            result.gpu_initialization_time_ms = metrics.gpu_initialization_time_ms;
            result.gpu_device = metrics.gpu_device_used;
            result.gpu_devices = metrics.gpu_devices_used;
            result.gpu_inter_gpu_transfer_time_ms = metrics.gpu_inter_gpu_transfer_time_ms;
            result.gpu_parallel_kernel_wall_time_ms = metrics.gpu_parallel_kernel_wall_time_ms;
            result.gpu_peer_copy_count = static_cast<std::size_t>(metrics.gpu_peer_copy_count);
            result.gpu_host_staged_copy_count = static_cast<std::size_t>(metrics.gpu_host_staged_copy_count);
            result.gpu_qft_fused_stage_count = static_cast<std::size_t>(metrics.gpu_qft_fused_stage_count);
            result.gpu_qft_swap_count = static_cast<std::size_t>(metrics.gpu_qft_swap_count);
            result.gpu_pinned_host_memory_used = metrics.gpu_pinned_host_memory_used;
        }

        [[nodiscard]] std::uint32_t modular_power(
            std::uint32_t base, std::uint32_t exponent, const std::uint32_t modulus)
        {
            std::uint64_t result = 1U;
            std::uint64_t value = base % modulus;
            while (exponent > 0U)
            {
                if ((exponent & 1U) != 0U) result = (result * value) % modulus;
                exponent >>= 1U;
                value = (value * value) % modulus;
            }
            return static_cast<std::uint32_t>(result);
        }

        [[nodiscard]] std::size_t ceil_log2(const std::uint32_t value)
        {
            std::size_t bits = 0U;
            std::uint32_t current = 1U;
            while (current < value)
            {
                current <<= 1U;
                ++bits;
            }
            return std::max<std::size_t>(1U, bits);
        }

        [[nodiscard]] std::uint32_t gcd_u32(std::uint32_t left, std::uint32_t right)
        {
            while (right != 0U)
            {
                const std::uint32_t remainder = left % right;
                left = right;
                right = remainder;
            }
            return left;
        }

        [[nodiscard]] std::uint32_t find_period_candidate(
            const std::uint32_t measured, const std::size_t counting_dimension,
            const std::uint32_t base, const std::uint32_t modulus)
        {
            if (measured == 0U) return 0U;
            const double phase = static_cast<double>(measured) /
                                 static_cast<double>(counting_dimension);
            for (std::uint32_t denominator = 1U; denominator < modulus; ++denominator)
            {
                const auto numerator = static_cast<std::uint32_t>(
                    std::llround(phase * static_cast<double>(denominator)));
                const double approximation = static_cast<double>(numerator) /
                                              static_cast<double>(denominator);
                const double tolerance = 1.0 /
                                         (2.0 * static_cast<double>(counting_dimension));
                if (std::abs(phase - approximation) <= tolerance &&
                    modular_power(base, denominator, modulus) == 1U)
                {
                    return denominator;
                }
            }
            return 0U;
        }

        [[nodiscard]] bool extract_factors(const std::uint32_t number,
                                           const std::uint32_t base,
                                           const std::uint32_t order,
                                           std::uint32_t& first,
                                           std::uint32_t& second)
        {
            if (order == 0U || (order & 1U) != 0U) return false;
            const std::uint32_t midpoint = modular_power(base, order / 2U, number);
            if (midpoint == number - 1U || midpoint == 1U) return false;
            first = gcd_u32(midpoint - 1U, number);
            second = gcd_u32(midpoint + 1U, number);
            return first > 1U && second > 1U && first * second == number;
        }
    }

    ExperimentResult run_superposition_experiment(const QuantumExecutionOptions& options)
    {
        const auto start = Clock::now();
        QuantumSimulator simulator(1U, 22U, options);
        simulator.apply_hadamard(0U);
        const auto probabilities = simulator.probabilities();
        ExperimentResult result;
        result.name = "Superposition";
        result.summary = "Hadamard gate creates equal probability amplitudes for |0> and |1>.";
        result.passed = probabilities.size() == 2U &&
                        std::abs(probabilities[0] - 0.5) < 1e-9 &&
                        std::abs(probabilities[1] - 0.5) < 1e-9;
        fill_common(result, simulator, start);
        return result;
    }

    ExperimentResult run_entanglement_experiment(const QuantumExecutionOptions& options)
    {
        const auto start = Clock::now();
        QuantumSimulator simulator(2U, 22U, options);
        simulator.apply_hadamard(0U);
        simulator.apply_cnot(0U, 1U);
        const auto probabilities = simulator.probabilities();
        ExperimentResult result;
        result.name = "Entanglement";
        result.summary = "A Bell state is prepared; only |00> and |11> have non-zero probability.";
        result.passed = probabilities.size() == 4U &&
                        std::abs(probabilities[0] - 0.5) < 1e-9 &&
                        std::abs(probabilities[3] - 0.5) < 1e-9 &&
                        probabilities[1] < 1e-9 && probabilities[2] < 1e-9;
        fill_common(result, simulator, start);
        return result;
    }

    ExperimentResult run_interference_experiment(const QuantumExecutionOptions& options)
    {
        const auto start = Clock::now();
        QuantumSimulator simulator(1U, 22U, options);
        simulator.apply_hadamard(0U);
        simulator.apply_z(0U);
        simulator.apply_hadamard(0U);
        const auto probabilities = simulator.probabilities();
        ExperimentResult result;
        result.name = "Quantum Interference";
        result.summary = "The phase change causes constructive interference at |1> and cancellation at |0>.";
        result.passed = probabilities.size() == 2U && probabilities[0] < 1e-9 &&
                        std::abs(probabilities[1] - 1.0) < 1e-9;
        fill_common(result, simulator, start);
        return result;
    }

    ExperimentResult run_measurement_experiment(const std::size_t shots, const QuantumExecutionOptions& options)
    {
        const auto start = Clock::now();
        QuantumSimulator simulator(1U, 22U, options);
        simulator.apply_hadamard(0U);
        const auto measurements = simulator.measure_all(shots, 0x51A7EULL);
        const std::size_t zero = measurements.counts.contains("0") ? measurements.counts.at("0") : 0U;
        const std::size_t one = measurements.counts.contains("1") ? measurements.counts.at("1") : 0U;
        ExperimentResult result;
        result.name = "Quantum Measurement";
        result.summary = "Repeated measurements sample the Born-rule probabilities; this run is reproducible.";
        result.passed = zero + one == shots && zero > 0U && one > 0U;
        fill_common(result, simulator, start);
        return result;
    }

    ExperimentResult run_grover_experiment(const std::size_t qubits,
                                           const std::size_t target,
                                           const std::size_t shots,
                                           const QuantumExecutionOptions& options)
    {
        if (qubits == 0U || qubits > 12U)
            throw std::invalid_argument("The Grover learning experiment supports 1 to 12 qubits.");
        const std::size_t dimension = std::size_t{1} << qubits;
        if (target >= dimension) throw std::invalid_argument("The Grover target is outside the search space.");
        const auto start = Clock::now();
        QuantumSimulator simulator(qubits, 22U, options);
        for (std::size_t bit = 0; bit < qubits; ++bit) simulator.apply_hadamard(bit);
        const std::size_t iterations = std::max<std::size_t>(
            std::size_t{1}, static_cast<std::size_t>(std::llround(
                std::numbers::pi / 4.0 * std::sqrt(static_cast<double>(dimension)))));
        for (std::size_t iteration = 0; iteration < iterations; ++iteration)
        {
            simulator.apply_phase_flip(target);
            simulator.apply_diffusion();
        }
        const auto measurements = simulator.measure_all(shots, 0x6A0B3ULL);
        const std::string target_label = [&]()
        {
            std::string value(qubits, '0');
            for (std::size_t bit = 0; bit < qubits; ++bit)
                if ((target & (std::size_t{1} << bit)) != 0U) value[qubits - bit - 1U] = '1';
            return value;
        }();
        const auto target_count = measurements.counts.contains(target_label)
            ? measurements.counts.at(target_label) : 0U;
        ExperimentResult result;
        result.name = "Grover Search";
        result.summary = "A marked item is amplified in a small, self-contained search space; target=" + target_label +
                         ", iterations=" + std::to_string(iterations) +
                         ", observed target shots=" + std::to_string(target_count) + "/" + std::to_string(shots) + ".";
        result.passed = target_count > shots / 2U;
        fill_common(result, simulator, start);
        return result;
    }

    ExperimentResult run_qft_experiment(const std::size_t qubits, const QuantumExecutionOptions& options)
    {
        if (qubits == 0U || qubits > 10U)
            throw std::invalid_argument("The QFT learning experiment supports 1 to 10 qubits.");
        const auto start = Clock::now();
        QuantumSimulator simulator(qubits, 22U, options);
        const std::size_t basis = std::min<std::size_t>(3U, (std::size_t{1} << qubits) - 1U);
        simulator.set_basis_state(basis);
        std::vector<std::size_t> targets(qubits);
        std::iota(targets.begin(), targets.end(), 0U);
        simulator.apply_qft(targets);
        const auto probabilities = simulator.probabilities();
        const double expected = 1.0 / static_cast<double>(probabilities.size());
        const bool uniform = std::all_of(probabilities.begin(), probabilities.end(),
            [expected](const double value) { return std::abs(value - expected) < 1e-8; });
        ExperimentResult result;
        result.name = "Quantum Fourier Transform";
        result.summary = "The QFT maps a computational-basis state to a state with uniform measurement probabilities.";
        result.passed = uniform;
        fill_common(result, simulator, start);
        return result;
    }

    ShorToyResult run_shor_toy_experiment(const std::uint32_t number,
                                          const std::uint32_t base,
                                          const std::size_t shots,
                                          const QuantumExecutionOptions& options)
    {
        const auto start = Clock::now();
        ShorToyResult result;
        result.input_number = number;
        result.base = base;
        result.shots = shots;
        result.backend = backend_name(options.backend);

        // This implementation is deliberately restricted to tiny toy inputs.
        if (number < 4U || number > 15U || (number % 2U) == 0U || base < 2U || base >= number || shots == 0U)
        {
            result.status = "INPUT_OUTSIDE_TOY_LIMIT";
            result.elapsed_ms = elapsed_ms(start);
            return result;
        }
        const std::uint32_t common = gcd_u32(base, number);
        if (common > 1U)
        {
            result.factored = true;
            result.factor_a = common;
            result.factor_b = number / common;
            result.status = "FACTOR_FOUND_BY_GCD_PRECHECK";
            result.elapsed_ms = elapsed_ms(start);
            return result;
        }

        const std::size_t target_qubits = ceil_log2(number);
        const std::size_t counting_qubits = 2U * target_qubits;
        if (counting_qubits + target_qubits > 20U)
        {
            result.status = "SIMULATOR_RESOURCE_LIMIT";
            result.elapsed_ms = elapsed_ms(start);
            return result;
        }
        result.qubits = counting_qubits + target_qubits;

        QuantumSimulator simulator(result.qubits, 20U, options);
        const std::size_t counting_dimension = std::size_t{1} << counting_qubits;
        simulator.set_basis_state(counting_dimension); // |count=0, target=1>

        for (std::size_t bit = 0; bit < counting_qubits; ++bit)
            simulator.apply_hadamard(bit);

        std::vector<std::size_t> target_register(target_qubits);
        for (std::size_t bit = 0; bit < target_qubits; ++bit)
            target_register[bit] = counting_qubits + bit;

        // Controlled modular multiplication is simulated as a reversible permutation.
        // The target range is tiny by design (N <= 15).
        for (std::size_t control_bit = 0; control_bit < counting_qubits; ++control_bit)
        {
            const std::uint32_t multiplier = modular_power(
                base, static_cast<std::uint32_t>(std::uint64_t{1} << control_bit), number);
            std::vector<std::size_t> permutation(std::size_t{1} << target_qubits);
            for (std::size_t target = 0; target < permutation.size(); ++target)
            {
                permutation[target] = target < number
                    ? (target * static_cast<std::size_t>(multiplier)) % number
                    : target;
            }
            simulator.apply_controlled_permutation(control_bit, target_register, permutation);
        }

        std::vector<std::size_t> counting_targets(counting_qubits);
        std::iota(counting_targets.begin(), counting_targets.end(), 0U);
        simulator.apply_qft(counting_targets);
        const auto measurements = simulator.measure_all(shots, 0x5A0F15ULL);
        fill_shor_backend_metrics(result, simulator);

        std::map<std::uint32_t, std::size_t> count_histogram;
        for (const auto& [label, count] : measurements.counts)
        {
            std::uint32_t measured = 0U;
            for (std::size_t index = 0; index < counting_qubits; ++index)
            {
                if (label[label.size() - index - 1U] == '1') measured |= (1U << index);
            }
            count_histogram[measured] += count;
        }

        std::vector<std::pair<std::uint32_t, std::size_t>> ranked(
            count_histogram.begin(), count_histogram.end());
        std::sort(ranked.begin(), ranked.end(), [](const auto& left, const auto& right)
        {
            return left.second > right.second;
        });

        for (const auto& [measured, ignored_count] : ranked)
        {
            (void)ignored_count;
            const std::uint32_t order = find_period_candidate(
                measured, counting_dimension, base, number);
            if (order == 0U) continue;
            result.recovered_order = order;
            if (extract_factors(number, base, order, result.factor_a, result.factor_b))
            {
                result.factored = true;
                result.status = "TOY_SHOR_ORDER_FINDING_COMPLETED";
                break;
            }
        }
        if (!result.factored && result.status.empty())
            result.status = "PERIOD_NOT_RECOVERED_IN_THIS_SAMPLE";
        result.elapsed_ms = elapsed_ms(start);
        return result;
    }

    std::string format_experiment(const ExperimentResult& result)
    {
        std::ostringstream output;
        output << "Experiment: " << result.name << '\n'
               << "Result: " << (result.passed ? "PASS" : "CHECK") << '\n'
               << result.summary << '\n'
               << "Qubits: " << result.qubits << '\n'
               << "Gate count (model): " << result.gate_count << '\n'
               << "Operation depth (sequential API calls): " << result.operation_depth << '\n'
               << "State-vector memory: " << result.state_vector_bytes << " bytes\n"
               << std::fixed << std::setprecision(3)
               << "Backend: " << result.backend << '\n'
               << "CPU worker-pool size: " << result.cpu_threads << '\n'
               << "CPU operations: " << result.cpu_operations << '\n'
               << "GPU operations: " << result.gpu_operations << '\n'
               << "CPU fallback operations: " << result.cpu_fallback_operations << '\n'
               << std::fixed << std::setprecision(3)
               << "End-to-end time: " << result.elapsed_ms << " ms\n"
               << "CPU wall time: " << result.cpu_wall_time_ms << " ms\n"
               << "GPU kernel time: " << result.gpu_kernel_time_ms << " ms\n"
               << "GPU transfer time: " << result.gpu_transfer_time_ms << " ms\n"
               << "GPU initialization time: " << result.gpu_initialization_time_ms << " ms\n";
        if (!result.gpu_devices.empty())
        {
            output << "GPU devices: ";
            for (std::size_t index = 0U; index < result.gpu_devices.size(); ++index)
            {
                if (index != 0U) output << ',';
                output << result.gpu_devices[index];
            }
            output << '\n'
                   << "Inter-GPU transfer time: " << result.gpu_inter_gpu_transfer_time_ms << " ms\n"
                   << "Parallel GPU kernel wall time: " << result.gpu_parallel_kernel_wall_time_ms << " ms\n"
                   << "Peer copies: " << result.gpu_peer_copy_count << '\n'
                   << "Host-staged copies: " << result.gpu_host_staged_copy_count << '\n';
        }
        output << "Fused QFT stages: " << result.gpu_qft_fused_stage_count << '\n'
               << "QFT swaps: " << result.gpu_qft_swap_count << '\n'
               << "Pinned host staging: " << (result.gpu_pinned_host_memory_used ? "enabled" : "not enabled") << '\n';
        return output.str();
    }

    std::string format_shor_result(const ShorToyResult& result)
    {
        std::ostringstream output;
        output << "Toy Shor experiment\n"
               << "Input number: " << result.input_number << '\n'
               << "Base: " << result.base << '\n'
               << "Status: " << result.status << '\n'
               << "Simulated qubits: " << result.qubits << '\n'
               << "Measurement shots: " << result.shots << '\n';
        if (result.factored)
            output << "Factors: " << result.factor_a << " x " << result.factor_b << '\n';
        if (result.recovered_order != 0U)
            output << "Recovered order candidate: " << result.recovered_order << '\n';
        output << std::fixed << std::setprecision(3)
               << "Backend: " << result.backend << '\n'
               << "CPU worker-pool size: " << result.cpu_threads << '\n'
               << "CPU operations: " << result.cpu_operations << '\n'
               << "GPU operations: " << result.gpu_operations << '\n'
               << "CPU fallback operations: " << result.cpu_fallback_operations << '\n'
               << "End-to-end time: " << result.elapsed_ms << " ms\n"
               << "CPU wall time: " << result.cpu_wall_time_ms << " ms\n"
               << "GPU kernel time: " << result.gpu_kernel_time_ms << " ms\n"
               << "GPU transfer time: " << result.gpu_transfer_time_ms << " ms\n"
               << "GPU initialization time: " << result.gpu_initialization_time_ms << " ms\n";
        if (!result.gpu_devices.empty())
        {
            output << "GPU devices: ";
            for (std::size_t index = 0U; index < result.gpu_devices.size(); ++index)
            {
                if (index != 0U) output << ',';
                output << result.gpu_devices[index];
            }
            output << '\n'
                   << "Inter-GPU transfer time: " << result.gpu_inter_gpu_transfer_time_ms << " ms\n"
                   << "Parallel GPU kernel wall time: " << result.gpu_parallel_kernel_wall_time_ms << " ms\n"
                   << "Peer copies: " << result.gpu_peer_copy_count << '\n'
                   << "Host-staged copies: " << result.gpu_host_staged_copy_count << '\n';
        }
        output << "Fused QFT stages: " << result.gpu_qft_fused_stage_count << '\n'
               << "QFT swaps: " << result.gpu_qft_swap_count << '\n'
               << "Pinned host staging: " << (result.gpu_pinned_host_memory_used ? "enabled" : "not enabled") << '\n'
               << "Limit: this is a small educational state-vector experiment, not a practical cryptographic attack.\n";
        return output.str();
    }
}
