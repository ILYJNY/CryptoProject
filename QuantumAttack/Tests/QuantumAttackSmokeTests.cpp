#include "../Standard/Core/QuantumSimulator.h"
#include "../Standard/Algorithms/QuantumAlgorithms.h"
#include "../Benchmark/QftBenchmark.h"
#include "../Benchmark/AlgorithmBenchmark.h"

#include <cmath>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace
{
    void require(const bool condition, const char* message)
    {
        if (!condition) throw std::runtime_error(message);
    }

    void compare_states(
        const std::vector<crypto::quantum::Complex>& left,
        const std::vector<crypto::quantum::Complex>& right,
        const double tolerance = 1e-10)
    {
        require(left.size() == right.size(), "State-vector sizes do not match.");
        for (std::size_t index = 0U; index < left.size(); ++index)
            require(std::abs(left[index] - right[index]) <= tolerance, "CPU backend results do not match.");
    }
}

int main()
{
    try
    {
        using namespace crypto::quantum;
        QuantumExecutionOptions single_options;
        single_options.backend = QuantumBackendType::CpuSingleThread;
        QuantumExecutionOptions multi_options;
        multi_options.backend = QuantumBackendType::CpuMultiThread;
        multi_options.cpu_threads = 4U;

        QuantumSimulator single(13U, 22U, single_options);
        QuantumSimulator multi(13U, 22U, multi_options);
        for (std::size_t qubit = 0U; qubit < 13U; ++qubit)
        {
            single.apply_hadamard(qubit);
            multi.apply_hadamard(qubit);
        }
        single.apply_cnot(0U, 4U);
        multi.apply_cnot(0U, 4U);
        single.apply_phase_flip(7U);
        multi.apply_phase_flip(7U);
        single.apply_diffusion();
        multi.apply_diffusion();
        compare_states(single.state(), multi.state());

        const auto grover = run_grover_experiment(3U, 5U, 1024U, multi_options);
        require(grover.passed, "CPU multi-thread Grover experiment did not pass.");
        require(grover.backend == "CPU-MULTI", "Backend label was not propagated to the experiment result.");

        const auto qft = run_qft_experiment(3U, multi_options);
        require(qft.passed, "CPU multi-thread QFT experiment did not pass.");

        const auto shor = run_shor_toy_experiment(15U, 2U, 1024U, multi_options);
        require(shor.factored, "The small educational Shor experiment did not recover its factors.");

        QftBenchmarkOptions benchmark_options;
        benchmark_options.qubit_counts = {2U, 3U};
        benchmark_options.repeats = 2U;
        benchmark_options.warmup_runs = 0U;
        benchmark_options.max_state_vector_bytes = 1024U * 1024U;
        benchmark_options.include_cpu_backends = true;
        benchmark_options.include_cuda_backends = false;
        benchmark_options.cpu_threads = 2U;
        const auto benchmark_results = run_qft_benchmark(benchmark_options);
        require(benchmark_results.size() == 4U, "QFT benchmark did not create one row per CPU backend and size.");
        for (const auto& result : benchmark_results)
        {
            require(result.status == "OK", "A CPU QFT benchmark row did not complete successfully.");
            require(result.successful_runs == 2U, "QFT benchmark repeat count was not honored.");
            require(result.qft.mean_ms > 0.0, "QFT benchmark did not record a positive elapsed time.");
            require(result.maximum_norm_error <= 1e-8, "QFT benchmark norm validation failed.");
        }

        AlgorithmBenchmarkOptions algorithm_options;
        algorithm_options.qubit_counts = {2U, 3U};
        algorithm_options.repeats = 1U;
        algorithm_options.warmup_runs = 0U;
        algorithm_options.shots = 128U;
        algorithm_options.max_state_vector_bytes = 1024U * 1024U;
        algorithm_options.include_cpu_backends = true;
        algorithm_options.include_cuda_backends = false;
        algorithm_options.cpu_threads = 2U;
        const auto algorithm_results = run_algorithm_benchmark(algorithm_options);
        require(algorithm_results.size() == 10U,
                "Integrated algorithm benchmark did not create Grover, QFT, and toy Shor rows.");
        for (const auto& result : algorithm_results)
        {
            require(result.status == "OK", "An integrated CPU algorithm benchmark row failed.");
            require(result.successful_runs == 1U, "Integrated algorithm benchmark repeat count was not honored.");
            require(result.mean_ms > 0.0, "Integrated algorithm benchmark did not record elapsed time.");
        }

        QftBenchmarkOptions limited_benchmark;
        limited_benchmark.qubit_counts = {8U};
        limited_benchmark.repeats = 1U;
        limited_benchmark.warmup_runs = 0U;
        limited_benchmark.max_state_vector_bytes = 1U;
        limited_benchmark.include_cpu_backends = true;
        limited_benchmark.include_cuda_backends = false;
        const auto skipped_benchmark = run_qft_benchmark(limited_benchmark);
        require(skipped_benchmark.size() == 2U, "Memory-limited QFT benchmark returned an unexpected row count.");
        require(skipped_benchmark.front().status == "SKIPPED-MEMORY",
                "QFT benchmark did not honor the configured state-vector memory limit.");

        if (!cuda_backend::CUDAQuantumBackend::is_available())
        {
            QuantumExecutionOptions gpu_options;
            gpu_options.backend = QuantumBackendType::CudaGpu;
            bool rejected_unavailable_gpu = false;
            try { QuantumSimulator unavailable_gpu(2U, 22U, gpu_options); }
            catch (const std::runtime_error&) { rejected_unavailable_gpu = true; }
            require(rejected_unavailable_gpu, "The unavailable GPU backend was not reported clearly.");
        }
        else
        {
            QuantumExecutionOptions gpu_options;
            gpu_options.backend = QuantumBackendType::CudaGpu;
            QuantumSimulator cpu_qft(5U, 22U, single_options);
            QuantumSimulator gpu_qft(5U, 22U, gpu_options);
            for (QuantumSimulator* simulator : {&cpu_qft, &gpu_qft})
            {
                simulator->apply_hadamard(0U);
                simulator->apply_hadamard(3U);
                simulator->apply_cnot(0U, 2U);
                simulator->apply_qft({0U, 2U, 4U});
            }
            compare_states(cpu_qft.state(), gpu_qft.state(), 1e-9);
            require(gpu_qft.backend_statistics().gpu_qft_fused_stage_count == 3U,
                    "Single-GPU QFT fused-stage count was not recorded.");
            require(gpu_qft.backend_statistics().gpu_qft_swap_count == 1U,
                    "Single-GPU QFT swap count was not recorded.");
        }

        if (cuda_backend::CUDAMultiGpuQuantumBackend::is_available())
        {
            QuantumExecutionOptions distributed_options;
            distributed_options.backend = QuantumBackendType::CudaMultiGpu;
            distributed_options.gpu_devices = {0, 1};
            QuantumSimulator distributed(5U, 22U, distributed_options);
            distributed.apply_hadamard(4U); // Distributed qubit for two devices.
            distributed.apply_hadamard(0U); // Local qubit.
            distributed.apply_cnot(0U, 4U); // Distributed target.
            distributed.apply_z(4U);
            distributed.apply_diffusion();

            QuantumSimulator cpu_distributed_reference(5U, 22U, single_options);
            cpu_distributed_reference.apply_hadamard(4U);
            cpu_distributed_reference.apply_hadamard(0U);
            cpu_distributed_reference.apply_cnot(0U, 4U);
            cpu_distributed_reference.apply_z(4U);
            cpu_distributed_reference.apply_diffusion();
            const std::vector<std::size_t> mixed_qft_targets{0U, 1U, 2U, 4U};
            distributed.apply_qft(mixed_qft_targets);
            cpu_distributed_reference.apply_qft(mixed_qft_targets);
            compare_states(cpu_distributed_reference.state(), distributed.state(), 1e-9);
            require(distributed.backend_statistics().gpu_qft_fused_stage_count == mixed_qft_targets.size(),
                    "Multi-GPU QFT fused-stage count was not recorded.");
            require(distributed.backend_statistics().gpu_qft_swap_count == 2U,
                    "Multi-GPU QFT swap count was not recorded.");

            require(distributed.state().size() == 32U, "Multi-GPU state-vector size changed unexpectedly.");
            require(distributed.backend_statistics().gpu_devices_used.size() == 2U,
                    "Multi-GPU device selection was not recorded.");

            const std::vector<int> available_devices = cuda_backend::CUDAMultiGpuQuantumBackend::available_devices();
            if (available_devices.size() >= 4U)
            {
                QuantumExecutionOptions four_gpu_options;
                four_gpu_options.backend = QuantumBackendType::CudaMultiGpu;
                four_gpu_options.gpu_devices = {available_devices[0], available_devices[1],
                                                 available_devices[2], available_devices[3]};
                QuantumSimulator cpu_dist_dist_qft(5U, 22U, single_options);
                QuantumSimulator four_gpu_qft(5U, 22U, four_gpu_options);
                cpu_dist_dist_qft.apply_hadamard(3U);
                cpu_dist_dist_qft.apply_hadamard(4U);
                four_gpu_qft.apply_hadamard(3U);
                four_gpu_qft.apply_hadamard(4U);
                const std::vector<std::size_t> distributed_pair_targets{3U, 4U};
                cpu_dist_dist_qft.apply_qft(distributed_pair_targets);
                four_gpu_qft.apply_qft(distributed_pair_targets);
                compare_states(cpu_dist_dist_qft.state(), four_gpu_qft.state(), 1e-9);
            }
        }

        std::cout << "QuantumAttack smoke tests passed.\n";
        return EXIT_SUCCESS;
    }
    catch (const std::exception& exception)
    {
        std::cerr << "QuantumAttack smoke test failed: " << exception.what() << '\n';
        return EXIT_FAILURE;
    }
}
