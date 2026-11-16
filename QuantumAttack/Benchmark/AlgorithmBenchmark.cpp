#include "AlgorithmBenchmark.h"

#include "../Backend/CUDA/CUDAMultiGpuQuantumBackend.h"
#include "../Backend/CUDA/CUDAQuantumBackend.h"
#include "../Standard/Algorithms/QuantumAlgorithms.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace crypto::quantum
{
    namespace
    {
        using Clock = std::chrono::steady_clock;

        struct BackendCase
        {
            QuantumExecutionOptions execution;
            std::string name;
            bool available = true;
            std::string unavailable_reason;
        };

        struct Sample
        {
            double elapsed_ms = 0.0;
            double cpu_wall_ms = 0.0;
            double gpu_kernel_ms = 0.0;
            double gpu_transfer_ms = 0.0;
            double gpu_initialization_ms = 0.0;
            double inter_gpu_transfer_ms = 0.0;
            double parallel_kernel_wall_ms = 0.0;
            double norm_error = 0.0;
            double experiment_pass_rate = 0.0;
            std::size_t cpu_threads = 0U;
            std::size_t cpu_operations = 0U;
            std::size_t gpu_operations = 0U;
            std::size_t cpu_fallback_operations = 0U;
            std::size_t gate_count = 0U;
            std::size_t operation_depth = 0U;
            int gpu_device = -1;
            std::vector<int> gpu_devices{};
            bool passed = false;
            std::string detail;
        };

        [[nodiscard]] std::size_t state_bytes(const std::size_t qubits)
        {
            if (qubits == 0U || qubits >= sizeof(std::size_t) * 8U)
                throw std::invalid_argument("Benchmark qubit count is outside the supported size_t range.");
            const std::size_t amplitudes = std::size_t{1} << qubits;
            if (amplitudes > static_cast<std::size_t>(-1) / sizeof(Complex))
                throw std::overflow_error("Benchmark state-vector size overflows size_t.");
            return amplitudes * sizeof(Complex);
        }

        [[nodiscard]] std::vector<BackendCase> backend_cases(const AlgorithmBenchmarkOptions& options)
        {
            std::vector<BackendCase> result;
            if (options.include_cpu_backends)
            {
                BackendCase single;
                single.execution.backend = QuantumBackendType::CpuSingleThread;
                single.execution.cpu_threads = 1U;
                single.name = "CPU-SINGLE";
                result.push_back(single);

                BackendCase multi;
                multi.execution.backend = QuantumBackendType::CpuMultiThread;
                multi.execution.cpu_threads = options.cpu_threads;
                multi.name = "CPU-MULTI";
                result.push_back(multi);
            }
            if (options.include_cuda_backends)
            {
                BackendCase gpu;
                gpu.execution.backend = QuantumBackendType::CudaGpu;
                gpu.execution.gpu_device = options.gpu_device;
                gpu.name = "CUDA-GPU";
                gpu.available = cuda_backend::CUDAQuantumBackend::is_available();
                gpu.unavailable_reason = "Single-GPU backend unavailable (CUDA compiler, driver, or NVIDIA GPU not detected).";
                result.push_back(gpu);

                BackendCase multi_gpu;
                multi_gpu.execution.backend = QuantumBackendType::CudaMultiGpu;
                multi_gpu.execution.gpu_devices = options.gpu_devices;
                multi_gpu.name = "CUDA-MULTI-GPU";
                multi_gpu.available = cuda_backend::CUDAMultiGpuQuantumBackend::is_available();
                multi_gpu.unavailable_reason = "Multi-GPU backend unavailable (at least two usable CUDA devices are required).";
                result.push_back(multi_gpu);
            }
            return result;
        }

        [[nodiscard]] Sample run_one(const BenchmarkAlgorithm algorithm, const std::size_t qubits,
                                     const BackendCase& backend, const AlgorithmBenchmarkOptions& options)
        {
            Sample sample;
            if (algorithm == BenchmarkAlgorithm::Grover)
            {
                const std::size_t dimension = std::size_t{1} << qubits;
                const std::size_t target = std::min<std::size_t>(5U, dimension - 1U);
                const ExperimentResult result = run_grover_experiment(qubits, target, options.shots, backend.execution);
                sample.elapsed_ms = result.elapsed_ms;
                sample.cpu_wall_ms = result.cpu_wall_time_ms;
                sample.gpu_kernel_ms = result.gpu_kernel_time_ms;
                sample.gpu_transfer_ms = result.gpu_transfer_time_ms;
                sample.gpu_initialization_ms = result.gpu_initialization_time_ms;
                sample.inter_gpu_transfer_ms = result.gpu_inter_gpu_transfer_time_ms;
                sample.parallel_kernel_wall_ms = result.gpu_parallel_kernel_wall_time_ms;
                sample.cpu_threads = result.cpu_threads;
                sample.cpu_operations = result.cpu_operations;
                sample.gpu_operations = result.gpu_operations;
                sample.cpu_fallback_operations = result.cpu_fallback_operations;
                sample.gate_count = result.gate_count;
                sample.operation_depth = result.operation_depth;
                sample.gpu_device = result.gpu_device;
                sample.gpu_devices = result.gpu_devices;
                sample.passed = result.passed;
                sample.experiment_pass_rate = result.passed ? 1.0 : 0.0;
                const std::string marker = "observed target shots=";
                const std::size_t marker_pos = result.summary.find(marker);
                if (marker_pos != std::string::npos)
                {
                    const std::size_t value_start = marker_pos + marker.size();
                    const std::size_t slash = result.summary.find('/', value_start);
                    if (slash != std::string::npos)
                    {
                        const std::size_t value_end = result.summary.find_first_of(" .", slash + 1U);
                        const std::size_t observed = static_cast<std::size_t>(std::stoull(
                            result.summary.substr(value_start, slash - value_start)));
                        const std::size_t total = static_cast<std::size_t>(std::stoull(
                            result.summary.substr(slash + 1U, value_end - slash - 1U)));
                        if (total != 0U) sample.experiment_pass_rate = static_cast<double>(observed) / static_cast<double>(total);
                    }
                }
                sample.detail = result.summary;
            }
            else if (algorithm == BenchmarkAlgorithm::Qft)
            {
                const ExperimentResult result = run_qft_experiment(qubits, backend.execution);
                sample.elapsed_ms = result.elapsed_ms;
                sample.cpu_wall_ms = result.cpu_wall_time_ms;
                sample.gpu_kernel_ms = result.gpu_kernel_time_ms;
                sample.gpu_transfer_ms = result.gpu_transfer_time_ms;
                sample.gpu_initialization_ms = result.gpu_initialization_time_ms;
                sample.inter_gpu_transfer_ms = result.gpu_inter_gpu_transfer_time_ms;
                sample.parallel_kernel_wall_ms = result.gpu_parallel_kernel_wall_time_ms;
                sample.cpu_threads = result.cpu_threads;
                sample.cpu_operations = result.cpu_operations;
                sample.gpu_operations = result.gpu_operations;
                sample.cpu_fallback_operations = result.cpu_fallback_operations;
                sample.gate_count = result.gate_count;
                sample.operation_depth = result.operation_depth;
                sample.gpu_device = result.gpu_device;
                sample.gpu_devices = result.gpu_devices;
                sample.passed = result.passed;
                sample.experiment_pass_rate = result.passed ? 1.0 : 0.0;
                sample.detail = result.summary;
            }
            else
            {
                const ShorToyResult result = run_shor_toy_experiment(
                    options.shor_number, options.shor_base, options.shots, backend.execution);
                sample.elapsed_ms = result.elapsed_ms;
                sample.cpu_wall_ms = result.cpu_wall_time_ms;
                sample.gpu_kernel_ms = result.gpu_kernel_time_ms;
                sample.gpu_transfer_ms = result.gpu_transfer_time_ms;
                sample.gpu_initialization_ms = result.gpu_initialization_time_ms;
                sample.inter_gpu_transfer_ms = result.gpu_inter_gpu_transfer_time_ms;
                sample.parallel_kernel_wall_ms = result.gpu_parallel_kernel_wall_time_ms;
                sample.cpu_threads = result.cpu_threads;
                sample.cpu_operations = result.cpu_operations;
                sample.gpu_operations = result.gpu_operations;
                sample.cpu_fallback_operations = result.cpu_fallback_operations;
                sample.gpu_device = result.gpu_device;
                sample.gpu_devices = result.gpu_devices;
                sample.passed = result.factored;
                sample.experiment_pass_rate = result.factored ? 1.0 : 0.0;
                sample.detail = result.status + "; factors=" + std::to_string(result.factor_a)
                    + "x" + std::to_string(result.factor_b) + "; order=" + std::to_string(result.recovered_order);
            }
            return sample;
        }

        [[nodiscard]] double median(std::vector<double> values)
        {
            if (values.empty()) return 0.0;
            std::sort(values.begin(), values.end());
            const std::size_t middle = values.size() / 2U;
            return values.size() % 2U == 0U ? (values[middle - 1U] + values[middle]) / 2.0 : values[middle];
        }

        void summarize(AlgorithmBenchmarkResult& result, const std::vector<double>& values)
        {
            if (values.empty()) return;
            result.minimum_ms = *std::min_element(values.begin(), values.end());
            result.maximum_ms = *std::max_element(values.begin(), values.end());
            result.mean_ms = std::accumulate(values.begin(), values.end(), 0.0) / static_cast<double>(values.size());
            result.median_ms = median(values);
            double squared = 0.0;
            for (const double value : values) squared += (value - result.mean_ms) * (value - result.mean_ms);
            result.standard_deviation_ms = std::sqrt(squared / static_cast<double>(values.size()));
        }

        [[nodiscard]] const char* algorithm_name(const BenchmarkAlgorithm algorithm)
        {
            switch (algorithm)
            {
            case BenchmarkAlgorithm::Grover: return "GROVER";
            case BenchmarkAlgorithm::Qft: return "QFT";
            case BenchmarkAlgorithm::ShorToy: return "SHOR-TOY";
            }
            return "UNKNOWN";
        }

        [[nodiscard]] std::string csv_escape(const std::string& value)
        {
            std::string result = "\"";
            for (const char character : value)
            {
                if (character == '\"') result += "\"\"";
                else result += character;
            }
            result += "\"";
            return result;
        }
    }

    std::vector<AlgorithmBenchmarkResult> run_algorithm_benchmark(const AlgorithmBenchmarkOptions& options)
    {
        if (options.repeats == 0U) throw std::invalid_argument("Algorithm benchmark repeats must be positive.");
        if (options.shots == 0U) throw std::invalid_argument("Algorithm benchmark shots must be positive.");
        if (!options.include_cpu_backends && !options.include_cuda_backends)
            throw std::invalid_argument("At least one backend family must be enabled.");

        const std::vector<BackendCase> backends = backend_cases(options);
        const std::vector<BenchmarkAlgorithm> algorithms{
            BenchmarkAlgorithm::Grover, BenchmarkAlgorithm::Qft, BenchmarkAlgorithm::ShorToy};
        std::vector<AlgorithmBenchmarkResult> output;

        for (const BenchmarkAlgorithm algorithm : algorithms)
        {
            std::vector<std::size_t> sizes;
            if (algorithm == BenchmarkAlgorithm::ShorToy)
            {
                const std::size_t target_qubits = options.shor_number > 1U
                    ? static_cast<std::size_t>(std::ceil(std::log2(static_cast<double>(options.shor_number)))) : 0U;
                sizes.push_back(3U * target_qubits);
            }
            else sizes = options.qubit_counts;

            for (const std::size_t qubits : sizes)
            {
                AlgorithmBenchmarkResult memory_template;
                memory_template.algorithm = algorithm_name(algorithm);
                memory_template.qubits = qubits;
                memory_template.shots = options.shots;
                try { memory_template.state_vector_bytes = state_bytes(qubits); }
                catch (const std::exception&) { memory_template.state_vector_bytes = 0U; }

                for (const BackendCase& backend : backends)
                {
                    AlgorithmBenchmarkResult result = memory_template;
                    result.backend = backend.name;
                    result.requested_runs = options.repeats;
                    if (!backend.available)
                    {
                        result.status = "UNAVAILABLE";
                        result.detail = backend.unavailable_reason;
                        output.push_back(std::move(result));
                        continue;
                    }
                    if (result.state_vector_bytes == 0U || result.state_vector_bytes > options.max_state_vector_bytes)
                    {
                        result.status = "SKIPPED-MEMORY";
                        result.detail = "Estimated state-vector allocation exceeds the configured memory limit.";
                        output.push_back(std::move(result));
                        continue;
                    }
                    if ((algorithm == BenchmarkAlgorithm::Grover && (qubits == 0U || qubits > 12U))
                        || (algorithm == BenchmarkAlgorithm::Qft && (qubits == 0U || qubits > 10U)))
                    {
                        result.status = "SKIPPED-ALGORITHM-LIMIT";
                        result.detail = "Requested size exceeds the educational algorithm's documented qubit limit.";
                        output.push_back(std::move(result));
                        continue;
                    }

                    std::vector<double> elapsed_values, cpu_values, kernel_values, transfer_values,
                        init_values, inter_gpu_values, parallel_values, norm_values;
                    double pass_rate_sum = 0.0;
                    for (std::size_t warmup = 0U; warmup < options.warmup_runs; ++warmup)
                    {
                        try { (void)run_one(algorithm, qubits, backend, options); }
                        catch (...) { /* warm-up failures do not count as measured samples */ }
                    }
                    for (std::size_t repeat = 0U; repeat < options.repeats; ++repeat)
                    {
                        try
                        {
                            const Sample sample = run_one(algorithm, qubits, backend, options);
                            elapsed_values.push_back(sample.elapsed_ms);
                            cpu_values.push_back(sample.cpu_wall_ms);
                            kernel_values.push_back(sample.gpu_kernel_ms);
                            transfer_values.push_back(sample.gpu_transfer_ms);
                            init_values.push_back(sample.gpu_initialization_ms);
                            inter_gpu_values.push_back(sample.inter_gpu_transfer_ms);
                            parallel_values.push_back(sample.parallel_kernel_wall_ms);
                            pass_rate_sum += sample.experiment_pass_rate;
                            result.cpu_threads = sample.cpu_threads;
                            result.cpu_operations += sample.cpu_operations;
                            result.gpu_operations += sample.gpu_operations;
                            result.cpu_fallback_operations += sample.cpu_fallback_operations;
                            result.gate_count += sample.gate_count;
                            result.operation_depth = std::max(result.operation_depth, sample.operation_depth);
                            result.gpu_device = sample.gpu_device;
                            result.gpu_devices = sample.gpu_devices;
                            if (!sample.detail.empty()) result.detail = sample.detail;
                            ++result.successful_runs;
                        }
                        catch (const std::exception& exception)
                        {
                            ++result.failed_runs;
                            result.detail = exception.what();
                        }
                    }
                    summarize(result, elapsed_values);
                    const auto mean = [](const std::vector<double>& values)
                    {
                        return values.empty() ? 0.0
                            : std::accumulate(values.begin(), values.end(), 0.0) / static_cast<double>(values.size());
                    };
                    result.mean_cpu_wall_ms = mean(cpu_values);
                    result.mean_gpu_kernel_ms = mean(kernel_values);
                    result.mean_gpu_transfer_ms = mean(transfer_values);
                    result.mean_gpu_initialization_ms = mean(init_values);
                    result.mean_inter_gpu_transfer_ms = mean(inter_gpu_values);
                    result.mean_parallel_kernel_wall_ms = mean(parallel_values);
                    result.experiment_pass_rate = result.successful_runs == 0U ? 0.0
                        : pass_rate_sum / static_cast<double>(result.successful_runs);
                    result.status = result.successful_runs == 0U ? "FAILED"
                        : (result.failed_runs == 0U ? "OK" : "PARTIAL");
                    output.push_back(std::move(result));
                }
            }
        }
        return output;
    }

    std::string format_algorithm_benchmark_result(const AlgorithmBenchmarkResult& result)
    {
        std::ostringstream out;
        out << result.algorithm << " | " << result.backend << " | " << result.status
            << " | qubits=" << result.qubits << " | runs=" << result.successful_runs << '/' << result.requested_runs
            << std::fixed << std::setprecision(4) << " | mean=" << result.mean_ms << " ms"
            << " | median=" << result.median_ms << " ms | min=" << result.minimum_ms
            << " ms | max=" << result.maximum_ms << " ms | stddev=" << result.standard_deviation_ms
            << " ms | experiment-pass-rate=" << (result.experiment_pass_rate * 100.0) << "%";
        if (!result.detail.empty()) out << " | " << result.detail;
        return out.str();
    }

    std::string export_algorithm_benchmark_csv(const std::vector<AlgorithmBenchmarkResult>& results,
                                                const std::string& file_path)
    {
        const std::filesystem::path path(file_path);
        if (path.has_parent_path()) std::filesystem::create_directories(path.parent_path());
        std::ofstream file(path, std::ios::out | std::ios::trunc);
        if (!file) throw std::runtime_error("Could not open algorithm benchmark CSV output: " + file_path);
        file << "algorithm,backend,status,qubits,state_vector_bytes,requested_runs,successful_runs,failed_runs,shots,"
                "mean_ms,median_ms,min_ms,max_ms,stddev_ms,experiment_pass_rate,cpu_threads,cpu_operations,gpu_operations,"
                "cpu_fallback_operations,gate_count,operation_depth,gpu_device,gpu_devices,cpu_wall_ms,gpu_kernel_ms,"
                "gpu_transfer_ms,gpu_initialization_ms,inter_gpu_transfer_ms,parallel_kernel_wall_ms,detail\n";
        for (const auto& row : results)
        {
            std::ostringstream devices;
            for (std::size_t index = 0U; index < row.gpu_devices.size(); ++index)
            {
                if (index != 0U) devices << ';';
                devices << row.gpu_devices[index];
            }
            file << csv_escape(row.algorithm) << ',' << csv_escape(row.backend) << ',' << csv_escape(row.status) << ','
                 << row.qubits << ',' << row.state_vector_bytes << ',' << row.requested_runs << ','
                 << row.successful_runs << ',' << row.failed_runs << ',' << row.shots << ','
                 << std::setprecision(12) << row.mean_ms << ',' << row.median_ms << ',' << row.minimum_ms << ','
                 << row.maximum_ms << ',' << row.standard_deviation_ms << ',' << row.experiment_pass_rate << ','
                 << row.cpu_threads << ',' << row.cpu_operations << ',' << row.gpu_operations << ','
                 << row.cpu_fallback_operations << ',' << row.gate_count << ',' << row.operation_depth << ','
                 << row.gpu_device << ',' << csv_escape(devices.str()) << ',' << row.mean_cpu_wall_ms << ','
                 << row.mean_gpu_kernel_ms << ',' << row.mean_gpu_transfer_ms << ',' << row.mean_gpu_initialization_ms << ','
                 << row.mean_inter_gpu_transfer_ms << ',' << row.mean_parallel_kernel_wall_ms << ','
                 << csv_escape(row.detail) << '\n';
        }
        if (!file) throw std::runtime_error("Failed while writing algorithm benchmark CSV output: " + file_path);
        return path.string();
    }
}
