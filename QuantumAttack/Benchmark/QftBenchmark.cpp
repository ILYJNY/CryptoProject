#include "QftBenchmark.h"

#include "../Backend/CPU/CPUQuantumBackend.h"
#include "../Backend/CUDA/CUDAMultiGpuQuantumBackend.h"
#include "../Backend/CUDA/CUDAQuantumBackend.h"
#include "../Standard/Core/QuantumSimulator.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
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
            double setup_ms = 0.0;
            double qft_ms = 0.0;
            double result_readback_ms = 0.0;
            double end_to_end_ms = 0.0;
            double validation_ms = 0.0;
            double cpu_wall_ms = 0.0;
            double gpu_kernel_ms = 0.0;
            double gpu_transfer_ms = 0.0;
            double gpu_initialization_ms = 0.0;
            double inter_gpu_transfer_ms = 0.0;
            double parallel_kernel_wall_ms = 0.0;
            double norm_error = 0.0;
            double gpu_peer_copies = 0.0;
            double gpu_host_staged_copies = 0.0;
            double gpu_qft_fused_stages = 0.0;
            double gpu_qft_swaps = 0.0;
            std::size_t gate_count = 0U;
            std::size_t operation_depth = 0U;
            std::size_t cpu_threads_used = 1U;
            int gpu_device_used = -1;
            std::vector<int> gpu_devices_used{};
            bool pinned_host_memory_used = false;
        };

        [[nodiscard]] double milliseconds(const Clock::time_point start)
        {
            return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
        }

        [[nodiscard]] std::size_t state_vector_size_bytes(const std::size_t qubits)
        {
            if (qubits == 0U || qubits >= std::numeric_limits<std::size_t>::digits)
            {
                throw std::invalid_argument("QFT benchmark qubit counts must fit in size_t and be at least one.");
            }
            const std::size_t amplitudes = std::size_t{1} << qubits;
            if (amplitudes > std::numeric_limits<std::size_t>::max() / sizeof(Complex))
            {
                throw std::overflow_error("The requested QFT state-vector size overflows size_t.");
            }
            return amplitudes * sizeof(Complex);
        }

        [[nodiscard]] std::vector<BackendCase> make_backend_cases(const QftBenchmarkOptions& options)
        {
            std::vector<BackendCase> cases;
            if (options.include_cpu_backends)
            {
                BackendCase single;
                single.execution.backend = QuantumBackendType::CpuSingleThread;
                single.execution.cpu_threads = 1U;
                single.name = "CPU-SINGLE";
                cases.push_back(std::move(single));

                BackendCase multi;
                multi.execution.backend = QuantumBackendType::CpuMultiThread;
                multi.execution.cpu_threads = options.cpu_threads;
                multi.name = "CPU-MULTI";
                cases.push_back(std::move(multi));
            }

            if (options.include_cuda_backends)
            {
                BackendCase gpu;
                gpu.execution.backend = QuantumBackendType::CudaGpu;
                gpu.execution.gpu_device = options.gpu_device;
                gpu.name = "CUDA-GPU";
                gpu.available = cuda_backend::CUDAQuantumBackend::is_available();
                if (!gpu.available)
                {
                    gpu.unavailable_reason =
                        "Single-GPU backend unavailable (CUDA compiler, driver, or NVIDIA GPU not detected).";
                }
                cases.push_back(std::move(gpu));

                BackendCase multi_gpu;
                multi_gpu.execution.backend = QuantumBackendType::CudaMultiGpu;
                multi_gpu.execution.gpu_devices = options.gpu_devices;
                multi_gpu.name = "CUDA-MULTI-GPU";
                multi_gpu.available = cuda_backend::CUDAMultiGpuQuantumBackend::is_available();
                if (!multi_gpu.available)
                {
                    multi_gpu.unavailable_reason =
                        "Multi-GPU backend unavailable (at least two usable CUDA devices are required).";
                }
                cases.push_back(std::move(multi_gpu));
            }
            return cases;
        }

        [[nodiscard]] Sample run_one_sample(
            const std::size_t qubits,
            const BackendCase& backend,
            const std::vector<std::size_t>& qft_targets)
        {
            Sample sample;
            const auto setup_start = Clock::now();
            QuantumSimulator simulator(qubits, qubits, backend.execution);
            sample.setup_ms = milliseconds(setup_start);

            const auto qft_start = Clock::now();
            simulator.apply_qft(qft_targets);
            sample.qft_ms = milliseconds(qft_start);

            const auto readback_start = Clock::now();
            const std::vector<Complex>& final_state = simulator.state();
            sample.result_readback_ms = milliseconds(readback_start);

            const auto validation_start = Clock::now();
            double probability_sum = 0.0;
            for (const Complex& amplitude : final_state)
            {
                probability_sum += std::norm(amplitude);
            }
            sample.norm_error = std::abs(probability_sum - 1.0);
            sample.validation_ms = milliseconds(validation_start);
            sample.end_to_end_ms = sample.setup_ms + sample.qft_ms + sample.result_readback_ms;

            sample.gate_count = simulator.gate_count();
            sample.operation_depth = simulator.operation_depth();
            const QuantumBackendStatistics& metrics = simulator.backend_statistics();
            if (backend.execution.backend == QuantumBackendType::CpuSingleThread
                || backend.execution.backend == QuantumBackendType::CpuMultiThread)
            {
                sample.cpu_threads_used = metrics.cpu_threads_used;
            }
            else
            {
                sample.cpu_threads_used = 0U;
            }
            sample.gpu_device_used = metrics.gpu_device_used;
            sample.gpu_devices_used = metrics.gpu_devices_used;
            sample.cpu_wall_ms = metrics.cpu_wall_time_ms;
            sample.gpu_kernel_ms = metrics.gpu_kernel_time_ms;
            sample.gpu_transfer_ms = metrics.gpu_transfer_time_ms;
            sample.gpu_initialization_ms = metrics.gpu_initialization_time_ms;
            sample.inter_gpu_transfer_ms = metrics.gpu_inter_gpu_transfer_time_ms;
            sample.parallel_kernel_wall_ms = metrics.gpu_parallel_kernel_wall_time_ms;
            sample.gpu_peer_copies = static_cast<double>(metrics.gpu_peer_copy_count);
            sample.gpu_host_staged_copies = static_cast<double>(metrics.gpu_host_staged_copy_count);
            sample.gpu_qft_fused_stages = static_cast<double>(metrics.gpu_qft_fused_stage_count);
            sample.gpu_qft_swaps = static_cast<double>(metrics.gpu_qft_swap_count);
            sample.pinned_host_memory_used = metrics.gpu_pinned_host_memory_used;
            return sample;
        }

        [[nodiscard]] BenchmarkTimingSummary summarize(std::vector<double> values)
        {
            BenchmarkTimingSummary summary;
            if (values.empty()) return summary;
            std::sort(values.begin(), values.end());
            summary.minimum_ms = values.front();
            summary.maximum_ms = values.back();
            const std::size_t middle = values.size() / 2U;
            summary.median_ms = values.size() % 2U == 0U
                ? (values[middle - 1U] + values[middle]) / 2.0
                : values[middle];
            summary.mean_ms = std::accumulate(values.begin(), values.end(), 0.0)
                / static_cast<double>(values.size());
            double squared_sum = 0.0;
            for (const double value : values)
            {
                const double difference = value - summary.mean_ms;
                squared_sum += difference * difference;
            }
            summary.standard_deviation_ms = std::sqrt(squared_sum / static_cast<double>(values.size()));
            return summary;
        }

        [[nodiscard]] BenchmarkTimingSummary summarize_samples(
            const std::vector<Sample>& samples, double Sample::*member)
        {
            std::vector<double> values;
            values.reserve(samples.size());
            for (const Sample& sample : samples) values.push_back(sample.*member);
            return summarize(std::move(values));
        }

        [[nodiscard]] double mean_sample_value(
            const std::vector<Sample>& samples, double Sample::*member)
        {
            if (samples.empty()) return 0.0;
            double total = 0.0;
            for (const Sample& sample : samples) total += sample.*member;
            return total / static_cast<double>(samples.size());
        }

        [[nodiscard]] QftBenchmarkResult run_backend_case(
            const std::size_t qubits,
            const std::size_t state_bytes,
            const BackendCase& backend,
            const QftBenchmarkOptions& options)
        {
            QftBenchmarkResult result;
            result.qubits = qubits;
            result.state_vector_bytes = state_bytes;
            result.backend = backend.name;
            result.requested_runs = options.repeats;

            if (!backend.available)
            {
                result.status = "UNAVAILABLE";
                result.error_message = backend.unavailable_reason;
                return result;
            }

            std::vector<std::size_t> targets(qubits);
            std::iota(targets.begin(), targets.end(), 0U);
            try
            {
                for (std::size_t warmup = 0U; warmup < options.warmup_runs; ++warmup)
                {
                    const Sample warmup_sample = run_one_sample(qubits, backend, targets);
                    if (warmup_sample.norm_error > 1e-8)
                    {
                        throw std::runtime_error("QFT warm-up produced a state with a non-unit norm.");
                    }
                }
            }
            catch (const std::exception& exception)
            {
                result.status = "FAILED";
                result.error_message = std::string("Warm-up failed: ") + exception.what();
                result.failed_runs = options.repeats;
                return result;
            }

            std::vector<Sample> samples;
            samples.reserve(options.repeats);
            for (std::size_t run = 0U; run < options.repeats; ++run)
            {
                try
                {
                    Sample sample = run_one_sample(qubits, backend, targets);
                    if (sample.norm_error > 1e-8)
                    {
                        throw std::runtime_error("QFT produced a state with a non-unit norm.");
                    }
                    samples.push_back(std::move(sample));
                }
                catch (const std::exception& exception)
                {
                    ++result.failed_runs;
                    if (result.error_message.empty()) result.error_message = exception.what();
                }
            }

            result.successful_runs = samples.size();
            if (samples.empty())
            {
                result.status = "FAILED";
                return result;
            }
            result.status = result.failed_runs == 0U ? "OK" : "PARTIAL";
            result.gate_count = samples.back().gate_count;
            result.operation_depth = samples.back().operation_depth;
            result.cpu_threads_used = samples.back().cpu_threads_used;
            result.gpu_device_used = samples.back().gpu_device_used;
            result.gpu_devices_used = samples.back().gpu_devices_used;
            result.setup = summarize_samples(samples, &Sample::setup_ms);
            result.qft = summarize_samples(samples, &Sample::qft_ms);
            result.result_readback = summarize_samples(samples, &Sample::result_readback_ms);
            result.end_to_end = summarize_samples(samples, &Sample::end_to_end_ms);
            result.validation = summarize_samples(samples, &Sample::validation_ms);
            result.cpu_wall = summarize_samples(samples, &Sample::cpu_wall_ms);
            result.gpu_kernel = summarize_samples(samples, &Sample::gpu_kernel_ms);
            result.gpu_transfer = summarize_samples(samples, &Sample::gpu_transfer_ms);
            result.gpu_initialization = summarize_samples(samples, &Sample::gpu_initialization_ms);
            result.inter_gpu_transfer = summarize_samples(samples, &Sample::inter_gpu_transfer_ms);
            result.parallel_kernel_wall = summarize_samples(samples, &Sample::parallel_kernel_wall_ms);
            result.maximum_norm_error = 0.0;
            for (const Sample& sample : samples)
            {
                result.maximum_norm_error = std::max(result.maximum_norm_error, sample.norm_error);
                result.pinned_host_memory_used = result.pinned_host_memory_used || sample.pinned_host_memory_used;
            }
            result.mean_gpu_peer_copies = mean_sample_value(samples, &Sample::gpu_peer_copies);
            result.mean_gpu_host_staged_copies = mean_sample_value(samples, &Sample::gpu_host_staged_copies);
            result.mean_gpu_qft_fused_stages = mean_sample_value(samples, &Sample::gpu_qft_fused_stages);
            result.mean_gpu_qft_swaps = mean_sample_value(samples, &Sample::gpu_qft_swaps);

            const double seconds = result.qft.mean_ms / 1000.0;
            if (seconds > 0.0)
            {
                const double amplitude_count = static_cast<double>(std::size_t{1} << qubits);
                result.state_amplitudes_per_second = amplitude_count / seconds;
            }
            return result;
        }

        [[nodiscard]] std::string csv_escape(const std::string& value)
        {
            std::string escaped = "\"";
            for (const char character : value)
            {
                if (character == '"') escaped += "\"\"";
                else if (character != '\r' && character != '\n') escaped += character;
            }
            escaped += '"';
            return escaped;
        }

        void write_summary(std::ofstream& output, const BenchmarkTimingSummary& summary)
        {
            output << summary.minimum_ms << ',' << summary.median_ms << ',' << summary.mean_ms << ','
                   << summary.maximum_ms << ',' << summary.standard_deviation_ms;
        }
    }

    std::vector<QftBenchmarkResult> run_qft_benchmark(const QftBenchmarkOptions& options)
    {
        if (options.repeats == 0U)
        {
            throw std::invalid_argument("QFT benchmark repeats must be at least one.");
        }
        if (!options.include_cpu_backends && !options.include_cuda_backends)
        {
            throw std::invalid_argument("At least one backend family must be enabled.");
        }
        if (options.qubit_counts.empty())
        {
            throw std::invalid_argument("At least one QFT benchmark qubit count is required.");
        }

        std::vector<std::size_t> qubit_counts = options.qubit_counts;
        std::sort(qubit_counts.begin(), qubit_counts.end());
        qubit_counts.erase(std::unique(qubit_counts.begin(), qubit_counts.end()), qubit_counts.end());
        const std::vector<BackendCase> backends = make_backend_cases(options);
        std::vector<QftBenchmarkResult> results;
        results.reserve(qubit_counts.size() * backends.size());

        for (const std::size_t qubits : qubit_counts)
        {
            const std::size_t state_bytes = state_vector_size_bytes(qubits);
            for (const BackendCase& backend : backends)
            {
                if (options.max_state_vector_bytes != 0U && state_bytes > options.max_state_vector_bytes)
                {
                    QftBenchmarkResult skipped;
                    skipped.qubits = qubits;
                    skipped.state_vector_bytes = state_bytes;
                    skipped.backend = backend.name;
                    skipped.status = "SKIPPED-MEMORY";
                    skipped.requested_runs = options.repeats;
                    skipped.error_message =
                        "State-vector footprint exceeds max_state_vector_bytes; no run was attempted.";
                    results.push_back(std::move(skipped));
                    continue;
                }
                results.push_back(run_backend_case(qubits, state_bytes, backend, options));
            }
        }

        for (QftBenchmarkResult& result : results)
        {
            if (result.backend != "CPU-SINGLE" || result.successful_runs == 0U) continue;
            const double baseline = result.qft.mean_ms;
            if (baseline <= 0.0) continue;
            for (QftBenchmarkResult& candidate : results)
            {
                if (candidate.qubits == result.qubits && candidate.successful_runs > 0U
                    && candidate.qft.mean_ms > 0.0)
                {
                    candidate.speedup_vs_cpu_single = baseline / candidate.qft.mean_ms;
                }
            }
        }
        return results;
    }

    std::string format_qft_benchmark_result(const QftBenchmarkResult& result)
    {
        std::ostringstream output;
        output << std::fixed << std::setprecision(4)
               << "[" << result.status << "] " << result.backend
               << " | qubits=" << result.qubits
               << " | state=" << std::setprecision(2)
               << static_cast<double>(result.state_vector_bytes) / (1024.0 * 1024.0) << " MiB";
        if (result.cpu_threads_used > 0U) output << " | CPU threads=" << result.cpu_threads_used;
        if (!result.gpu_devices_used.empty())
        {
            output << " | GPU devices=";
            for (std::size_t index = 0U; index < result.gpu_devices_used.size(); ++index)
            {
                if (index != 0U) output << ';';
                output << result.gpu_devices_used[index];
            }
        }
        if (result.successful_runs > 0U)
        {
            output << std::setprecision(4)
                   << " | QFT mean/median/min/max=" << result.qft.mean_ms << '/'
                   << result.qft.median_ms << '/' << result.qft.minimum_ms << '/' << result.qft.maximum_ms
                   << " ms | end-to-end=" << result.end_to_end.mean_ms << " ms"
                   << " | kernel=" << result.gpu_kernel.mean_ms << " ms"
                   << " | transfer=" << result.gpu_transfer.mean_ms << " ms"
                   << " | inter-GPU=" << result.inter_gpu_transfer.mean_ms << " ms"
                   << " | speedup=" << result.speedup_vs_cpu_single
                   << "x | norm-error=" << std::scientific << result.maximum_norm_error;
        }
        else if (!result.error_message.empty())
        {
            output << " | " << result.error_message;
        }
        return output.str();
    }

    std::string export_qft_benchmark_csv(
        const std::vector<QftBenchmarkResult>& results,
        const std::string& file_path)
    {
        const std::filesystem::path path(file_path);
        if (!path.parent_path().empty()) std::filesystem::create_directories(path.parent_path());
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        if (!output) throw std::runtime_error("Unable to open the QFT benchmark CSV output file.");
        output << "qubits,state_vector_bytes,backend,status,requested_runs,successful_runs,failed_runs,gate_count,operation_depth,"
                  "cpu_threads_used,gpu_device_used,gpu_devices_used,";
        const std::vector<std::string> summary_names{
            "setup", "qft", "result_readback", "end_to_end", "validation", "cpu_wall", "gpu_kernel",
            "gpu_transfer", "gpu_initialization", "inter_gpu_transfer", "parallel_kernel_wall"};
        for (const std::string& name : summary_names)
        {
            output << name << "_min_ms," << name << "_median_ms," << name << "_mean_ms,"
                   << name << "_max_ms," << name << "_stddev_ms,";
        }
        output << "state_amplitudes_per_second,speedup_vs_cpu_single,maximum_norm_error,mean_gpu_peer_copies,"
                  "mean_gpu_host_staged_copies,mean_gpu_qft_fused_stages,mean_gpu_qft_swaps,"
                  "pinned_host_memory_used,error_message\n";
        for (const QftBenchmarkResult& result : results)
        {
            output << result.qubits << ',' << result.state_vector_bytes << ',' << csv_escape(result.backend)
                   << ',' << csv_escape(result.status)
                   << ',' << result.requested_runs << ',' << result.successful_runs << ',' << result.failed_runs
                   << ',' << result.gate_count << ',' << result.operation_depth << ','
                   << result.cpu_threads_used << ',' << result.gpu_device_used << ',';
            std::ostringstream devices;
            for (std::size_t index = 0U; index < result.gpu_devices_used.size(); ++index)
            {
                if (index != 0U) devices << ';';
                devices << result.gpu_devices_used[index];
            }
            output << csv_escape(devices.str()) << ',';
            const BenchmarkTimingSummary* summaries[]{
                &result.setup, &result.qft, &result.result_readback, &result.end_to_end, &result.validation,
                &result.cpu_wall, &result.gpu_kernel, &result.gpu_transfer, &result.gpu_initialization,
                &result.inter_gpu_transfer, &result.parallel_kernel_wall};
            for (const BenchmarkTimingSummary* summary : summaries)
            {
                write_summary(output, *summary);
                output << ',';
            }
            output << result.state_amplitudes_per_second << ',' << result.speedup_vs_cpu_single << ','
                   << result.maximum_norm_error << ',' << result.mean_gpu_peer_copies << ','
                   << result.mean_gpu_host_staged_copies << ',' << result.mean_gpu_qft_fused_stages << ','
                   << result.mean_gpu_qft_swaps << ','
                   << (result.pinned_host_memory_used ? "true" : "false") << ','
                   << csv_escape(result.error_message) << '\n';
        }
        if (!output) throw std::runtime_error("Writing the QFT benchmark CSV failed.");
        return path.string();
    }
}
