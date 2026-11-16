#include "ComputeEngine.h"

#include "ErrorHandling/CryptoException.h"
#include "CryptoSystem/Standard/SHA/SHA256.h"

#if CRYPTO_HAS_CUDA
    #include "CUDA/CudaCrypto.h"
#endif

#include <algorithm>
#include <chrono>
#include <ctime>
#include <exception>
#include <future>
#include <limits>
#include <mutex>
#include <thread>
#include <utility>

#if CRYPTO_HAS_CUDA
    #include "CUDA/CudaVectorAdd.h"
    #include <cuda_runtime_api.h>
#endif

namespace crypto
{
    namespace
    {
        [[nodiscard]] std::string backend_name(const ComputeBackend backend)
        {
            switch (backend)
            {
            case ComputeBackend::Auto: return "AUTO";
            case ComputeBackend::Cpu: return "CPU";
            case ComputeBackend::Gpu: return "GPU";
            case ComputeBackend::MultiGpu: return "MULTI-GPU";
            }
            return "UNKNOWN";
        }

        void cpu_vector_add(
            const std::span<const std::uint32_t> left,
            const std::span<const std::uint32_t> right,
            const std::span<std::uint32_t> output,
            std::size_t requested_thread_count)
        {
            const std::size_t count = left.size();
            if (count == 0)
            {
                return;
            }

            if (requested_thread_count == 0)
            {
                requested_thread_count = static_cast<std::size_t>(
                    std::max(1U, std::thread::hardware_concurrency()));
            }

            const std::size_t worker_count = std::min(count, requested_thread_count);
            std::vector<std::jthread> workers;
            workers.reserve(worker_count);

            for (std::size_t worker = 0; worker < worker_count; ++worker)
            {
                const std::size_t begin = (count / worker_count) * worker +
                    std::min(worker, count % worker_count);
                const std::size_t chunk_size = count / worker_count +
                    (worker < count % worker_count ? 1U : 0U);
                const std::size_t end = begin + chunk_size;

                workers.emplace_back([left, right, output, begin, end]()
                {
                    for (std::size_t index = begin; index < end; ++index)
                    {
                        output[index] = left[index] + right[index];
                    }
                });
            }
        }

        [[nodiscard]] double elapsed_ms(
            const std::chrono::steady_clock::time_point start,
            const std::chrono::steady_clock::time_point end)
        {
            return std::chrono::duration<double, std::milli>(end - start).count();
        }

        [[nodiscard]] double process_cpu_ms(
            const std::clock_t start,
            const std::clock_t end)
        {
            if (start == static_cast<std::clock_t>(-1) ||
                end == static_cast<std::clock_t>(-1))
            {
                return 0.0;
            }

            return static_cast<double>(end - start) * 1000.0 /
                static_cast<double>(CLOCKS_PER_SEC);
        }
    }

    std::string to_string(const ComputeBackend backend)
    {
        return backend_name(backend);
    }

    ComputeEngine::ComputeEngine(
        ComputeOptions options,
        PerformanceMonitor* performance_monitor)
        : options_(std::move(options)),
          performance_monitor_(performance_monitor)
    {
    }

    bool ComputeEngine::cuda_compiled() noexcept
    {
#if CRYPTO_HAS_CUDA
        return true;
#else
        return false;
#endif
    }

    std::vector<std::array<std::uint8_t, 32>> ComputeEngine::sha256_short_batch(
        const std::vector<std::string>& messages,
        Sha256BatchReport* output_report) const
    {
        for (const std::string& message : messages)
        {
            if (message.size() > 55U)
            {
                raise_error(ErrorCode::InvalidLength,
                    "The CUDA-compatible SHA-256 batch accepts messages of at most 55 bytes.");
            }
        }

        Sha256BatchReport local_report;
        Sha256BatchReport& report = output_report != nullptr ? *output_report : local_report;
        report = {};
        report.messages_processed = messages.size();
        report.execution.requested_backend = options_.backend;
        report.execution.items_processed = messages.size();
        std::vector<std::array<std::uint8_t, 32>> digests(messages.size());
        const auto wall_start = std::chrono::steady_clock::now();
        const std::clock_t cpu_start = std::clock();

        bool use_gpu = false;
        std::vector<GpuDeviceInfo> devices;
#if CRYPTO_HAS_CUDA
        if (options_.backend != ComputeBackend::Cpu)
        {
            devices = discover_gpus();
            use_gpu = !devices.empty() &&
                (options_.backend == ComputeBackend::Gpu ||
                 options_.backend == ComputeBackend::MultiGpu ||
                 (options_.backend == ComputeBackend::Auto &&
                  messages.size() >= options_.minimum_gpu_work_items));
            if (options_.backend == ComputeBackend::Gpu && options_.selected_gpu_index >= 0)
            {
                const auto found = std::find_if(devices.begin(), devices.end(),
                    [this](const GpuDeviceInfo& device)
                    { return device.index == options_.selected_gpu_index; });
                if (found == devices.end())
                {
                    devices.clear();
                    use_gpu = false;
                    report.execution.used_cpu_fallback = true;
                    report.execution.detail = "The selected GPU was unavailable; CPU SHA-256 was selected.";
                }
                else
                {
                    const GpuDeviceInfo selected = *found;
                    devices.assign(1U, selected);
                }
            }
        }
#else
        if (options_.backend != ComputeBackend::Cpu)
        {
            report.execution.used_cpu_fallback = true;
            report.execution.detail = "CUDA support was not compiled; CPU SHA-256 was selected.";
        }
#endif

        if (use_gpu && !messages.empty())
        {
#if CRYPTO_HAS_CUDA
            const std::size_t device_count = options_.backend == ComputeBackend::MultiGpu
                ? devices.size() : 1U;
            const std::size_t task_count = std::max<std::size_t>(1U, device_count);
            std::vector<std::future<void>> tasks;
            std::exception_ptr task_error;
            const std::size_t base = messages.size() / task_count;
            const std::size_t remainder = messages.size() % task_count;
            std::size_t offset = 0U;
            double kernel_ms = 0.0;
            double transfer_ms = 0.0;
            double initialization_ms = 0.0;
            std::mutex timing_mutex;
            for (std::size_t i = 0U; i < task_count; ++i)
            {
                const std::size_t count = base + (i < remainder ? 1U : 0U);
                const std::size_t begin = offset;
                offset += count;
                if (count == 0U) continue;
                const int device_index = devices[i].index;
                tasks.emplace_back(std::async(std::launch::async,
                    [&, begin, count, device_index]()
                    {
                        std::vector<std::uint8_t> packed(count * 55U, 0U);
                        std::vector<std::uint8_t> lengths(count, 0U);
                        std::vector<std::uint8_t> output(count * 32U, 0U);
                        for (std::size_t j = 0; j < count; ++j)
                        {
                            lengths[j] = static_cast<std::uint8_t>(messages[begin + j].size());
                            std::copy(messages[begin + j].begin(), messages[begin + j].end(),
                                      packed.begin() + static_cast<std::ptrdiff_t>(j * 55U));
                        }
                        cuda_backend::CudaCryptoTiming timing;
                        cuda_backend::sha256_short_batch(device_index, packed.data(), lengths.data(),
                                                         output.data(), count, timing);
                        for (std::size_t j = 0; j < count; ++j)
                            std::copy_n(output.begin() + static_cast<std::ptrdiff_t>(j * 32U), 32U,
                                        digests[begin + j].begin());
                        std::scoped_lock lock(timing_mutex);
                        kernel_ms += timing.kernel_time_ms;
                        transfer_ms += timing.transfer_time_ms;
                        initialization_ms += timing.initialization_time_ms;
                    }));
                report.execution.gpu_device_indices.push_back(device_index);
            }
            for (auto& task : tasks)
            {
                try { task.get(); }
                catch (...) { if (!task_error) task_error = std::current_exception(); }
            }
            if (task_error) std::rethrow_exception(task_error);
            report.execution.actual_backend = task_count > 1U ? ComputeBackend::MultiGpu : ComputeBackend::Gpu;
            report.execution.gpu_kernel_time_ms = kernel_ms;
            report.execution.gpu_transfer_time_ms = transfer_ms;
            report.execution.gpu_initialization_time_ms = initialization_ms;
            report.execution.detail = "Short-message SHA-256 batch executed with the CUDA kernel.";
#endif
        }
        else
        {
            for (std::size_t i = 0; i < messages.size(); ++i)
                digests[i] = standard::sha256(messages[i]);
            report.execution.actual_backend = ComputeBackend::Cpu;
            if (report.execution.detail.empty() && options_.backend != ComputeBackend::Cpu)
                report.execution.used_cpu_fallback = true;
            if (report.execution.detail.empty())
                report.execution.detail = "Short-message SHA-256 batch executed on the CPU.";
        }

        const auto wall_end = std::chrono::steady_clock::now();
        const std::clock_t cpu_end = std::clock();
        report.execution.wall_time_ms = elapsed_ms(wall_start, wall_end);
        report.execution.process_cpu_time_ms = process_cpu_ms(cpu_start, cpu_end);
        if (performance_monitor_ != nullptr)
        {
            PerformanceRecord record;
            record.stage = "ComputeEngine.SHA256ShortBatch";
            record.backend = to_string(report.execution.actual_backend);
            record.wall_time_ms = report.execution.wall_time_ms;
            record.process_cpu_time_ms = report.execution.process_cpu_time_ms;
            if (use_gpu)
            {
                record.gpu_kernel_time_ms = report.execution.gpu_kernel_time_ms;
                record.gpu_transfer_time_ms = report.execution.gpu_transfer_time_ms;
                record.gpu_initialization_time_ms = report.execution.gpu_initialization_time_ms;
            }
            record.detail = report.execution.detail;
            performance_monitor_->record(std::move(record));
        }
        return digests;
    }

    const ComputeOptions& ComputeEngine::options() const noexcept
    {
        return options_;
    }

    std::vector<GpuDeviceInfo> ComputeEngine::discover_gpus()
    {
        std::vector<GpuDeviceInfo> devices;

#if CRYPTO_HAS_CUDA
        int device_count = 0;
        const cudaError_t count_status = cudaGetDeviceCount(&device_count);

        if (count_status == cudaErrorNoDevice ||
            count_status == cudaErrorInsufficientDriver ||
            count_status == cudaErrorInitializationError)
        {
            (void)cudaGetLastError();
            return devices;
        }

        if (count_status != cudaSuccess)
        {
            const std::string message =
                std::string("CUDA device discovery failed: ") + cudaGetErrorString(count_status);
            (void)cudaGetLastError();
            raise_error(ErrorCode::UnsupportedPlatform, message);
        }

        devices.reserve(static_cast<std::size_t>(device_count));

        for (int index = 0; index < device_count; ++index)
        {
            cudaDeviceProp properties{};
            const cudaError_t property_status = cudaGetDeviceProperties(&properties, index);
            if (property_status != cudaSuccess)
            {
                const std::string message =
                    std::string("Unable to read CUDA device properties: ") +
                    cudaGetErrorString(property_status);
                (void)cudaGetLastError();
                raise_error(ErrorCode::UnsupportedPlatform, message);
            }

            GpuDeviceInfo info;
            info.index = index;
            info.name = properties.name;
            info.total_memory_bytes = static_cast<std::uint64_t>(properties.totalGlobalMem);
            info.compute_major = properties.major;
            info.compute_minor = properties.minor;
            info.multiprocessor_count = properties.multiProcessorCount;
            devices.push_back(std::move(info));
        }
#endif

        return devices;
    }

    ComputeExecutionReport ComputeEngine::vector_add_u32(
        const std::span<const std::uint32_t> left,
        const std::span<const std::uint32_t> right,
        const std::span<std::uint32_t> output) const
    {
        if (left.size() != right.size() || left.size() != output.size())
        {
            raise_error(
                ErrorCode::InvalidLength,
                "Vector addition requires input and output spans of equal length.");
        }

        ComputeExecutionReport report;
        report.requested_backend = options_.backend;
        report.items_processed = left.size();

        const auto wall_start = std::chrono::steady_clock::now();
        const std::clock_t cpu_start = std::clock();

        bool use_cpu = options_.backend == ComputeBackend::Cpu;
        bool use_multi_gpu = false;
        std::vector<GpuDeviceInfo> selected_devices;

        if (!use_cpu)
        {
            const auto available_devices = discover_gpus();

            if (available_devices.empty())
            {
                use_cpu = true;
                report.used_cpu_fallback = options_.backend != ComputeBackend::Cpu;
                report.detail = "No usable CUDA GPU was found; CPU execution was selected.";
            }
            else if (options_.backend == ComputeBackend::Auto &&
                     left.size() < options_.minimum_gpu_work_items)
            {
                use_cpu = true;
                report.used_cpu_fallback = true;
                report.detail = "The workload is below the configured GPU threshold; CPU execution was selected.";
            }
            else if (options_.backend == ComputeBackend::Gpu)
            {
                const int requested_index = options_.selected_gpu_index;
                const auto found = std::find_if(
                    available_devices.begin(), available_devices.end(),
                    [requested_index](const GpuDeviceInfo& device)
                    {
                        return requested_index < 0 || device.index == requested_index;
                    });

                if (found == available_devices.end())
                {
                    use_cpu = true;
                    report.used_cpu_fallback = true;
                    report.detail = "The selected GPU index is unavailable; CPU execution was selected.";
                }
                else
                {
                    selected_devices.push_back(*found);
                }
            }
            else if (options_.backend == ComputeBackend::MultiGpu)
            {
                selected_devices = available_devices;
                use_multi_gpu = selected_devices.size() > 1U;

                if (selected_devices.size() == 1U)
                {
                    report.detail = "Only one CUDA GPU is available; single-GPU execution will be used.";
                }
            }
            else
            {
                selected_devices.push_back(available_devices.front());
            }
        }

        if (left.empty())
        {
            use_cpu = true;
            selected_devices.clear();
            use_multi_gpu = false;
            report.detail = "The input is empty; no computation was required.";
        }

        (void)use_multi_gpu;

        if (use_cpu)
        {
            cpu_vector_add(left, right, output, options_.cpu_thread_count);
            report.actual_backend = ComputeBackend::Cpu;
        }
        else
        {
#if CRYPTO_HAS_CUDA
            struct GpuTaskResult
            {
                int device_index = -1;
                cuda_backend::CudaVectorAddTiming timing;
            };

            struct GpuTask
            {
                int device_index = -1;
                std::size_t offset = 0;
                std::size_t count = 0;
                std::future<cuda_backend::CudaVectorAddTiming> future;
            };

            std::vector<GpuTask> tasks;
            const std::size_t device_count = selected_devices.size();
            std::size_t total_weight = 0;

            for (const auto& device : selected_devices)
            {
                total_weight += static_cast<std::size_t>(
                    std::max(1, device.multiprocessor_count));
            }

            std::size_t offset = 0;
            std::exception_ptr task_error;

            try
            {
                for (std::size_t device_position = 0;
                     device_position < device_count;
                     ++device_position)
                {
                    const auto& device = selected_devices[device_position];
                    const std::size_t remaining = left.size() - offset;
                    std::size_t chunk_count = remaining;

                    if (device_position + 1U < device_count)
                    {
                        const std::size_t weight = static_cast<std::size_t>(
                            std::max(1, device.multiprocessor_count));
                        const long double proportional =
                            static_cast<long double>(left.size()) *
                            static_cast<long double>(weight) /
                            static_cast<long double>(total_weight);
                        chunk_count = static_cast<std::size_t>(proportional);
                        chunk_count = std::min(chunk_count, remaining);
                    }

                    if (chunk_count == 0U)
                    {
                        continue;
                    }

                    GpuTask task;
                    task.device_index = device.index;
                    task.offset = offset;
                    task.count = chunk_count;

                    const std::uint32_t* left_pointer = left.data() + offset;
                    const std::uint32_t* right_pointer = right.data() + offset;
                    std::uint32_t* output_pointer = output.data() + offset;
                    const int device_index = device.index;
                    const std::size_t task_count = chunk_count;

                    task.future = std::async(
                        std::launch::async,
                        [device_index, left_pointer, right_pointer, output_pointer, task_count]()
                        {
                            cuda_backend::CudaVectorAddTiming timing;
                            cuda_backend::vector_add_u32(
                                device_index,
                                left_pointer,
                                right_pointer,
                                output_pointer,
                                task_count,
                                timing);
                            return timing;
                        });

                    tasks.push_back(std::move(task));
                    offset += chunk_count;
                }
            }
            catch (...)
            {
                task_error = std::current_exception();
            }

            for (auto& task : tasks)
            {
                try
                {
                    const auto timing = task.future.get();
                    report.gpu_device_indices.push_back(task.device_index);
                    report.gpu_kernel_time_ms += timing.kernel_time_ms;
                    report.gpu_transfer_time_ms += timing.transfer_time_ms;
                    report.gpu_initialization_time_ms += timing.initialization_time_ms;
                }
                catch (...)
                {
                    if (task_error == nullptr)
                    {
                        task_error = std::current_exception();
                    }
                }
            }

            if (task_error != nullptr)
            {
                try
                {
                    std::rethrow_exception(task_error);
                }
                catch (const std::exception& exception)
                {
                    report.detail = std::string("CUDA execution failed; CPU fallback was used. Reason: ") + exception.what();
                }
                catch (...)
                {
                    report.detail = "CUDA execution failed; CPU fallback was used due to an unknown error.";
                }

                cpu_vector_add(left, right, output, options_.cpu_thread_count);
                report.actual_backend = ComputeBackend::Cpu;
                report.used_cpu_fallback = true;
                report.gpu_device_indices.clear();
            }
            else
            {
                report.actual_backend = use_multi_gpu
                    ? ComputeBackend::MultiGpu
                    : ComputeBackend::Gpu;
            }
#else
            cpu_vector_add(left, right, output, options_.cpu_thread_count);
            report.actual_backend = ComputeBackend::Cpu;
            report.used_cpu_fallback = true;
            report.detail = "This build does not include CUDA; CPU execution was selected.";
#endif
        }

        const auto wall_end = std::chrono::steady_clock::now();
        const std::clock_t cpu_end = std::clock();
        report.wall_time_ms = elapsed_ms(wall_start, wall_end);
        report.process_cpu_time_ms = process_cpu_ms(cpu_start, cpu_end);

        if (performance_monitor_ != nullptr)
        {
            PerformanceRecord record;
            record.stage = "ComputeEngine.VectorAddU32";
            record.backend = backend_name(report.actual_backend);
            record.wall_time_ms = report.wall_time_ms;
            record.process_cpu_time_ms = report.process_cpu_time_ms;
            record.gpu_kernel_time_ms = report.gpu_kernel_time_ms;
            record.gpu_transfer_time_ms = report.gpu_transfer_time_ms;
            record.gpu_initialization_time_ms = report.gpu_initialization_time_ms;
            record.detail = report.detail;
            performance_monitor_->record(std::move(record));
        }

        return report;
    }
}
