#include "CUDAMultiGpuQuantumBackend.h"

#include <cuda_runtime.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <numeric>
#include <stdexcept>
#include <string>
#include <utility>

namespace crypto::quantum::cuda_backend
{
    namespace
    {
        using Clock = std::chrono::steady_clock;

        void check_cuda(const cudaError_t result, const char* operation)
        {
            if (result != cudaSuccess)
            {
                throw std::runtime_error(std::string(operation) + " failed: " + cudaGetErrorString(result));
            }
        }

        [[nodiscard]] double elapsed_ms(const Clock::time_point start)
        {
            return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
        }

        [[nodiscard]] bool is_power_of_two(const std::size_t value) noexcept
        {
            return value != 0U && (value & (value - 1U)) == 0U;
        }

        [[nodiscard]] std::size_t integer_log2(std::size_t value)
        {
            std::size_t result = 0U;
            while (value > 1U) { value >>= 1U; ++result; }
            return result;
        }

        [[nodiscard]] unsigned int grid_size(const std::size_t count)
        {
            constexpr std::size_t threads = 256U;
            const std::size_t blocks = (count + threads - 1U) / threads;
            return static_cast<unsigned int>(std::clamp<std::size_t>(blocks, 1U, 65535U));
        }

        __global__ void x_local_kernel(double* real, double* imag, const std::size_t count,
                                       const std::size_t mask)
        {
            const std::size_t pair_count = count / 2U;
            const std::size_t stride = static_cast<std::size_t>(gridDim.x) * blockDim.x;
            for (std::size_t pair = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
                 pair < pair_count; pair += stride)
            {
                const std::size_t low = (pair & (mask - 1U)) | ((pair / mask) * (mask << 1U));
                const std::size_t high = low | mask;
                const double r = real[low]; real[low] = real[high]; real[high] = r;
                const double i = imag[low]; imag[low] = imag[high]; imag[high] = i;
            }
        }

        __global__ void z_local_kernel(double* real, double* imag, const std::size_t count,
                                       const std::size_t mask)
        {
            const std::size_t stride = static_cast<std::size_t>(gridDim.x) * blockDim.x;
            for (std::size_t index = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
                 index < count; index += stride)
            {
                if ((index & mask) != 0U) { real[index] = -real[index]; imag[index] = -imag[index]; }
            }
        }

        __global__ void negate_kernel(double* real, double* imag, const std::size_t count)
        {
            const std::size_t stride = static_cast<std::size_t>(gridDim.x) * blockDim.x;
            for (std::size_t index = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
                 index < count; index += stride)
            {
                real[index] = -real[index]; imag[index] = -imag[index];
            }
        }

        __global__ void hadamard_local_kernel(double* real, double* imag, const std::size_t count,
                                              const std::size_t mask, const double scale)
        {
            const std::size_t pair_count = count / 2U;
            const std::size_t stride = static_cast<std::size_t>(gridDim.x) * blockDim.x;
            for (std::size_t pair = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
                 pair < pair_count; pair += stride)
            {
                const std::size_t low = (pair & (mask - 1U)) | ((pair / mask) * (mask << 1U));
                const std::size_t high = low | mask;
                const double r0 = real[low], i0 = imag[low];
                const double r1 = real[high], i1 = imag[high];
                real[low] = (r0 + r1) * scale; imag[low] = (i0 + i1) * scale;
                real[high] = (r0 - r1) * scale; imag[high] = (i0 - i1) * scale;
            }
        }

        __global__ void distributed_copy_kernel(double* real, double* imag,
                                                const double* remote_real, const double* remote_imag,
                                                const std::size_t count)
        {
            const std::size_t stride = static_cast<std::size_t>(gridDim.x) * blockDim.x;
            for (std::size_t index = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
                 index < count; index += stride)
            {
                real[index] = remote_real[index]; imag[index] = remote_imag[index];
            }
        }

        __global__ void distributed_hadamard_kernel(double* real, double* imag,
                                                    const double* remote_real, const double* remote_imag,
                                                    const std::size_t count, const bool device_bit_is_one,
                                                    const double scale)
        {
            const std::size_t stride = static_cast<std::size_t>(gridDim.x) * blockDim.x;
            for (std::size_t index = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
                 index < count; index += stride)
            {
                const double local_r = real[index], local_i = imag[index];
                const double other_r = remote_real[index], other_i = remote_imag[index];
                if (!device_bit_is_one)
                {
                    real[index] = (local_r + other_r) * scale;
                    imag[index] = (local_i + other_i) * scale;
                }
                else
                {
                    real[index] = (other_r - local_r) * scale;
                    imag[index] = (other_i - local_i) * scale;
                }
            }
        }

        __global__ void cnot_local_kernel(double* real, double* imag, const std::size_t count,
                                          const std::size_t global_offset, const std::size_t control_mask,
                                          const std::size_t target_local_mask)
        {
            const std::size_t stride = static_cast<std::size_t>(gridDim.x) * blockDim.x;
            for (std::size_t index = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
                 index < count; index += stride)
            {
                if ((index & target_local_mask) == 0U && (((global_offset + index) & control_mask) != 0U))
                {
                    const std::size_t partner = index | target_local_mask;
                    const double r = real[index]; real[index] = real[partner]; real[partner] = r;
                    const double i = imag[index]; imag[index] = imag[partner]; imag[partner] = i;
                }
            }
        }

        __global__ void cnot_distributed_kernel(double* real, double* imag,
                                                const double* remote_real, const double* remote_imag,
                                                const std::size_t count, const std::size_t global_offset,
                                                const std::size_t control_mask)
        {
            const std::size_t stride = static_cast<std::size_t>(gridDim.x) * blockDim.x;
            for (std::size_t index = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
                 index < count; index += stride)
            {
                if (((global_offset + index) & control_mask) != 0U)
                {
                    real[index] = remote_real[index]; imag[index] = remote_imag[index];
                }
            }
        }

        __global__ void controlled_phase_local_kernel(double* real, double* imag, const std::size_t count,
                                                      const std::size_t global_offset,
                                                      const std::size_t control_mask, const std::size_t target_mask,
                                                      const double cosine, const double sine)
        {
            const std::size_t stride = static_cast<std::size_t>(gridDim.x) * blockDim.x;
            for (std::size_t local = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
                 local < count; local += stride)
            {
                const std::size_t global = global_offset + local;
                if ((global & control_mask) != 0U && (global & target_mask) != 0U)
                {
                    const double r = real[local], i = imag[local];
                    real[local] = r * cosine - i * sine;
                    imag[local] = r * sine + i * cosine;
                }
            }
        }

        __device__ __forceinline__ void apply_qft_stage_phase(
            double& value_real, double& value_imag, const std::size_t global_index,
            const std::size_t* qft_qubits, const std::size_t control_count,
            const std::size_t target_position, const double pi)
        {
            double phase = 0.0;
            for (std::size_t k = 0U; k < control_count; ++k)
            {
                const std::size_t control_mask = std::size_t{1} << qft_qubits[k];
                if ((global_index & control_mask) != 0U)
                {
                    const std::size_t denominator = std::size_t{1} << (target_position - k);
                    phase += pi / static_cast<double>(denominator);
                }
            }
            const double cosine = cos(phase), sine = sin(phase);
            const double r = value_real, i = value_imag;
            value_real = r * cosine - i * sine;
            value_imag = r * sine + i * cosine;
        }

        __global__ void fused_qft_local_kernel(
            double* real, double* imag, const std::size_t count,
            const std::size_t global_offset, const std::size_t target_mask,
            const std::size_t* qft_qubits, const std::size_t control_count,
            const std::size_t target_position, const double scale, const double pi)
        {
            const std::size_t pair_count = count / 2U;
            const std::size_t stride = static_cast<std::size_t>(gridDim.x) * blockDim.x;
            for (std::size_t pair = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
                 pair < pair_count; pair += stride)
            {
                const std::size_t low = (pair & (target_mask - 1U)) |
                                        ((pair / target_mask) * (target_mask << 1U));
                const std::size_t high = low | target_mask;
                const double r0 = real[low], i0 = imag[low];
                const double r1 = real[high], i1 = imag[high];
                real[low] = (r0 + r1) * scale;
                imag[low] = (i0 + i1) * scale;
                double high_real = (r0 - r1) * scale;
                double high_imag = (i0 - i1) * scale;
                apply_qft_stage_phase(high_real, high_imag, global_offset + high,
                                      qft_qubits, control_count, target_position, pi);
                real[high] = high_real;
                imag[high] = high_imag;
            }
        }

        __global__ void fused_qft_distributed_kernel(
            double* real, double* imag, const double* remote_real, const double* remote_imag,
            const std::size_t count, const std::size_t global_offset,
            const bool device_bit_is_one, const double scale,
            const std::size_t* qft_qubits, const std::size_t control_count,
            const std::size_t target_position, const double pi)
        {
            const std::size_t stride = static_cast<std::size_t>(gridDim.x) * blockDim.x;
            for (std::size_t index = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
                 index < count; index += stride)
            {
                const double local_real = real[index], local_imag = imag[index];
                const double other_real = remote_real[index], other_imag = remote_imag[index];
                if (!device_bit_is_one)
                {
                    real[index] = (local_real + other_real) * scale;
                    imag[index] = (local_imag + other_imag) * scale;
                }
                else
                {
                    double high_real = (other_real - local_real) * scale;
                    double high_imag = (other_imag - local_imag) * scale;
                    apply_qft_stage_phase(high_real, high_imag, global_offset + index,
                                          qft_qubits, control_count, target_position, pi);
                    real[index] = high_real;
                    imag[index] = high_imag;
                }
            }
        }

        __global__ void swap_local_qubits_kernel(double* real, double* imag,
                                                  const std::size_t count,
                                                  const std::size_t first_mask,
                                                  const std::size_t second_mask)
        {
            const std::size_t stride = static_cast<std::size_t>(gridDim.x) * blockDim.x;
            for (std::size_t index = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
                 index < count; index += stride)
            {
                if ((index & first_mask) == 0U && (index & second_mask) != 0U)
                {
                    const std::size_t partner = index ^ first_mask ^ second_mask;
                    const double r = real[index]; real[index] = real[partner]; real[partner] = r;
                    const double i = imag[index]; imag[index] = imag[partner]; imag[partner] = i;
                }
            }
        }

        __global__ void swap_local_distributed_kernel(
            double* real, double* imag, const double* remote_real, const double* remote_imag,
            const std::size_t count, const std::size_t local_mask, const bool distributed_bit_is_one)
        {
            const std::size_t stride = static_cast<std::size_t>(gridDim.x) * blockDim.x;
            for (std::size_t index = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
                 index < count; index += stride)
            {
                const bool local_bit_is_one = (index & local_mask) != 0U;
                if (local_bit_is_one != distributed_bit_is_one)
                {
                    const std::size_t source = index ^ local_mask;
                    real[index] = remote_real[source];
                    imag[index] = remote_imag[source];
                }
            }
        }

        __global__ void phase_flip_kernel(double* real, double* imag, const std::size_t index)
        {
            if (blockIdx.x == 0U && threadIdx.x == 0U)
            {
                real[index] = -real[index]; imag[index] = -imag[index];
            }
        }

        __global__ void partial_sum_kernel(const double* real, const double* imag,
                                           double* partial_real, double* partial_imag,
                                           const std::size_t count)
        {
            __shared__ double shared_real[256];
            __shared__ double shared_imag[256];
            const unsigned int lane = threadIdx.x;
            const std::size_t first = static_cast<std::size_t>(blockIdx.x) * blockDim.x + lane;
            const std::size_t stride = static_cast<std::size_t>(gridDim.x) * blockDim.x;
            double sum_real = 0.0, sum_imag = 0.0;
            for (std::size_t index = first; index < count; index += stride)
            { sum_real += real[index]; sum_imag += imag[index]; }
            shared_real[lane] = sum_real; shared_imag[lane] = sum_imag;
            __syncthreads();
            for (unsigned int offset = blockDim.x / 2U; offset > 0U; offset >>= 1U)
            {
                if (lane < offset)
                { shared_real[lane] += shared_real[lane + offset]; shared_imag[lane] += shared_imag[lane + offset]; }
                __syncthreads();
            }
            if (lane == 0U)
            { partial_real[blockIdx.x] = shared_real[0]; partial_imag[blockIdx.x] = shared_imag[0]; }
        }

        __global__ void diffusion_kernel(double* real, double* imag, const std::size_t count,
                                         const double mean_real, const double mean_imag)
        {
            const std::size_t stride = static_cast<std::size_t>(gridDim.x) * blockDim.x;
            for (std::size_t index = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
                 index < count; index += stride)
            { real[index] = 2.0 * mean_real - real[index]; imag[index] = 2.0 * mean_imag - imag[index]; }
        }
    }

    struct CUDAMultiGpuQuantumBackend::Impl
    {
        struct Shard
        {
            int device = -1;
            std::size_t rank = 0U;
            double* real = nullptr;
            double* imag = nullptr;
            double* remote_real = nullptr;
            double* remote_imag = nullptr;
            double* partial_real = nullptr;
            double* partial_imag = nullptr;
            std::size_t* qft_qubits = nullptr;
            std::size_t qft_capacity = 0U;
            std::size_t partial_count = 0U;
            cudaEvent_t start = nullptr;
            cudaEvent_t end = nullptr;
        };

        explicit Impl(const std::size_t requested_qubits, std::vector<int> requested_devices)
            : qubits(requested_qubits)
        {
            const auto init_start = Clock::now();
            if (qubits >= sizeof(std::size_t) * 8U)
                throw std::length_error("The requested state vector cannot be represented by size_t.");
            int device_count = 0;
            check_cuda(cudaGetDeviceCount(&device_count), "cudaGetDeviceCount");
            if (requested_devices.empty())
            {
                const std::size_t maximum_devices_for_state = std::size_t{1} << qubits;
                std::size_t selected_count = 1U;
                while (selected_count * 2U <= static_cast<std::size_t>(std::max(device_count, 0)) &&
                       selected_count * 2U <= maximum_devices_for_state)
                    selected_count *= 2U;
                requested_devices.reserve(selected_count);
                for (std::size_t device = 0U; device < selected_count; ++device)
                    requested_devices.push_back(static_cast<int>(device));
            }
            if (requested_devices.size() < 2U)
                throw std::invalid_argument("Multi-GPU mode requires at least two selected NVIDIA GPUs.");
            if (!is_power_of_two(requested_devices.size()))
                throw std::invalid_argument("The number of selected GPUs must be a power of two (2, 4, 8, ...).");
            for (std::size_t i = 0U; i < requested_devices.size(); ++i)
            {
                if (requested_devices[i] < 0 || requested_devices[i] >= device_count)
                    throw std::out_of_range("A selected CUDA device index is unavailable.");
                if (std::find(requested_devices.begin(), requested_devices.begin() + static_cast<std::ptrdiff_t>(i),
                              requested_devices[i]) != requested_devices.begin() + static_cast<std::ptrdiff_t>(i))
                    throw std::invalid_argument("The multi-GPU device list contains a duplicate device index.");
            }

            distributed_bits = integer_log2(requested_devices.size());
            if (qubits < distributed_bits)
                throw std::invalid_argument("The qubit count must be at least log2(number of selected GPUs).");
            if (qubits >= sizeof(std::size_t) * 8U)
                throw std::length_error("The requested state vector cannot be represented by size_t.");

            state_count = std::size_t{1} << qubits;
            local_count = state_count / requested_devices.size();
            devices = std::move(requested_devices);
            shards.resize(devices.size());

            const std::size_t bytes = local_count * sizeof(double);
            for (std::size_t rank = 0U; rank < shards.size(); ++rank)
            {
                Shard& shard = shards[rank];
                shard.device = devices[rank];
                shard.rank = rank;
                try
                {
                    check_cuda(cudaSetDevice(shard.device), "cudaSetDevice multi-GPU init");
                    check_cuda(cudaFree(nullptr), "CUDA multi-GPU context initialization");
                    check_cuda(cudaMalloc(reinterpret_cast<void**>(&shard.real), bytes), "cudaMalloc shard real");
                    check_cuda(cudaMalloc(reinterpret_cast<void**>(&shard.imag), bytes), "cudaMalloc shard imag");
                    check_cuda(cudaMalloc(reinterpret_cast<void**>(&shard.remote_real), bytes), "cudaMalloc remote real");
                    check_cuda(cudaMalloc(reinterpret_cast<void**>(&shard.remote_imag), bytes), "cudaMalloc remote imag");
                    const std::size_t blocks = grid_size(local_count);
                    shard.partial_count = blocks;
                    check_cuda(cudaMalloc(reinterpret_cast<void**>(&shard.partial_real), blocks * sizeof(double)), "cudaMalloc partial real");
                    check_cuda(cudaMalloc(reinterpret_cast<void**>(&shard.partial_imag), blocks * sizeof(double)), "cudaMalloc partial imag");
                    check_cuda(cudaEventCreate(&shard.start), "cudaEventCreate multi-GPU start");
                    check_cuda(cudaEventCreate(&shard.end), "cudaEventCreate multi-GPU end");
                }
                catch (...)
                {
                    release_shard(shard);
                    for (Shard& previous : shards) release_shard(previous);
                    throw;
                }
            }

            try
            {
                peer_access.assign(shards.size(), std::vector<bool>(shards.size(), false));
                for (std::size_t destination = 0U; destination < shards.size(); ++destination)
                {
                    for (std::size_t source = 0U; source < shards.size(); ++source)
                    {
                        if (destination == source) continue;
                        int can_access = 0;
                        check_cuda(cudaDeviceCanAccessPeer(&can_access, devices[destination], devices[source]),
                                   "cudaDeviceCanAccessPeer");
                        if (can_access != 0)
                        {
                            check_cuda(cudaSetDevice(devices[destination]), "cudaSetDevice enable peer");
                            const cudaError_t enabled = cudaDeviceEnablePeerAccess(devices[source], 0U);
                            if (enabled == cudaSuccess || enabled == cudaErrorPeerAccessAlreadyEnabled)
                            {
                                (void)cudaGetLastError();
                                peer_access[destination][source] = true;
                            }
                            else
                            {
                                // Peer access may be blocked by device topology or runtime policy.
                                (void)cudaGetLastError();
                                peer_access[destination][source] = false;
                            }
                        }
                    }
                }
            }
            catch (...)
            {
                for (Shard& shard : shards) release_shard(shard);
                throw;
            }
            timing.initialization_time_ms = elapsed_ms(init_start);
            timing.gpu_count = shards.size();
        }

        ~Impl()
        {
            for (Shard& shard : shards)
            {
                if (shard.device >= 0) (void)cudaSetDevice(shard.device);
                release_shard(shard);
            }
            if (host_staging_registered)
            {
                (void)cudaHostUnregister(host_real.data());
                (void)cudaHostUnregister(host_imag.data());
            }
        }

        static void release_shard(Shard& shard) noexcept
        {
            if (shard.device >= 0) (void)cudaSetDevice(shard.device);
            if (shard.real != nullptr) (void)cudaFree(shard.real);
            if (shard.imag != nullptr) (void)cudaFree(shard.imag);
            if (shard.remote_real != nullptr) (void)cudaFree(shard.remote_real);
            if (shard.remote_imag != nullptr) (void)cudaFree(shard.remote_imag);
            if (shard.partial_real != nullptr) (void)cudaFree(shard.partial_real);
            if (shard.partial_imag != nullptr) (void)cudaFree(shard.partial_imag);
            if (shard.qft_qubits != nullptr) (void)cudaFree(shard.qft_qubits);
            if (shard.start != nullptr) (void)cudaEventDestroy(shard.start);
            if (shard.end != nullptr) (void)cudaEventDestroy(shard.end);
            shard.real = shard.imag = shard.remote_real = shard.remote_imag = nullptr;
            shard.partial_real = shard.partial_imag = nullptr;
            shard.qft_qubits = nullptr;
            shard.qft_capacity = 0U;
            shard.start = shard.end = nullptr;
        }

        template <typename Launch>
        void launch_all(Launch&& launch)
        {
            const auto wall_start = Clock::now();
            for (Shard& shard : shards)
            {
                check_cuda(cudaSetDevice(shard.device), "cudaSetDevice kernel launch");
                check_cuda(cudaEventRecord(shard.start), "cudaEventRecord multi-GPU start");
                launch(shard);
                check_cuda(cudaGetLastError(), "multi-GPU kernel launch");
                check_cuda(cudaEventRecord(shard.end), "cudaEventRecord multi-GPU end");
            }
            for (Shard& shard : shards)
            {
                check_cuda(cudaSetDevice(shard.device), "cudaSetDevice kernel sync");
                check_cuda(cudaEventSynchronize(shard.end), "cudaEventSynchronize multi-GPU");
                float elapsed = 0.0F;
                check_cuda(cudaEventElapsedTime(&elapsed, shard.start, shard.end), "cudaEventElapsedTime multi-GPU");
                timing.kernel_time_ms += static_cast<double>(elapsed);
            }
            timing.parallel_kernel_wall_time_ms += elapsed_ms(wall_start);
        }

        void ensure_host_staging()
        {
            if (host_real.size() == local_count && host_imag.size() == local_count) return;
            if (host_staging_registered)
            {
                (void)cudaHostUnregister(host_real.data());
                (void)cudaHostUnregister(host_imag.data());
                host_staging_registered = false;
            }
            host_real.resize(local_count);
            host_imag.resize(local_count);
            if (local_count == 0U) return;
            const std::size_t bytes = local_count * sizeof(double);
            const cudaError_t real_status = cudaHostRegister(host_real.data(), bytes, cudaHostRegisterPortable);
            if (real_status != cudaSuccess)
            {
                (void)cudaGetLastError();
                timing.used_pinned_host_memory = false;
                return;
            }
            const cudaError_t imag_status = cudaHostRegister(host_imag.data(), bytes, cudaHostRegisterPortable);
            if (imag_status != cudaSuccess)
            {
                (void)cudaHostUnregister(host_real.data());
                (void)cudaGetLastError();
                timing.used_pinned_host_memory = false;
                return;
            }
            host_staging_registered = true;
            timing.used_pinned_host_memory = true;
        }

        void ensure_qft_qubits(const std::vector<std::size_t>& qubits_to_upload)
        {
            for (Shard& shard : shards)
            {
                check_cuda(cudaSetDevice(shard.device), "cudaSetDevice QFT qubit upload");
                if (qubits_to_upload.size() > shard.qft_capacity)
                {
                    if (shard.qft_qubits != nullptr)
                        check_cuda(cudaFree(shard.qft_qubits), "cudaFree multi-GPU QFT qubits");
                    shard.qft_qubits = nullptr;
                    check_cuda(cudaMalloc(reinterpret_cast<void**>(&shard.qft_qubits),
                                          qubits_to_upload.size() * sizeof(std::size_t)),
                               "cudaMalloc multi-GPU QFT qubits");
                    shard.qft_capacity = qubits_to_upload.size();
                }
                check_cuda(cudaMemcpy(shard.qft_qubits, qubits_to_upload.data(),
                                      qubits_to_upload.size() * sizeof(std::size_t), cudaMemcpyHostToDevice),
                           "cudaMemcpy multi-GPU QFT qubits");
            }
        }

        void copy_partner_to_remote(const std::size_t destination_rank, const std::size_t source_rank)
        {
            Shard& destination = shards[destination_rank];
            const Shard& source = shards[source_rank];
            const std::size_t bytes = local_count * sizeof(double);
            const auto transfer_start = Clock::now();
            if (peer_access[destination_rank][source_rank])
            {
                check_cuda(cudaSetDevice(destination.device), "cudaSetDevice peer copy");
                check_cuda(cudaMemcpyPeer(destination.remote_real, destination.device,
                                          source.real, source.device, bytes), "cudaMemcpyPeer real");
                check_cuda(cudaMemcpyPeer(destination.remote_imag, destination.device,
                                          source.imag, source.device, bytes), "cudaMemcpyPeer imag");
                ++timing.peer_copy_count;
            }
            else
            {
                ensure_host_staging();
                check_cuda(cudaSetDevice(source.device), "cudaSetDevice host-staged source");
                check_cuda(cudaMemcpy(host_real.data(), source.real, bytes, cudaMemcpyDeviceToHost), "cudaMemcpy remote real D2H");
                check_cuda(cudaSetDevice(destination.device), "cudaSetDevice host-staged destination");
                check_cuda(cudaMemcpy(destination.remote_real, host_real.data(), bytes, cudaMemcpyHostToDevice), "cudaMemcpy remote real H2D");
                check_cuda(cudaSetDevice(source.device), "cudaSetDevice host-staged source imag");
                check_cuda(cudaMemcpy(host_imag.data(), source.imag, bytes, cudaMemcpyDeviceToHost), "cudaMemcpy remote imag D2H");
                check_cuda(cudaSetDevice(destination.device), "cudaSetDevice host-staged destination imag");
                check_cuda(cudaMemcpy(destination.remote_imag, host_imag.data(), bytes, cudaMemcpyHostToDevice), "cudaMemcpy remote imag H2D");
                ++timing.host_staged_copy_count;
            }
            const double spent = elapsed_ms(transfer_start);
            timing.inter_gpu_transfer_time_ms += spent;
            timing.transfer_time_ms += spent;
        }

        void stage_xor_partner(const std::size_t distributed_device_bit)
        {
            const std::size_t partner_mask = std::size_t{1} << distributed_device_bit;
            // Complete every read/exchange before launching any writer kernel.
            for (std::size_t rank = 0U; rank < shards.size(); ++rank)
                copy_partner_to_remote(rank, rank ^ partner_mask);
        }

        std::size_t qubits = 0U;
        std::size_t state_count = 0U;
        std::size_t local_count = 0U;
        std::size_t distributed_bits = 0U;
        std::vector<int> devices;
        std::vector<Shard> shards;
        std::vector<std::vector<bool>> peer_access;
        std::vector<double> host_real;
        std::vector<double> host_imag;
        bool host_staging_registered = false;
        CudaMultiGpuTiming timing{};
    };

    CUDAMultiGpuQuantumBackend::CUDAMultiGpuQuantumBackend(
        const std::size_t qubits, std::vector<int> device_indices)
        : impl_(std::make_unique<Impl>(qubits, std::move(device_indices)))
    {
    }

    CUDAMultiGpuQuantumBackend::~CUDAMultiGpuQuantumBackend() = default;

    bool CUDAMultiGpuQuantumBackend::is_available() noexcept
    {
        int count = 0;
        return cudaGetDeviceCount(&count) == cudaSuccess && count >= 2;
    }

    std::vector<int> CUDAMultiGpuQuantumBackend::available_devices()
    {
        int count = 0;
        check_cuda(cudaGetDeviceCount(&count), "cudaGetDeviceCount");
        std::vector<int> result(static_cast<std::size_t>(std::max(count, 0)));
        std::iota(result.begin(), result.end(), 0);
        return result;
    }

    const std::vector<int>& CUDAMultiGpuQuantumBackend::device_indices() const noexcept { return impl_->devices; }
    std::size_t CUDAMultiGpuQuantumBackend::state_size() const noexcept { return impl_->state_count; }
    std::size_t CUDAMultiGpuQuantumBackend::local_state_size() const noexcept { return impl_->local_count; }
    std::size_t CUDAMultiGpuQuantumBackend::distributed_qubit_count() const noexcept { return impl_->distributed_bits; }
    const CudaMultiGpuTiming& CUDAMultiGpuQuantumBackend::timing() const noexcept { return impl_->timing; }

    void CUDAMultiGpuQuantumBackend::upload(const std::vector<Complex>& state)
    {
        if (state.size() != impl_->state_count)
            throw std::invalid_argument("The uploaded state vector has a different size from the multi-GPU register.");
        impl_->ensure_host_staging();
        const std::size_t bytes = impl_->local_count * sizeof(double);
        const auto transfer_start = Clock::now();
        for (auto& shard : impl_->shards)
        {
            const std::size_t offset = shard.rank * impl_->local_count;
            for (std::size_t i = 0U; i < impl_->local_count; ++i)
            {
                impl_->host_real[i] = state[offset + i].real();
                impl_->host_imag[i] = state[offset + i].imag();
            }
            check_cuda(cudaSetDevice(shard.device), "cudaSetDevice upload shard");
            if (impl_->host_staging_registered)
            {
                check_cuda(cudaMemcpyAsync(shard.real, impl_->host_real.data(), bytes,
                                           cudaMemcpyHostToDevice), "cudaMemcpyAsync upload real shard");
                check_cuda(cudaMemcpyAsync(shard.imag, impl_->host_imag.data(), bytes,
                                           cudaMemcpyHostToDevice), "cudaMemcpyAsync upload imag shard");
            }
            else
            {
                check_cuda(cudaMemcpy(shard.real, impl_->host_real.data(), bytes,
                                      cudaMemcpyHostToDevice), "cudaMemcpy upload real shard");
                check_cuda(cudaMemcpy(shard.imag, impl_->host_imag.data(), bytes,
                                      cudaMemcpyHostToDevice), "cudaMemcpy upload imag shard");
            }
            check_cuda(cudaDeviceSynchronize(), "cudaDeviceSynchronize upload shard");
        }
        impl_->timing.transfer_time_ms += elapsed_ms(transfer_start);
    }

    void CUDAMultiGpuQuantumBackend::download(std::vector<Complex>& state)
    {
        impl_->ensure_host_staging();
        state.resize(impl_->state_count);
        const std::size_t bytes = impl_->local_count * sizeof(double);
        const auto transfer_start = Clock::now();
        for (const auto& shard : impl_->shards)
        {
            check_cuda(cudaSetDevice(shard.device), "cudaSetDevice download shard");
            if (impl_->host_staging_registered)
            {
                check_cuda(cudaMemcpyAsync(impl_->host_real.data(), shard.real, bytes,
                                           cudaMemcpyDeviceToHost), "cudaMemcpyAsync download real shard");
                check_cuda(cudaMemcpyAsync(impl_->host_imag.data(), shard.imag, bytes,
                                           cudaMemcpyDeviceToHost), "cudaMemcpyAsync download imag shard");
            }
            else
            {
                check_cuda(cudaMemcpy(impl_->host_real.data(), shard.real, bytes,
                                      cudaMemcpyDeviceToHost), "cudaMemcpy download real shard");
                check_cuda(cudaMemcpy(impl_->host_imag.data(), shard.imag, bytes,
                                      cudaMemcpyDeviceToHost), "cudaMemcpy download imag shard");
            }
            check_cuda(cudaDeviceSynchronize(), "cudaDeviceSynchronize download shard");
            const std::size_t offset = shard.rank * impl_->local_count;
            for (std::size_t i = 0U; i < impl_->local_count; ++i)
                state[offset + i] = Complex{impl_->host_real[i], impl_->host_imag[i]};
        }
        impl_->timing.transfer_time_ms += elapsed_ms(transfer_start);
    }

    void CUDAMultiGpuQuantumBackend::apply_x(const std::size_t target_qubit)
    {
        if (target_qubit >= impl_->qubits) throw std::out_of_range("Multi-GPU X target qubit is outside the register.");
        constexpr unsigned int threads = 256U;
        if (target_qubit < impl_->qubits - impl_->distributed_bits)
        {
            const std::size_t mask = std::size_t{1} << target_qubit;
            impl_->launch_all([&](Impl::Shard& shard)
            { x_local_kernel<<<grid_size(impl_->local_count / 2U), threads>>>(shard.real, shard.imag, impl_->local_count, mask); });
        }
        else
        {
            const std::size_t distributed_bit = target_qubit - (impl_->qubits - impl_->distributed_bits);
            impl_->stage_xor_partner(distributed_bit);
            impl_->launch_all([&](Impl::Shard& shard)
            { distributed_copy_kernel<<<grid_size(impl_->local_count), threads>>>(shard.real, shard.imag, shard.remote_real, shard.remote_imag, impl_->local_count); });
        }
    }

    void CUDAMultiGpuQuantumBackend::apply_z(const std::size_t target_qubit)
    {
        if (target_qubit >= impl_->qubits) throw std::out_of_range("Multi-GPU Z target qubit is outside the register.");
        constexpr unsigned int threads = 256U;
        if (target_qubit < impl_->qubits - impl_->distributed_bits)
        {
            const std::size_t mask = std::size_t{1} << target_qubit;
            impl_->launch_all([&](Impl::Shard& shard)
            { z_local_kernel<<<grid_size(impl_->local_count), threads>>>(shard.real, shard.imag, impl_->local_count, mask); });
        }
        else
        {
            const std::size_t bit = target_qubit - (impl_->qubits - impl_->distributed_bits);
            const std::size_t mask = std::size_t{1} << bit;
            impl_->launch_all([&](Impl::Shard& shard)
            { if ((shard.rank & mask) != 0U) negate_kernel<<<grid_size(impl_->local_count), threads>>>(shard.real, shard.imag, impl_->local_count); });
        }
    }

    void CUDAMultiGpuQuantumBackend::apply_hadamard(const std::size_t target_qubit)
    {
        if (target_qubit >= impl_->qubits) throw std::out_of_range("Multi-GPU Hadamard target qubit is outside the register.");
        constexpr unsigned int threads = 256U;
        constexpr double scale = 0.70710678118654752440;
        if (target_qubit < impl_->qubits - impl_->distributed_bits)
        {
            const std::size_t mask = std::size_t{1} << target_qubit;
            impl_->launch_all([&](Impl::Shard& shard)
            { hadamard_local_kernel<<<grid_size(impl_->local_count / 2U), threads>>>(shard.real, shard.imag, impl_->local_count, mask, scale); });
        }
        else
        {
            const std::size_t bit = target_qubit - (impl_->qubits - impl_->distributed_bits);
            impl_->stage_xor_partner(bit);
            const std::size_t mask = std::size_t{1} << bit;
            impl_->launch_all([&](Impl::Shard& shard)
            { distributed_hadamard_kernel<<<grid_size(impl_->local_count), threads>>>(
                  shard.real, shard.imag, shard.remote_real, shard.remote_imag, impl_->local_count,
                  (shard.rank & mask) != 0U, scale); });
        }
    }

    void CUDAMultiGpuQuantumBackend::apply_cnot(
        const std::size_t control_qubit, const std::size_t target_qubit)
    {
        if (control_qubit >= impl_->qubits || target_qubit >= impl_->qubits)
            throw std::out_of_range("Multi-GPU CNOT qubit is outside the register.");
        if (control_qubit == target_qubit) throw std::invalid_argument("CNOT control and target must differ.");
        constexpr unsigned int threads = 256U;
        const std::size_t control_mask = std::size_t{1} << control_qubit;
        if (target_qubit < impl_->qubits - impl_->distributed_bits)
        {
            const std::size_t target_mask = std::size_t{1} << target_qubit;
            impl_->launch_all([&](Impl::Shard& shard)
            {
                const std::size_t global_offset = shard.rank * impl_->local_count;
                cnot_local_kernel<<<grid_size(impl_->local_count), threads>>>(
                    shard.real, shard.imag, impl_->local_count, global_offset, control_mask, target_mask);
            });
        }
        else
        {
            const std::size_t target_device_bit = target_qubit - (impl_->qubits - impl_->distributed_bits);
            impl_->stage_xor_partner(target_device_bit);
            impl_->launch_all([&](Impl::Shard& shard)
            {
                const std::size_t global_offset = shard.rank * impl_->local_count;
                cnot_distributed_kernel<<<grid_size(impl_->local_count), threads>>>(
                    shard.real, shard.imag, shard.remote_real, shard.remote_imag,
                    impl_->local_count, global_offset, control_mask);
            });
        }
    }

    void CUDAMultiGpuQuantumBackend::apply_controlled_phase(
        const std::size_t control_qubit, const std::size_t target_qubit, const double angle)
    {
        if (control_qubit >= impl_->qubits || target_qubit >= impl_->qubits || control_qubit == target_qubit)
            throw std::out_of_range("Multi-GPU controlled-phase qubits are invalid.");
        constexpr unsigned int threads = 256U;
        const std::size_t control_mask = std::size_t{1} << control_qubit;
        const std::size_t target_mask = std::size_t{1} << target_qubit;
        const double cosine = std::cos(angle), sine = std::sin(angle);
        impl_->launch_all([&](Impl::Shard& shard)
        {
            const std::size_t global_offset = shard.rank * impl_->local_count;
            controlled_phase_local_kernel<<<grid_size(impl_->local_count), threads>>>(
                shard.real, shard.imag, impl_->local_count, global_offset,
                control_mask, target_mask, cosine, sine);
        });
    }

    void CUDAMultiGpuQuantumBackend::apply_qft(const std::vector<std::size_t>& target_qubits)
    {
        if (target_qubits.empty()) throw std::invalid_argument("QFT requires at least one target qubit.");
        if (target_qubits.size() >= sizeof(std::size_t) * 8U)
            throw std::length_error("The QFT target register is too large.");
        std::vector<bool> seen(impl_->qubits, false);
        for (const std::size_t q : target_qubits)
        {
            if (q >= impl_->qubits || seen[q])
                throw std::invalid_argument("QFT target qubits must be valid and unique.");
            seen[q] = true;
        }
        impl_->ensure_qft_qubits(target_qubits);
        constexpr unsigned int threads = 256U;
        constexpr double scale = 0.70710678118654752440;
        constexpr double pi = 3.1415926535897932384626433832795;
        const std::size_t local_qubits = impl_->qubits - impl_->distributed_bits;
        const std::size_t n = target_qubits.size();

        for (std::size_t j = n; j-- > 0U;)
        {
            const std::size_t target_qubit = target_qubits[j];
            if (target_qubit < local_qubits)
            {
                const std::size_t target_mask = std::size_t{1} << target_qubit;
                impl_->launch_all([&](Impl::Shard& shard)
                {
                    const std::size_t global_offset = shard.rank * impl_->local_count;
                    fused_qft_local_kernel<<<grid_size(impl_->local_count / 2U), threads>>>(
                        shard.real, shard.imag, impl_->local_count, global_offset, target_mask,
                        shard.qft_qubits, j, j, scale, pi);
                });
            }
            else
            {
                const std::size_t distributed_bit = target_qubit - local_qubits;
                const std::size_t rank_mask = std::size_t{1} << distributed_bit;
                impl_->stage_xor_partner(distributed_bit);
                impl_->launch_all([&](Impl::Shard& shard)
                {
                    const std::size_t global_offset = shard.rank * impl_->local_count;
                    fused_qft_distributed_kernel<<<grid_size(impl_->local_count), threads>>>(
                        shard.real, shard.imag, shard.remote_real, shard.remote_imag,
                        impl_->local_count, global_offset, (shard.rank & rank_mask) != 0U,
                        scale, shard.qft_qubits, j, j, pi);
                });
            }
            ++impl_->timing.qft_fused_stage_count;
        }

        // Bit-reversal permutation. Local-local swaps are entirely local; a
        // local/distributed swap exchanges only the necessary partner shards;
        // distributed/distributed swaps exchange complete shards once.
        for (std::size_t i = 0U; i < n / 2U; ++i)
        {
            const std::size_t first = target_qubits[i];
            const std::size_t second = target_qubits[n - 1U - i];
            const bool first_local = first < local_qubits;
            const bool second_local = second < local_qubits;

            if (first_local && second_local)
            {
                const std::size_t first_mask = std::size_t{1} << first;
                const std::size_t second_mask = std::size_t{1} << second;
                impl_->launch_all([&](Impl::Shard& shard)
                {
                    swap_local_qubits_kernel<<<grid_size(impl_->local_count), threads>>>(
                        shard.real, shard.imag, impl_->local_count, first_mask, second_mask);
                });
            }
            else if (!first_local && !second_local)
            {
                const std::size_t first_device_bit = first - local_qubits;
                const std::size_t second_device_bit = second - local_qubits;
                const std::size_t first_mask = std::size_t{1} << first_device_bit;
                const std::size_t second_mask = std::size_t{1} << second_device_bit;
                const std::size_t partner_mask = first_mask | second_mask;
                // Swapping two rank bits changes a rank only when those bits differ.
                // Equal-bit ranks keep their existing shard contents unchanged.
                for (std::size_t rank = 0U; rank < impl_->shards.size(); ++rank)
                {
                    const bool first_is_one = (rank & first_mask) != 0U;
                    const bool second_is_one = (rank & second_mask) != 0U;
                    if (first_is_one != second_is_one)
                        impl_->copy_partner_to_remote(rank, rank ^ partner_mask);
                }
                impl_->launch_all([&](Impl::Shard& shard)
                {
                    const bool first_is_one = (shard.rank & first_mask) != 0U;
                    const bool second_is_one = (shard.rank & second_mask) != 0U;
                    if (first_is_one != second_is_one)
                    {
                        distributed_copy_kernel<<<grid_size(impl_->local_count), threads>>>(
                            shard.real, shard.imag, shard.remote_real, shard.remote_imag, impl_->local_count);
                    }
                });
            }
            else
            {
                const std::size_t local_qubit = first_local ? first : second;
                const std::size_t distributed_qubit = first_local ? second : first;
                const std::size_t local_mask = std::size_t{1} << local_qubit;
                const std::size_t distributed_bit = distributed_qubit - local_qubits;
                const std::size_t rank_mask = std::size_t{1} << distributed_bit;
                impl_->stage_xor_partner(distributed_bit);
                impl_->launch_all([&](Impl::Shard& shard)
                {
                    swap_local_distributed_kernel<<<grid_size(impl_->local_count), threads>>>(
                        shard.real, shard.imag, shard.remote_real, shard.remote_imag,
                        impl_->local_count, local_mask, (shard.rank & rank_mask) != 0U);
                });
            }
            ++impl_->timing.qft_swap_operation_count;
        }
    }

    void CUDAMultiGpuQuantumBackend::apply_phase_flip(const std::size_t basis_index)
    {
        if (basis_index >= impl_->state_count) throw std::out_of_range("Multi-GPU phase-flip index is outside the register.");
        const std::size_t device_rank = basis_index / impl_->local_count;
        const std::size_t local_index = basis_index % impl_->local_count;
        constexpr unsigned int threads = 1U;
        Impl::Shard& shard = impl_->shards[device_rank];
        check_cuda(cudaSetDevice(shard.device), "cudaSetDevice phase flip");
        check_cuda(cudaEventRecord(shard.start), "cudaEventRecord phase start");
        phase_flip_kernel<<<1U, threads>>>(shard.real, shard.imag, local_index);
        check_cuda(cudaGetLastError(), "multi-GPU phase-flip launch");
        check_cuda(cudaEventRecord(shard.end), "cudaEventRecord phase end");
        check_cuda(cudaEventSynchronize(shard.end), "cudaEventSynchronize phase flip");
        float elapsed = 0.0F;
        check_cuda(cudaEventElapsedTime(&elapsed, shard.start, shard.end), "cudaEventElapsedTime phase flip");
        impl_->timing.kernel_time_ms += static_cast<double>(elapsed);
    }

    void CUDAMultiGpuQuantumBackend::apply_diffusion()
    {
        constexpr unsigned int threads = 256U;
        impl_->launch_all([&](Impl::Shard& shard)
        {
            partial_sum_kernel<<<static_cast<unsigned int>(shard.partial_count), threads>>>(
                shard.real, shard.imag, shard.partial_real, shard.partial_imag, impl_->local_count);
        });

        std::vector<double> host_real, host_imag;
        for (const auto& shard : impl_->shards)
        {
            check_cuda(cudaSetDevice(shard.device), "cudaSetDevice diffusion reduction");
            std::vector<double> partial_real(shard.partial_count), partial_imag(shard.partial_count);
            const auto transfer_start = Clock::now();
            check_cuda(cudaMemcpy(partial_real.data(), shard.partial_real, shard.partial_count * sizeof(double), cudaMemcpyDeviceToHost), "cudaMemcpy diffusion partial real");
            check_cuda(cudaMemcpy(partial_imag.data(), shard.partial_imag, shard.partial_count * sizeof(double), cudaMemcpyDeviceToHost), "cudaMemcpy diffusion partial imag");
            impl_->timing.transfer_time_ms += elapsed_ms(transfer_start);
            host_real.insert(host_real.end(), partial_real.begin(), partial_real.end());
            host_imag.insert(host_imag.end(), partial_imag.begin(), partial_imag.end());
        }
        const double mean_real = std::accumulate(host_real.begin(), host_real.end(), 0.0) /
                                 static_cast<double>(impl_->state_count);
        const double mean_imag = std::accumulate(host_imag.begin(), host_imag.end(), 0.0) /
                                 static_cast<double>(impl_->state_count);
        impl_->launch_all([&](Impl::Shard& shard)
        {
            diffusion_kernel<<<grid_size(impl_->local_count), threads>>>(
                shard.real, shard.imag, impl_->local_count, mean_real, mean_imag);
        });
    }
}
