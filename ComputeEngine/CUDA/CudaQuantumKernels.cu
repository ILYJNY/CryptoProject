#include "CudaQuantumKernels.h"

#include <cuda_runtime.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <stdexcept>
#include <numeric>
#include <string>
#include <vector>

namespace crypto::cuda_backend
{
    namespace
    {
        void check_cuda(const cudaError_t result, const char* operation)
        {
            if (result != cudaSuccess)
            {
                throw std::runtime_error(
                    std::string(operation) + " failed: " + cudaGetErrorString(result));
            }
        }

        class DeviceBuffer final
        {
        public:
            explicit DeviceBuffer(const std::size_t bytes)
            {
                if (bytes != 0U) check_cuda(cudaMalloc(&pointer_, bytes), "cudaMalloc");
            }
            DeviceBuffer(const DeviceBuffer&) = delete;
            DeviceBuffer& operator=(const DeviceBuffer&) = delete;
            ~DeviceBuffer() { if (pointer_ != nullptr) (void)cudaFree(pointer_); }
            [[nodiscard]] void* get() const noexcept { return pointer_; }
        private:
            void* pointer_ = nullptr;
        };

        class Event final
        {
        public:
            Event() { check_cuda(cudaEventCreate(&event_), "cudaEventCreate"); }
            Event(const Event&) = delete;
            Event& operator=(const Event&) = delete;
            ~Event() { if (event_ != nullptr) (void)cudaEventDestroy(event_); }
            [[nodiscard]] cudaEvent_t get() const noexcept { return event_; }
        private:
            cudaEvent_t event_ = nullptr;
        };

        __global__ void hadamard_kernel(
            double* real, double* imag, const std::size_t count,
            const std::size_t mask, const double scale)
        {
            const std::size_t pair = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
            if (pair >= count / 2U) return;
            const std::size_t low = (pair & (mask - 1U)) | ((pair / mask) * (mask << 1U));
            const std::size_t high = low | mask;
            const double r0 = real[low], i0 = imag[low];
            const double r1 = real[high], i1 = imag[high];
            real[low] = (r0 + r1) * scale;
            imag[low] = (i0 + i1) * scale;
            real[high] = (r0 - r1) * scale;
            imag[high] = (i0 - i1) * scale;
        }

        __global__ void phase_flip_kernel(
            double* real, double* imag, const std::size_t basis_index)
        {
            if (blockIdx.x == 0U && threadIdx.x == 0U)
            {
                real[basis_index] = -real[basis_index];
                imag[basis_index] = -imag[basis_index];
            }
        }

        __global__ void partial_sum_kernel(
            const double* real, const double* imag,
            double* partial_real, double* partial_imag,
            const std::size_t count)
        {
            __shared__ double shared_real[256];
            __shared__ double shared_imag[256];
            const unsigned int lane = threadIdx.x;
            const std::size_t index = static_cast<std::size_t>(blockIdx.x) * blockDim.x + lane;
            double sum_real = 0.0;
            double sum_imag = 0.0;
            for (std::size_t current = index; current < count;
                 current += static_cast<std::size_t>(gridDim.x) * blockDim.x)
            {
                sum_real += real[current];
                sum_imag += imag[current];
            }
            shared_real[lane] = sum_real;
            shared_imag[lane] = sum_imag;
            __syncthreads();
            for (unsigned int stride = blockDim.x / 2U; stride > 0U; stride >>= 1U)
            {
                if (lane < stride)
                {
                    shared_real[lane] += shared_real[lane + stride];
                    shared_imag[lane] += shared_imag[lane + stride];
                }
                __syncthreads();
            }
            if (lane == 0U)
            {
                partial_real[blockIdx.x] = shared_real[0];
                partial_imag[blockIdx.x] = shared_imag[0];
            }
        }

        __global__ void diffusion_kernel(
            double* real, double* imag, const std::size_t count,
            const double mean_real, const double mean_imag)
        {
            const std::size_t index = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
            const std::size_t stride = static_cast<std::size_t>(gridDim.x) * blockDim.x;
            for (std::size_t current = index; current < count; current += stride)
            {
                real[current] = 2.0 * mean_real - real[current];
                imag[current] = 2.0 * mean_imag - imag[current];
            }
        }

        void validate_state(const std::vector<double>& real, const std::vector<double>& imag)
        {
            if (real.empty() || real.size() != imag.size())
                throw std::invalid_argument("CUDA quantum state arrays must be non-empty and have equal lengths.");
        }

        void prepare_device(
            const int device_index,
            const std::vector<double>& real,
            const std::vector<double>& imag,
            DeviceBuffer& device_real,
            DeviceBuffer& device_imag,
            CudaQuantumTiming& timing)
        {
            const auto start = std::chrono::steady_clock::now();
            check_cuda(cudaSetDevice(device_index), "cudaSetDevice");
            check_cuda(cudaFree(nullptr), "CUDA context initialization");
            timing.initialization_time_ms = std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - start).count();

            const std::size_t bytes = real.size() * sizeof(double);
            Event transfer_start, transfer_end;
            check_cuda(cudaEventRecord(transfer_start.get()), "cudaEventRecord H2D start");
            check_cuda(cudaMemcpy(device_real.get(), real.data(), bytes, cudaMemcpyHostToDevice), "cudaMemcpy real H2D");
            check_cuda(cudaMemcpy(device_imag.get(), imag.data(), bytes, cudaMemcpyHostToDevice), "cudaMemcpy imag H2D");
            check_cuda(cudaEventRecord(transfer_end.get()), "cudaEventRecord H2D end");
            check_cuda(cudaEventSynchronize(transfer_end.get()), "cudaEventSynchronize H2D");
            float transfer_ms = 0.0F;
            check_cuda(cudaEventElapsedTime(&transfer_ms, transfer_start.get(), transfer_end.get()), "cudaEventElapsedTime H2D");
            timing.transfer_time_ms = static_cast<double>(transfer_ms);
        }

        void finish_device(
            const std::size_t count,
            DeviceBuffer& device_real,
            DeviceBuffer& device_imag,
            std::vector<double>& real,
            std::vector<double>& imag,
            CudaQuantumTiming& timing)
        {
            Event transfer_start, transfer_end;
            check_cuda(cudaEventRecord(transfer_start.get()), "cudaEventRecord D2H start");
            const std::size_t bytes = count * sizeof(double);
            check_cuda(cudaMemcpy(real.data(), device_real.get(), bytes, cudaMemcpyDeviceToHost), "cudaMemcpy real D2H");
            check_cuda(cudaMemcpy(imag.data(), device_imag.get(), bytes, cudaMemcpyDeviceToHost), "cudaMemcpy imag D2H");
            check_cuda(cudaEventRecord(transfer_end.get()), "cudaEventRecord D2H end");
            check_cuda(cudaEventSynchronize(transfer_end.get()), "cudaEventSynchronize D2H");
            float transfer_ms = 0.0F;
            check_cuda(cudaEventElapsedTime(&transfer_ms, transfer_start.get(), transfer_end.get()), "cudaEventElapsedTime D2H");
            timing.transfer_time_ms += static_cast<double>(transfer_ms);
        }

        [[nodiscard]] unsigned int grid_size(const std::size_t count)
        {
            constexpr std::size_t threads = 256U;
            const std::size_t blocks = (count + threads - 1U) / threads;
            return static_cast<unsigned int>(std::min<std::size_t>(blocks, 65535U));
        }
    }

    void apply_hadamard_state(
        const int device_index, std::vector<double>& real, std::vector<double>& imag,
        const std::size_t target_qubit, CudaQuantumTiming& timing)
    {
        validate_state(real, imag);
        if (real.size() < 2U || target_qubit >= 8U * sizeof(std::size_t) ||
            (std::size_t{1} << target_qubit) >= real.size())
            throw std::out_of_range("CUDA Hadamard target qubit is outside the state vector.");
        timing = {};
        const std::size_t count = real.size();
        const std::size_t bytes = count * sizeof(double);
        DeviceBuffer device_real(bytes), device_imag(bytes);
        prepare_device(device_index, real, imag, device_real, device_imag, timing);
        Event start, end;
        constexpr unsigned int threads = 256U;
        check_cuda(cudaEventRecord(start.get()), "cudaEventRecord kernel start");
        hadamard_kernel<<<grid_size(count / 2U), threads>>>(
            static_cast<double*>(device_real.get()), static_cast<double*>(device_imag.get()),
            count, std::size_t{1} << target_qubit, 0.70710678118654752440);
        check_cuda(cudaGetLastError(), "Hadamard kernel launch");
        check_cuda(cudaEventRecord(end.get()), "cudaEventRecord kernel end");
        check_cuda(cudaEventSynchronize(end.get()), "cudaEventSynchronize kernel");
        float ms = 0.0F;
        check_cuda(cudaEventElapsedTime(&ms, start.get(), end.get()), "cudaEventElapsedTime kernel");
        timing.kernel_time_ms = static_cast<double>(ms);
        finish_device(count, device_real, device_imag, real, imag, timing);
    }

    void apply_phase_flip_state(
        const int device_index, std::vector<double>& real, std::vector<double>& imag,
        const std::size_t basis_index, CudaQuantumTiming& timing)
    {
        validate_state(real, imag);
        if (basis_index >= real.size()) throw std::out_of_range("CUDA phase-flip index is outside the state vector.");
        timing = {};
        const std::size_t count = real.size();
        const std::size_t bytes = count * sizeof(double);
        DeviceBuffer device_real(bytes), device_imag(bytes);
        prepare_device(device_index, real, imag, device_real, device_imag, timing);
        Event start, end;
        check_cuda(cudaEventRecord(start.get()), "cudaEventRecord kernel start");
        phase_flip_kernel<<<1U, 1U>>>(
            static_cast<double*>(device_real.get()), static_cast<double*>(device_imag.get()), basis_index);
        check_cuda(cudaGetLastError(), "Phase-flip kernel launch");
        check_cuda(cudaEventRecord(end.get()), "cudaEventRecord kernel end");
        check_cuda(cudaEventSynchronize(end.get()), "cudaEventSynchronize kernel");
        float ms = 0.0F;
        check_cuda(cudaEventElapsedTime(&ms, start.get(), end.get()), "cudaEventElapsedTime kernel");
        timing.kernel_time_ms = static_cast<double>(ms);
        finish_device(count, device_real, device_imag, real, imag, timing);
    }

    void apply_diffusion_state(
        const int device_index, std::vector<double>& real, std::vector<double>& imag,
        CudaQuantumTiming& timing)
    {
        validate_state(real, imag);
        timing = {};
        const std::size_t count = real.size();
        const std::size_t bytes = count * sizeof(double);
        DeviceBuffer device_real(bytes), device_imag(bytes);
        prepare_device(device_index, real, imag, device_real, device_imag, timing);

        constexpr unsigned int threads = 256U;
        const unsigned int blocks = grid_size(count);
        DeviceBuffer partial_real(static_cast<std::size_t>(blocks) * sizeof(double));
        DeviceBuffer partial_imag(static_cast<std::size_t>(blocks) * sizeof(double));
        Event start, end;
        check_cuda(cudaEventRecord(start.get()), "cudaEventRecord reduction start");
        partial_sum_kernel<<<blocks, threads>>>(
            static_cast<const double*>(device_real.get()), static_cast<const double*>(device_imag.get()),
            static_cast<double*>(partial_real.get()), static_cast<double*>(partial_imag.get()), count);
        check_cuda(cudaGetLastError(), "Quantum reduction kernel launch");
        check_cuda(cudaEventRecord(end.get()), "cudaEventRecord reduction end");
        check_cuda(cudaEventSynchronize(end.get()), "cudaEventSynchronize reduction");
        float reduction_ms = 0.0F;
        check_cuda(cudaEventElapsedTime(&reduction_ms, start.get(), end.get()), "cudaEventElapsedTime reduction");

        std::vector<double> host_partial_real(blocks), host_partial_imag(blocks);
        const auto transfer_start = std::chrono::steady_clock::now();
        check_cuda(cudaMemcpy(host_partial_real.data(), partial_real.get(), blocks * sizeof(double), cudaMemcpyDeviceToHost), "cudaMemcpy partial real");
        check_cuda(cudaMemcpy(host_partial_imag.data(), partial_imag.get(), blocks * sizeof(double), cudaMemcpyDeviceToHost), "cudaMemcpy partial imag");
        const double partial_transfer_ms = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - transfer_start).count();
        const double sum_real = std::accumulate(host_partial_real.begin(), host_partial_real.end(), 0.0);
        const double sum_imag = std::accumulate(host_partial_imag.begin(), host_partial_imag.end(), 0.0);
        const double mean_real = sum_real / static_cast<double>(count);
        const double mean_imag = sum_imag / static_cast<double>(count);

        check_cuda(cudaEventRecord(start.get()), "cudaEventRecord diffusion start");
        diffusion_kernel<<<blocks, threads>>>(
            static_cast<double*>(device_real.get()), static_cast<double*>(device_imag.get()),
            count, mean_real, mean_imag);
        check_cuda(cudaGetLastError(), "Quantum diffusion kernel launch");
        check_cuda(cudaEventRecord(end.get()), "cudaEventRecord diffusion end");
        check_cuda(cudaEventSynchronize(end.get()), "cudaEventSynchronize diffusion");
        float diffusion_ms = 0.0F;
        check_cuda(cudaEventElapsedTime(&diffusion_ms, start.get(), end.get()), "cudaEventElapsedTime diffusion");
        timing.kernel_time_ms = static_cast<double>(reduction_ms) + static_cast<double>(diffusion_ms);
        timing.transfer_time_ms += partial_transfer_ms;
        finish_device(count, device_real, device_imag, real, imag, timing);
    }
}
