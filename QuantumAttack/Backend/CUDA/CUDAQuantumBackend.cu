#include "CUDAQuantumBackend.h"

#include <cuda_runtime.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <numeric>
#include <stdexcept>
#include <string>
#include <vector>

namespace crypto::quantum::cuda_backend
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

        class Event final
        {
        public:
            Event() { check_cuda(cudaEventCreate(&event_), "cudaEventCreate"); }
            ~Event() { if (event_ != nullptr) (void)cudaEventDestroy(event_); }
            Event(const Event&) = delete;
            Event& operator=(const Event&) = delete;
            [[nodiscard]] cudaEvent_t get() const noexcept { return event_; }
        private:
            cudaEvent_t event_ = nullptr;
        };

        __global__ void x_gate_kernel(double* real, double* imag, const std::size_t count,
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

        __global__ void z_gate_kernel(double* real, double* imag, const std::size_t count,
                                      const std::size_t mask)
        {
            const std::size_t stride = static_cast<std::size_t>(gridDim.x) * blockDim.x;
            for (std::size_t index = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
                 index < count; index += stride)
            {
                if ((index & mask) != 0U) { real[index] = -real[index]; imag[index] = -imag[index]; }
            }
        }

        __global__ void hadamard_kernel(double* real, double* imag, const std::size_t count,
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
                real[low] = (r0 + r1) * scale;
                imag[low] = (i0 + i1) * scale;
                real[high] = (r0 - r1) * scale;
                imag[high] = (i0 - i1) * scale;
            }
        }

        __global__ void cnot_kernel(double* real, double* imag, const std::size_t count,
                                    const std::size_t control_mask, const std::size_t target_mask)
        {
            const std::size_t stride = static_cast<std::size_t>(gridDim.x) * blockDim.x;
            for (std::size_t index = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
                 index < count; index += stride)
            {
                if ((index & control_mask) != 0U && (index & target_mask) == 0U)
                {
                    const std::size_t partner = index | target_mask;
                    const double r = real[index]; real[index] = real[partner]; real[partner] = r;
                    const double i = imag[index]; imag[index] = imag[partner]; imag[partner] = i;
                }
            }
        }

        __global__ void controlled_phase_kernel(double* real, double* imag, const std::size_t count,
                                                const std::size_t control_mask, const std::size_t target_mask,
                                                const double cosine, const double sine)
        {
            const std::size_t stride = static_cast<std::size_t>(gridDim.x) * blockDim.x;
            for (std::size_t index = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
                 index < count; index += stride)
            {
                if ((index & control_mask) != 0U && (index & target_mask) != 0U)
                {
                    const double r = real[index];
                    const double i = imag[index];
                    real[index] = r * cosine - i * sine;
                    imag[index] = r * sine + i * cosine;
                }
            }
        }

        // One kernel performs H(target) followed by every controlled-phase gate
        // belonging to the same QFT stage. The controls are read from one small
        // device-side qubit-index array uploaded once per QFT invocation.
        __global__ void fused_qft_stage_kernel(
            double* real, double* imag, const std::size_t count,
            const std::size_t target_mask, const std::size_t* qft_qubits,
            const std::size_t control_count, const std::size_t target_position,
            const double scale, const double pi)
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
                const double low_real = (r0 + r1) * scale;
                const double low_imag = (i0 + i1) * scale;
                double high_real = (r0 - r1) * scale;
                double high_imag = (i0 - i1) * scale;

                double phase = 0.0;
                for (std::size_t k = 0U; k < control_count; ++k)
                {
                    const std::size_t control_mask = std::size_t{1} << qft_qubits[k];
                    if ((low & control_mask) != 0U)
                    {
                        const std::size_t denominator = std::size_t{1} << (target_position - k);
                        phase += pi / static_cast<double>(denominator);
                    }
                }
                const double cosine = cos(phase);
                const double sine = sin(phase);
                real[low] = low_real;
                imag[low] = low_imag;
                real[high] = high_real * cosine - high_imag * sine;
                imag[high] = high_real * sine + high_imag * cosine;
            }
        }

        // A SWAP permutation needs one pass, rather than three CNOT passes.
        __global__ void swap_qubits_kernel(double* real, double* imag,
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

        __global__ void phase_flip_kernel(double* real, double* imag, const std::size_t index)
        {
            if (blockIdx.x == 0U && threadIdx.x == 0U)
            {
                real[index] = -real[index];
                imag[index] = -imag[index];
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
            double sum_real = 0.0;
            double sum_imag = 0.0;
            for (std::size_t index = first; index < count; index += stride)
            {
                sum_real += real[index];
                sum_imag += imag[index];
            }
            shared_real[lane] = sum_real;
            shared_imag[lane] = sum_imag;
            __syncthreads();
            for (unsigned int offset = blockDim.x / 2U; offset > 0U; offset >>= 1U)
            {
                if (lane < offset)
                {
                    shared_real[lane] += shared_real[lane + offset];
                    shared_imag[lane] += shared_imag[lane + offset];
                }
                __syncthreads();
            }
            if (lane == 0U)
            {
                partial_real[blockIdx.x] = shared_real[0];
                partial_imag[blockIdx.x] = shared_imag[0];
            }
        }

        __global__ void diffusion_kernel(double* real, double* imag, const std::size_t count,
                                         const double mean_real, const double mean_imag)
        {
            const std::size_t stride = static_cast<std::size_t>(gridDim.x) * blockDim.x;
            for (std::size_t index = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
                 index < count; index += stride)
            {
                real[index] = 2.0 * mean_real - real[index];
                imag[index] = 2.0 * mean_imag - imag[index];
            }
        }

        [[nodiscard]] unsigned int grid_size(const std::size_t count)
        {
            constexpr std::size_t threads = 256U;
            const std::size_t blocks = (count + threads - 1U) / threads;
            return static_cast<unsigned int>(std::clamp<std::size_t>(blocks, 1U, 65535U));
        }
    }

    struct CUDAQuantumBackend::Impl
    {
        explicit Impl(const int requested_device) : device(requested_device)
        {
            const auto start = std::chrono::steady_clock::now();
            int count = 0;
            check_cuda(cudaGetDeviceCount(&count), "cudaGetDeviceCount");
            if (device < 0 || device >= count) throw std::out_of_range("The selected CUDA device index is unavailable.");
            check_cuda(cudaSetDevice(device), "cudaSetDevice");
            check_cuda(cudaFree(nullptr), "CUDA context initialization");
            timing.initialization_time_ms = std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - start).count();
            check_cuda(cudaEventCreate(&kernel_start), "cudaEventCreate kernel start");
            check_cuda(cudaEventCreate(&kernel_end), "cudaEventCreate kernel end");
        }

        ~Impl()
        {
            (void)cudaSetDevice(device);
            if (device_real != nullptr) (void)cudaFree(device_real);
            if (device_imag != nullptr) (void)cudaFree(device_imag);
            if (device_qft_qubits != nullptr) (void)cudaFree(device_qft_qubits);
            if (host_staging_registered)
            {
                (void)cudaHostUnregister(host_real.data());
                (void)cudaHostUnregister(host_imag.data());
            }
            if (kernel_start != nullptr) (void)cudaEventDestroy(kernel_start);
            if (kernel_end != nullptr) (void)cudaEventDestroy(kernel_end);
        }

        void ensure_size(const std::size_t requested_count)
        {
            if (requested_count == count)
            {
                ensure_host_staging(requested_count);
                return;
            }
            if (device_real != nullptr) check_cuda(cudaFree(device_real), "cudaFree real");
            if (device_imag != nullptr) check_cuda(cudaFree(device_imag), "cudaFree imag");
            device_real = nullptr;
            device_imag = nullptr;
            count = requested_count;
            check_cuda(cudaMalloc(reinterpret_cast<void**>(&device_real), count * sizeof(double)), "cudaMalloc real");
            try
            {
                check_cuda(cudaMalloc(reinterpret_cast<void**>(&device_imag), count * sizeof(double)), "cudaMalloc imag");
            }
            catch (...)
            {
                (void)cudaFree(device_real);
                device_real = nullptr;
                count = 0U;
                throw;
            }
            ensure_host_staging(requested_count);
        }

        void ensure_host_staging(const std::size_t requested_count)
        {
            if (host_real.size() == requested_count && host_imag.size() == requested_count) return;
            if (host_staging_registered)
            {
                (void)cudaHostUnregister(host_real.data());
                (void)cudaHostUnregister(host_imag.data());
                host_staging_registered = false;
            }
            host_real.resize(requested_count);
            host_imag.resize(requested_count);
            if (requested_count == 0U) return;
            const std::size_t bytes = requested_count * sizeof(double);
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

        void ensure_qft_qubits(const std::vector<std::size_t>& qubits)
        {
            if (qubits.size() > qft_capacity)
            {
                if (device_qft_qubits != nullptr) check_cuda(cudaFree(device_qft_qubits), "cudaFree QFT qubits");
                device_qft_qubits = nullptr;
                check_cuda(cudaMalloc(reinterpret_cast<void**>(&device_qft_qubits),
                                      qubits.size() * sizeof(std::size_t)), "cudaMalloc QFT qubits");
                qft_capacity = qubits.size();
            }
            check_cuda(cudaMemcpy(device_qft_qubits, qubits.data(),
                                  qubits.size() * sizeof(std::size_t), cudaMemcpyHostToDevice),
                       "cudaMemcpy QFT qubits");
        }

        template <typename Launch>
        void timed_kernel(Launch&& launch)
        {
            check_cuda(cudaEventRecord(kernel_start), "cudaEventRecord kernel start");
            launch();
            check_cuda(cudaGetLastError(), "CUDA quantum kernel launch");
            check_cuda(cudaEventRecord(kernel_end), "cudaEventRecord kernel end");
            check_cuda(cudaEventSynchronize(kernel_end), "cudaEventSynchronize kernel");
            float elapsed = 0.0F;
            check_cuda(cudaEventElapsedTime(&elapsed, kernel_start, kernel_end), "cudaEventElapsedTime kernel");
            timing.kernel_time_ms += static_cast<double>(elapsed);
        }

        int device = 0;
        std::size_t count = 0U;
        double* device_real = nullptr;
        double* device_imag = nullptr;
        std::size_t* device_qft_qubits = nullptr;
        std::size_t qft_capacity = 0U;
        std::vector<double> host_real;
        std::vector<double> host_imag;
        bool host_staging_registered = false;
        cudaEvent_t kernel_start = nullptr;
        cudaEvent_t kernel_end = nullptr;
        CudaQuantumTiming timing{};
    };

    CUDAQuantumBackend::CUDAQuantumBackend(const int device_index)
        : impl_(std::make_unique<Impl>(device_index))
    {
    }

    CUDAQuantumBackend::~CUDAQuantumBackend() = default;

    bool CUDAQuantumBackend::is_available() noexcept
    {
        int count = 0;
        return cudaGetDeviceCount(&count) == cudaSuccess && count > 0;
    }

    int CUDAQuantumBackend::device_index() const noexcept { return impl_->device; }
    std::size_t CUDAQuantumBackend::state_size() const noexcept { return impl_->count; }
    const CudaQuantumTiming& CUDAQuantumBackend::timing() const noexcept { return impl_->timing; }

    void CUDAQuantumBackend::upload(const std::vector<Complex>& state)
    {
        if (state.empty()) throw std::invalid_argument("Cannot upload an empty quantum state.");
        check_cuda(cudaSetDevice(impl_->device), "cudaSetDevice");
        impl_->ensure_size(state.size());
        for (std::size_t index = 0U; index < state.size(); ++index)
        {
            impl_->host_real[index] = state[index].real();
            impl_->host_imag[index] = state[index].imag();
        }
        const auto start = std::chrono::steady_clock::now();
        const std::size_t bytes = state.size() * sizeof(double);
        if (impl_->host_staging_registered)
        {
            check_cuda(cudaMemcpyAsync(impl_->device_real, impl_->host_real.data(), bytes,
                                       cudaMemcpyHostToDevice), "cudaMemcpyAsync real H2D");
            check_cuda(cudaMemcpyAsync(impl_->device_imag, impl_->host_imag.data(), bytes,
                                       cudaMemcpyHostToDevice), "cudaMemcpyAsync imag H2D");
        }
        else
        {
            check_cuda(cudaMemcpy(impl_->device_real, impl_->host_real.data(), bytes,
                                  cudaMemcpyHostToDevice), "cudaMemcpy real H2D");
            check_cuda(cudaMemcpy(impl_->device_imag, impl_->host_imag.data(), bytes,
                                  cudaMemcpyHostToDevice), "cudaMemcpy imag H2D");
        }
        check_cuda(cudaDeviceSynchronize(), "cudaDeviceSynchronize upload");
        impl_->timing.transfer_time_ms += std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - start).count();
    }

    void CUDAQuantumBackend::download(std::vector<Complex>& state)
    {
        if (impl_->count == 0U) throw std::logic_error("The CUDA state has not been uploaded.");
        check_cuda(cudaSetDevice(impl_->device), "cudaSetDevice");
        const auto start = std::chrono::steady_clock::now();
        const std::size_t bytes = impl_->count * sizeof(double);
        if (impl_->host_staging_registered)
        {
            check_cuda(cudaMemcpyAsync(impl_->host_real.data(), impl_->device_real, bytes,
                                       cudaMemcpyDeviceToHost), "cudaMemcpyAsync real D2H");
            check_cuda(cudaMemcpyAsync(impl_->host_imag.data(), impl_->device_imag, bytes,
                                       cudaMemcpyDeviceToHost), "cudaMemcpyAsync imag D2H");
        }
        else
        {
            check_cuda(cudaMemcpy(impl_->host_real.data(), impl_->device_real, bytes,
                                  cudaMemcpyDeviceToHost), "cudaMemcpy real D2H");
            check_cuda(cudaMemcpy(impl_->host_imag.data(), impl_->device_imag, bytes,
                                  cudaMemcpyDeviceToHost), "cudaMemcpy imag D2H");
        }
        check_cuda(cudaDeviceSynchronize(), "cudaDeviceSynchronize download");
        state.resize(impl_->count);
        for (std::size_t index = 0U; index < impl_->count; ++index)
            state[index] = Complex{impl_->host_real[index], impl_->host_imag[index]};
        impl_->timing.transfer_time_ms += std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - start).count();
    }

    void CUDAQuantumBackend::apply_x(const std::size_t target_qubit)
    {
        if (impl_->count < 2U || target_qubit >= sizeof(std::size_t) * 8U ||
            (std::size_t{1} << target_qubit) >= impl_->count)
            throw std::out_of_range("CUDA X target qubit is outside the state vector.");
        check_cuda(cudaSetDevice(impl_->device), "cudaSetDevice");
        constexpr unsigned int threads = 256U;
        impl_->timed_kernel([&]()
        {
            x_gate_kernel<<<grid_size(impl_->count / 2U), threads>>>(
                impl_->device_real, impl_->device_imag, impl_->count, std::size_t{1} << target_qubit);
        });
    }

    void CUDAQuantumBackend::apply_z(const std::size_t target_qubit)
    {
        if (impl_->count < 2U || target_qubit >= sizeof(std::size_t) * 8U ||
            (std::size_t{1} << target_qubit) >= impl_->count)
            throw std::out_of_range("CUDA Z target qubit is outside the state vector.");
        check_cuda(cudaSetDevice(impl_->device), "cudaSetDevice");
        constexpr unsigned int threads = 256U;
        impl_->timed_kernel([&]()
        {
            z_gate_kernel<<<grid_size(impl_->count), threads>>>(
                impl_->device_real, impl_->device_imag, impl_->count, std::size_t{1} << target_qubit);
        });
    }

    void CUDAQuantumBackend::apply_hadamard(const std::size_t target_qubit)
    {
        if (impl_->count < 2U || target_qubit >= sizeof(std::size_t) * 8U ||
            (std::size_t{1} << target_qubit) >= impl_->count)
            throw std::out_of_range("CUDA Hadamard target qubit is outside the state vector.");
        check_cuda(cudaSetDevice(impl_->device), "cudaSetDevice");
        constexpr unsigned int threads = 256U;
        impl_->timed_kernel([&]()
        {
            hadamard_kernel<<<grid_size(impl_->count / 2U), threads>>>(
                impl_->device_real, impl_->device_imag, impl_->count,
                std::size_t{1} << target_qubit, 0.70710678118654752440);
        });
    }

    void CUDAQuantumBackend::apply_cnot(const std::size_t control_qubit, const std::size_t target_qubit)
    {
        if (control_qubit == target_qubit) throw std::invalid_argument("CNOT control and target must differ.");
        if (impl_->count < 2U || control_qubit >= sizeof(std::size_t) * 8U || target_qubit >= sizeof(std::size_t) * 8U ||
            (std::size_t{1} << control_qubit) >= impl_->count || (std::size_t{1} << target_qubit) >= impl_->count)
            throw std::out_of_range("CUDA CNOT qubit is outside the state vector.");
        check_cuda(cudaSetDevice(impl_->device), "cudaSetDevice");
        constexpr unsigned int threads = 256U;
        impl_->timed_kernel([&]()
        {
            cnot_kernel<<<grid_size(impl_->count), threads>>>(
                impl_->device_real, impl_->device_imag, impl_->count,
                std::size_t{1} << control_qubit, std::size_t{1} << target_qubit);
        });
    }

    void CUDAQuantumBackend::apply_controlled_phase(
        const std::size_t control_qubit, const std::size_t target_qubit, const double angle)
    {
        if (control_qubit == target_qubit) throw std::invalid_argument("Controlled-phase qubits must differ.");
        if (control_qubit >= sizeof(std::size_t) * 8U || target_qubit >= sizeof(std::size_t) * 8U ||
            (std::size_t{1} << control_qubit) >= impl_->count || (std::size_t{1} << target_qubit) >= impl_->count)
            throw std::out_of_range("CUDA controlled-phase qubit is outside the state vector.");
        check_cuda(cudaSetDevice(impl_->device), "cudaSetDevice");
        constexpr unsigned int threads = 256U;
        impl_->timed_kernel([&]()
        {
            controlled_phase_kernel<<<grid_size(impl_->count), threads>>>(
                impl_->device_real, impl_->device_imag, impl_->count,
                std::size_t{1} << control_qubit, std::size_t{1} << target_qubit, std::cos(angle), std::sin(angle));
        });
    }

    void CUDAQuantumBackend::apply_qft(const std::vector<std::size_t>& target_qubits)
    {
        if (target_qubits.empty()) throw std::invalid_argument("QFT requires at least one target qubit.");
        if (impl_->count == 0U) throw std::logic_error("The CUDA state has not been uploaded.");
        if (target_qubits.size() >= sizeof(std::size_t) * 8U)
            throw std::length_error("The QFT target register is too large.");
        std::size_t qubit_count = 0U;
        for (std::size_t value = impl_->count; value > 1U; value >>= 1U) ++qubit_count;
        std::vector<bool> seen(qubit_count, false);
        for (const std::size_t q : target_qubits)
        {
            if (q >= seen.size() || seen[q])
                throw std::invalid_argument("QFT target qubits must be valid and unique.");
            seen[q] = true;
        }
        check_cuda(cudaSetDevice(impl_->device), "cudaSetDevice");
        impl_->ensure_qft_qubits(target_qubits);
        constexpr unsigned int threads = 256U;
        constexpr double scale = 0.70710678118654752440;
        constexpr double pi = 3.1415926535897932384626433832795;
        const std::size_t n = target_qubits.size();
        for (std::size_t j = n; j-- > 0U;)
        {
            const std::size_t target_mask = std::size_t{1} << target_qubits[j];
            impl_->timed_kernel([&]()
            {
                fused_qft_stage_kernel<<<grid_size(impl_->count / 2U), threads>>>(
                    impl_->device_real, impl_->device_imag, impl_->count, target_mask,
                    impl_->device_qft_qubits, j, j, scale, pi);
            });
            ++impl_->timing.qft_fused_stage_count;
        }
        for (std::size_t i = 0U; i < n / 2U; ++i)
        {
            const std::size_t first_mask = std::size_t{1} << target_qubits[i];
            const std::size_t second_mask = std::size_t{1} << target_qubits[n - 1U - i];
            impl_->timed_kernel([&]()
            {
                swap_qubits_kernel<<<grid_size(impl_->count), threads>>>(
                    impl_->device_real, impl_->device_imag, impl_->count, first_mask, second_mask);
            });
            ++impl_->timing.qft_swap_kernel_count;
        }
    }

    void CUDAQuantumBackend::apply_phase_flip(const std::size_t basis_index)
    {
        if (basis_index >= impl_->count) throw std::out_of_range("CUDA phase-flip index is outside the state vector.");
        check_cuda(cudaSetDevice(impl_->device), "cudaSetDevice");
        impl_->timed_kernel([&]()
        {
            phase_flip_kernel<<<1U, 1U>>>(impl_->device_real, impl_->device_imag, basis_index);
        });
    }

    void CUDAQuantumBackend::apply_diffusion()
    {
        if (impl_->count == 0U) throw std::logic_error("The CUDA state has not been uploaded.");
        check_cuda(cudaSetDevice(impl_->device), "cudaSetDevice");
        constexpr unsigned int threads = 256U;
        const unsigned int blocks = grid_size(impl_->count);
        double* partial_real = nullptr;
        double* partial_imag = nullptr;
        check_cuda(cudaMalloc(reinterpret_cast<void**>(&partial_real), blocks * sizeof(double)), "cudaMalloc partial real");
        try
        {
            check_cuda(cudaMalloc(reinterpret_cast<void**>(&partial_imag), blocks * sizeof(double)), "cudaMalloc partial imag");
            impl_->timed_kernel([&]()
            {
                partial_sum_kernel<<<blocks, threads>>>(impl_->device_real, impl_->device_imag,
                                                        partial_real, partial_imag, impl_->count);
            });
            std::vector<double> host_partial_real(blocks), host_partial_imag(blocks);
            const auto transfer_start = std::chrono::steady_clock::now();
            check_cuda(cudaMemcpy(host_partial_real.data(), partial_real, blocks * sizeof(double), cudaMemcpyDeviceToHost), "cudaMemcpy partial real D2H");
            check_cuda(cudaMemcpy(host_partial_imag.data(), partial_imag, blocks * sizeof(double), cudaMemcpyDeviceToHost), "cudaMemcpy partial imag D2H");
            impl_->timing.transfer_time_ms += std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - transfer_start).count();

            const double mean_real = std::accumulate(host_partial_real.begin(), host_partial_real.end(), 0.0) /
                                     static_cast<double>(impl_->count);
            const double mean_imag = std::accumulate(host_partial_imag.begin(), host_partial_imag.end(), 0.0) /
                                     static_cast<double>(impl_->count);
            impl_->timed_kernel([&]()
            {
                diffusion_kernel<<<blocks, threads>>>(impl_->device_real, impl_->device_imag,
                                                      impl_->count, mean_real, mean_imag);
            });
        }
        catch (...)
        {
            if (partial_real != nullptr) (void)cudaFree(partial_real);
            if (partial_imag != nullptr) (void)cudaFree(partial_imag);
            throw;
        }
        if (partial_real != nullptr) check_cuda(cudaFree(partial_real), "cudaFree partial real");
        if (partial_imag != nullptr) check_cuda(cudaFree(partial_imag), "cudaFree partial imag");
    }
}
