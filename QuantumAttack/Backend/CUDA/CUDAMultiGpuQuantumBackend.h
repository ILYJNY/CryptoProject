#pragma once

#include "../../Standard/Core/QuantumTypes.h"

#include <cstddef>
#include <memory>
#include <vector>

namespace crypto::quantum::cuda_backend
{
    struct CudaMultiGpuTiming
    {
        // Sum of kernel execution time across devices (not wall-clock time).
        double kernel_time_ms = 0.0;
        // Host-to-device and device-to-host transfers, including fallback staging.
        double transfer_time_ms = 0.0;
        // Time spent copying chunks between GPUs (direct P2P and host-staged).
        double inter_gpu_transfer_time_ms = 0.0;
        // Wall time around distributed kernel launches and synchronization.
        double parallel_kernel_wall_time_ms = 0.0;
        double initialization_time_ms = 0.0;
        std::size_t gpu_count = 0U;
        std::size_t peer_copy_count = 0U;
        std::size_t host_staged_copy_count = 0U;
        std::size_t qft_fused_stage_count = 0U;
        std::size_t qft_swap_operation_count = 0U;
        bool used_pinned_host_memory = false;
    };

    // Distributes ONE state vector over a power-of-two number of CUDA devices.
    // Each device owns a contiguous shard. Gates on partition bits exchange partner
    // shards before launching kernels; all exchanges complete before any shard is
    // modified, preserving the gate's global-state semantics.
    class CUDAMultiGpuQuantumBackend final
    {
    public:
        explicit CUDAMultiGpuQuantumBackend(std::size_t qubits, std::vector<int> device_indices = {});
        ~CUDAMultiGpuQuantumBackend();

        CUDAMultiGpuQuantumBackend(const CUDAMultiGpuQuantumBackend&) = delete;
        CUDAMultiGpuQuantumBackend& operator=(const CUDAMultiGpuQuantumBackend&) = delete;

        [[nodiscard]] static bool is_available() noexcept;
        [[nodiscard]] static std::vector<int> available_devices();
        [[nodiscard]] const std::vector<int>& device_indices() const noexcept;
        [[nodiscard]] std::size_t state_size() const noexcept;
        [[nodiscard]] std::size_t local_state_size() const noexcept;
        [[nodiscard]] std::size_t distributed_qubit_count() const noexcept;
        [[nodiscard]] const CudaMultiGpuTiming& timing() const noexcept;

        void upload(const std::vector<Complex>& state);
        void download(std::vector<Complex>& state);
        void apply_x(std::size_t target_qubit);
        void apply_z(std::size_t target_qubit);
        void apply_hadamard(std::size_t target_qubit);
        void apply_cnot(std::size_t control_qubit, std::size_t target_qubit);
        void apply_controlled_phase(std::size_t control_qubit, std::size_t target_qubit, double angle);
        void apply_qft(const std::vector<std::size_t>& target_qubits);
        void apply_phase_flip(std::size_t basis_index);
        void apply_diffusion();

    private:
        struct Impl;
        std::unique_ptr<Impl> impl_;
    };
}
