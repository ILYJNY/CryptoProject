#pragma once

#include "../../Standard/Core/QuantumTypes.h"

#include <cstddef>
#include <memory>
#include <vector>

namespace crypto::quantum::cuda_backend
{
    struct CudaQuantumTiming
    {
        double kernel_time_ms = 0.0;
        double transfer_time_ms = 0.0;
        double initialization_time_ms = 0.0;
        std::size_t qft_fused_stage_count = 0U;
        std::size_t qft_swap_kernel_count = 0U;
        bool used_pinned_host_memory = false;
    };

    // Keeps the state vector in device memory between gates. Upload and download
    // happen only when the caller explicitly synchronizes the host representation.
    class CUDAQuantumBackend final
    {
    public:
        explicit CUDAQuantumBackend(int device_index = 0);
        ~CUDAQuantumBackend();

        CUDAQuantumBackend(const CUDAQuantumBackend&) = delete;
        CUDAQuantumBackend& operator=(const CUDAQuantumBackend&) = delete;

        [[nodiscard]] static bool is_available() noexcept;
        [[nodiscard]] int device_index() const noexcept;
        [[nodiscard]] std::size_t state_size() const noexcept;
        [[nodiscard]] const CudaQuantumTiming& timing() const noexcept;

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
