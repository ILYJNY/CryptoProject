#pragma once

#include <cstddef>
#include <vector>

namespace crypto::cuda_backend
{
    struct CudaQuantumTiming
    {
        double kernel_time_ms = 0.0;
        double transfer_time_ms = 0.0;
        double initialization_time_ms = 0.0;
    };

    void apply_hadamard_state(
        int device_index,
        std::vector<double>& real,
        std::vector<double>& imag,
        std::size_t target_qubit,
        CudaQuantumTiming& timing);

    void apply_phase_flip_state(
        int device_index,
        std::vector<double>& real,
        std::vector<double>& imag,
        std::size_t basis_index,
        CudaQuantumTiming& timing);

    void apply_diffusion_state(
        int device_index,
        std::vector<double>& real,
        std::vector<double>& imag,
        CudaQuantumTiming& timing);
}
