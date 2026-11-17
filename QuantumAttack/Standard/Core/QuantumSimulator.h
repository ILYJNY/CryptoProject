#pragma once

#include "QuantumTypes.h"
#include "../../Backend/QuantumBackendTypes.h"
#include "../../Backend/CPU/CPUQuantumBackend.h"
#include "../../Backend/CUDA/CUDAQuantumBackend.h"
#include "../../Backend/CUDA/CUDAMultiGpuQuantumBackend.h"
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace crypto::quantum
{
    struct MeasurementResult
    {
        std::map<std::string, std::size_t> counts;
        std::size_t shots = 0;
    };

    struct QuantumGpuTiming
    {
        double kernel_time_ms = 0.0;
        double transfer_time_ms = 0.0;
        double initialization_time_ms = 0.0;
        std::size_t qft_fused_stage_count = 0U;
        std::size_t qft_swap_kernel_count = 0U;
        bool used_pinned_host_memory = false;
    };

    // Result of a projective Z-basis measurement of a single qubit (QuantumAttack 2.8).
    struct QubitMeasurement
    {
        bool outcome = false;
        double probability_of_one = 0.0;
        double outcome_probability = 0.0;
    };

    class QuantumSimulator final
    {
    public:
        explicit QuantumSimulator(
            std::size_t qubits,
            std::size_t maximum_qubits = 22U,
            QuantumExecutionOptions options = {});
        ~QuantumSimulator();

        QuantumSimulator(const QuantumSimulator&) = delete;
        QuantumSimulator& operator=(const QuantumSimulator&) = delete;

        void set_execution_options(QuantumExecutionOptions options);
        [[nodiscard]] const QuantumExecutionOptions& execution_options() const noexcept;
        [[nodiscard]] const QuantumBackendStatistics& backend_statistics() const noexcept;

        [[nodiscard]] std::size_t qubit_count() const noexcept;
        [[nodiscard]] std::size_t basis_state_count() const noexcept;
        [[nodiscard]] std::size_t state_vector_bytes() const noexcept;
        [[nodiscard]] std::size_t gate_count() const noexcept;
        [[nodiscard]] std::size_t operation_depth() const noexcept;
        [[nodiscard]] std::size_t measurement_count() const noexcept;
        [[nodiscard]] const std::vector<Complex>& state() const;

        void reset_zero();
        void set_basis_state(std::size_t basis_index);
        void apply_x(std::size_t target);
        void apply_z(std::size_t target);
        void apply_hadamard(std::size_t target);
        void apply_cnot(std::size_t control, std::size_t target);
        void apply_phase_flip(std::size_t basis_index);
        void apply_controlled_permutation(
            std::size_t control_qubit,
            const std::vector<std::size_t>& target_qubits,
            const std::vector<std::size_t>& permutation);
        void apply_diffusion();

        // These methods explicitly run a temporary single-GPU operation; the selected
        // persistent backend is not changed. CPU-only builds report unavailability.
        void apply_hadamard_gpu(std::size_t target, int device_index, QuantumGpuTiming& timing);
        void apply_phase_flip_gpu(std::size_t basis_index, int device_index, QuantumGpuTiming& timing);
        void apply_diffusion_gpu(int device_index, QuantumGpuTiming& timing);
        void apply_qft(const std::vector<std::size_t>& target_qubits);

        // QuantumAttack 2.8 additions for iterative (semiclassical-QFT) phase estimation.
        // Both operations always run on the CPU reference path. When a CUDA backend is
        // selected they are counted as CPU fallback operations, never as GPU operations.
        //
        // apply_phase_shift applies diag(1, e^{i*angle}) to the target qubit.
        void apply_phase_shift(std::size_t target, double angle_radians);
        // measure_qubit performs a mid-circuit projective measurement: it samples the
        // outcome from the caller-supplied uniform value in [0, 1), collapses the state
        // and renormalizes it. It counts as a measurement, not as a gate.
        [[nodiscard]] QubitMeasurement measure_qubit(std::size_t target, double uniform_sample);

        [[nodiscard]] std::vector<double> probabilities() const;
        [[nodiscard]] MeasurementResult measure_all(
            std::size_t shots = 1024U,
            std::uint64_t seed = 0xC0FFEEULL) const;

    private:
        void validate_qubit(std::size_t qubit) const;
        void ensure_cuda_state() const;
        void ensure_multi_gpu_state() const;
        void sync_host_from_cuda() const;
        void mark_host_state_modified() noexcept;
        void record_cpu_operation(double elapsed_ms) noexcept;
        void record_cuda_operation() const noexcept;
        void record_multi_gpu_operation() const noexcept;
        [[nodiscard]] std::string basis_label(std::size_t index) const;

        std::size_t qubits_ = 0;
        mutable std::vector<Complex> amplitudes_;
        QuantumExecutionOptions execution_options_{};
        std::unique_ptr<cpu::CPUQuantumBackend> cpu_backend_;
        mutable std::unique_ptr<cuda_backend::CUDAQuantumBackend> cuda_backend_;
        mutable std::unique_ptr<cuda_backend::CUDAMultiGpuQuantumBackend> multi_gpu_backend_;
        mutable bool cuda_state_valid_ = false;
        mutable bool cuda_state_newer_ = false;
        mutable bool multi_gpu_state_valid_ = false;
        mutable bool multi_gpu_state_newer_ = false;
        mutable QuantumGpuTiming accounted_cuda_timing_{};
        mutable cuda_backend::CudaMultiGpuTiming accounted_multi_gpu_timing_{};
        mutable QuantumBackendStatistics backend_statistics_{};
        std::size_t gate_count_ = 0;
        std::size_t operation_depth_ = 0;
        std::size_t measurement_count_ = 0;
    };
}
