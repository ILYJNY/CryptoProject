#pragma once

#include "QuantumThreadPool.h"
#include "../../Standard/Core/QuantumTypes.h"

#include <cstddef>
#include <vector>

namespace crypto::quantum::cpu
{
    class CPUQuantumBackend final
    {
    public:
        explicit CPUQuantumBackend(std::size_t thread_count = 0U);

        [[nodiscard]] std::size_t thread_count() const noexcept;

        void apply_x(std::vector<Complex>& state, std::size_t target) const;
        void apply_z(std::vector<Complex>& state, std::size_t target) const;
        void apply_hadamard(std::vector<Complex>& state, std::size_t target) const;
        void apply_cnot(std::vector<Complex>& state, std::size_t control, std::size_t target) const;
        void apply_phase_flip(std::vector<Complex>& state, std::size_t basis_index) const;
        void apply_controlled_permutation(
            std::vector<Complex>& state,
            std::size_t total_qubits,
            std::size_t control_qubit,
            const std::vector<std::size_t>& target_qubits,
            const std::vector<std::size_t>& permutation) const;
        void apply_diffusion(std::vector<Complex>& state) const;
        void apply_qft(
            std::vector<Complex>& state,
            std::size_t total_qubits,
            const std::vector<std::size_t>& target_qubits) const;

    private:
        mutable QuantumThreadPool pool_;
    };
}
