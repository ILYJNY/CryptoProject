#include "CPUQuantumBackend.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <numbers>
#include <stdexcept>

namespace crypto::quantum::cpu
{
    namespace
    {
        [[nodiscard]] std::size_t insert_zero_bit(const std::size_t compact_index, const std::size_t bit)
        {
            const std::size_t low_mask = (std::size_t{1} << bit) - 1U;
            return (compact_index & low_mask) | ((compact_index & ~low_mask) << 1U);
        }

        void validate_state(const std::vector<Complex>& state)
        {
            if (state.empty() || (state.size() & (state.size() - 1U)) != 0U)
            {
                throw std::invalid_argument("A quantum state vector must have a non-zero power-of-two size.");
            }
        }

        void validate_qubit(const std::vector<Complex>& state, const std::size_t target)
        {
            validate_state(state);
            std::size_t count = 0U;
            for (std::size_t value = state.size(); value > 1U; value >>= 1U) ++count;
            if (target >= count) throw std::out_of_range("The qubit index is outside the state vector.");
        }
    }

    CPUQuantumBackend::CPUQuantumBackend(const std::size_t thread_count)
        : pool_(thread_count)
    {
    }

    std::size_t CPUQuantumBackend::thread_count() const noexcept
    {
        return pool_.thread_count();
    }

    void CPUQuantumBackend::apply_x(std::vector<Complex>& state, const std::size_t target) const
    {
        validate_qubit(state, target);
        const std::size_t pair_count = state.size() / 2U;
        const std::size_t mask = std::size_t{1} << target;
        pool_.parallel_for(0U, pair_count, [&](const std::size_t pair)
        {
            const std::size_t low = insert_zero_bit(pair, target);
            std::swap(state[low], state[low | mask]);
        }, 2048U);
    }

    void CPUQuantumBackend::apply_z(std::vector<Complex>& state, const std::size_t target) const
    {
        validate_qubit(state, target);
        const std::size_t mask = std::size_t{1} << target;
        pool_.parallel_for(0U, state.size(), [&](const std::size_t index)
        {
            if ((index & mask) != 0U) state[index] = -state[index];
        }, 4096U);
    }

    void CPUQuantumBackend::apply_hadamard(std::vector<Complex>& state, const std::size_t target) const
    {
        validate_qubit(state, target);
        constexpr double inverse_sqrt_two = 0.70710678118654752440;
        const std::size_t mask = std::size_t{1} << target;
        pool_.parallel_for(0U, state.size() / 2U, [&](const std::size_t pair)
        {
            const std::size_t low = insert_zero_bit(pair, target);
            const std::size_t high = low | mask;
            const Complex zero = state[low];
            const Complex one = state[high];
            state[low] = (zero + one) * inverse_sqrt_two;
            state[high] = (zero - one) * inverse_sqrt_two;
        }, 2048U);
    }

    void CPUQuantumBackend::apply_cnot(
        std::vector<Complex>& state,
        const std::size_t control,
        const std::size_t target) const
    {
        validate_qubit(state, control);
        validate_qubit(state, target);
        if (control == target) throw std::invalid_argument("CNOT control and target must be different qubits.");
        const std::size_t control_mask = std::size_t{1} << control;
        const std::size_t target_mask = std::size_t{1} << target;
        pool_.parallel_for(0U, state.size(), [&](const std::size_t index)
        {
            if ((index & control_mask) != 0U && (index & target_mask) == 0U)
            {
                std::swap(state[index], state[index | target_mask]);
            }
        }, 4096U);
    }

    void CPUQuantumBackend::apply_phase_flip(std::vector<Complex>& state, const std::size_t basis_index) const
    {
        validate_state(state);
        if (basis_index >= state.size()) throw std::out_of_range("The phase-flip basis index is outside the register.");
        state[basis_index] = -state[basis_index];
    }

    void CPUQuantumBackend::apply_controlled_permutation(
        std::vector<Complex>& state,
        const std::size_t total_qubits,
        const std::size_t control_qubit,
        const std::vector<std::size_t>& target_qubits,
        const std::vector<std::size_t>& permutation) const
    {
        validate_state(state);
        if (total_qubits >= std::numeric_limits<std::size_t>::digits ||
            (std::size_t{1} << total_qubits) != state.size())
            throw std::invalid_argument("The total qubit count does not match the state vector.");
        if (control_qubit >= total_qubits || target_qubits.empty())
            throw std::invalid_argument("The controlled permutation register is invalid.");

        std::vector<bool> selected(total_qubits, false);
        selected[control_qubit] = true;
        std::size_t target_mask = 0U;
        for (const std::size_t qubit : target_qubits)
        {
            if (qubit >= total_qubits || selected[qubit])
                throw std::invalid_argument("Controlled permutation qubits must be unique and exclude the control.");
            selected[qubit] = true;
            target_mask |= std::size_t{1} << qubit;
        }
        if (target_qubits.size() >= std::numeric_limits<std::size_t>::digits)
            throw std::length_error("The controlled permutation target register is too large.");
        const std::size_t dimension = std::size_t{1} << target_qubits.size();
        if (permutation.size() != dimension)
            throw std::invalid_argument("The permutation size does not match the target register.");
        std::vector<bool> seen(dimension, false);
        for (const std::size_t mapped : permutation)
        {
            if (mapped >= dimension || seen[mapped])
                throw std::invalid_argument("The supplied mapping is not a bijective permutation.");
            seen[mapped] = true;
        }

        std::vector<std::size_t> offsets(dimension, 0U);
        for (std::size_t pattern = 0U; pattern < dimension; ++pattern)
        {
            for (std::size_t bit = 0U; bit < target_qubits.size(); ++bit)
                if ((pattern & (std::size_t{1} << bit)) != 0U)
                    offsets[pattern] |= std::size_t{1} << target_qubits[bit];
        }

        // Read from an immutable snapshot: this implements arbitrary permutations,
        // including cycles longer than two, without in-place overwrite hazards.
        const std::vector<Complex> input = state;
        const std::size_t control_mask = std::size_t{1} << control_qubit;
        pool_.parallel_for(0U, state.size(), [&](const std::size_t base)
        {
            if ((base & control_mask) == 0U || (base & target_mask) != 0U) return;
            std::vector<Complex> source(dimension);
            for (std::size_t value = 0U; value < dimension; ++value)
                source[value] = input[base | offsets[value]];
            for (std::size_t value = 0U; value < dimension; ++value)
                state[base | offsets[permutation[value]]] = source[value];
        }, 1U);
    }

    void CPUQuantumBackend::apply_diffusion(std::vector<Complex>& state) const
    {
        validate_state(state);
        constexpr std::size_t reduction_block_size = 4096U;
        const std::size_t block_count = (state.size() + reduction_block_size - 1U) / reduction_block_size;
        std::vector<Complex> partial_sums(block_count, Complex{});

        pool_.parallel_for(0U, block_count, [&](const std::size_t block)
        {
            const std::size_t begin = block * reduction_block_size;
            const std::size_t end = std::min(state.size(), begin + reduction_block_size);
            Complex sum{};
            for (std::size_t index = begin; index < end; ++index) sum += state[index];
            partial_sums[block] = sum;
        }, 1U);

        Complex total{};
        for (const Complex& partial : partial_sums) total += partial;
        const Complex mean = total / static_cast<double>(state.size());
        pool_.parallel_for(0U, state.size(), [&](const std::size_t index)
        {
            state[index] = 2.0 * mean - state[index];
        }, 4096U);
    }

    void CPUQuantumBackend::apply_qft(
        std::vector<Complex>& state,
        const std::size_t total_qubits,
        const std::vector<std::size_t>& target_qubits) const
    {
        validate_state(state);
        if (target_qubits.empty()) throw std::invalid_argument("QFT requires at least one target qubit.");
        if (total_qubits >= std::numeric_limits<std::size_t>::digits ||
            (std::size_t{1} << total_qubits) != state.size())
            throw std::invalid_argument("The total qubit count does not match the state vector.");

        std::vector<bool> selected(total_qubits, false);
        std::size_t target_mask = 0U;
        for (const std::size_t qubit : target_qubits)
        {
            if (qubit >= total_qubits || selected[qubit])
                throw std::invalid_argument("QFT target qubits must be valid and unique.");
            selected[qubit] = true;
            target_mask |= std::size_t{1} << qubit;
        }

        if (target_qubits.size() >= std::numeric_limits<std::size_t>::digits)
            throw std::length_error("QFT target register is too large.");
        const std::size_t dimension = std::size_t{1} << target_qubits.size();
        if (dimension > 4096U)
            throw std::length_error("The direct QFT implementation is limited to 12 target qubits.");

        std::vector<std::size_t> target_offsets(dimension, 0U);
        for (std::size_t pattern = 0U; pattern < dimension; ++pattern)
        {
            std::size_t mapped = 0U;
            for (std::size_t bit = 0U; bit < target_qubits.size(); ++bit)
            {
                if ((pattern & (std::size_t{1} << bit)) != 0U)
                    mapped |= std::size_t{1} << target_qubits[bit];
            }
            target_offsets[pattern] = mapped;
        }

        const std::vector<Complex> input_state = state;
        const double scale = 1.0 / std::sqrt(static_cast<double>(dimension));
        const double two_pi = 2.0 * std::numbers::pi;
        pool_.parallel_for(0U, state.size(), [&](const std::size_t base)
        {
            if ((base & target_mask) != 0U) return;
            std::vector<Complex> input(dimension);
            std::vector<Complex> output(dimension);
            for (std::size_t index = 0U; index < dimension; ++index)
                input[index] = input_state[base | target_offsets[index]];

            for (std::size_t frequency = 0U; frequency < dimension; ++frequency)
            {
                Complex total{};
                for (std::size_t sample = 0U; sample < dimension; ++sample)
                {
                    const double angle = two_pi * static_cast<double>(sample * frequency) /
                                         static_cast<double>(dimension);
                    total += input[sample] * Complex{std::cos(angle), std::sin(angle)};
                }
                output[frequency] = total * scale;
            }
            for (std::size_t index = 0U; index < dimension; ++index)
                state[base | target_offsets[index]] = output[index];
        }, 1U);
    }

    void CPUQuantumBackend::apply_phase_shift(
        std::vector<Complex>& state,
        const std::size_t target,
        const double angle) const
    {
        validate_qubit(state, target);
        const Complex factor{std::cos(angle), std::sin(angle)};
        const std::size_t mask = std::size_t{1} << target;
        pool_.parallel_for(0U, state.size() / 2U, [&](const std::size_t pair)
        {
            const std::size_t high = insert_zero_bit(pair, target) | mask;
            state[high] *= factor;
        }, 2048U);
    }

    double CPUQuantumBackend::probability_of_one(
        const std::vector<Complex>& state,
        const std::size_t target) const
    {
        validate_qubit(state, target);
        constexpr std::size_t reduction_block_size = 4096U;
        const std::size_t pair_count = state.size() / 2U;
        const std::size_t block_count = (pair_count + reduction_block_size - 1U) / reduction_block_size;
        const std::size_t mask = std::size_t{1} << target;
        std::vector<double> partial_sums(block_count, 0.0);

        pool_.parallel_for(0U, block_count, [&](const std::size_t block)
        {
            const std::size_t begin = block * reduction_block_size;
            const std::size_t end = std::min(pair_count, begin + reduction_block_size);
            double sum = 0.0;
            for (std::size_t pair = begin; pair < end; ++pair)
                sum += std::norm(state[insert_zero_bit(pair, target) | mask]);
            partial_sums[block] = sum;
        }, 1U);

        double total = 0.0;
        for (const double partial : partial_sums) total += partial;
        return total;
    }

    void CPUQuantumBackend::collapse_qubit(
        std::vector<Complex>& state,
        const std::size_t target,
        const bool outcome,
        const double outcome_probability) const
    {
        validate_qubit(state, target);
        if (!(outcome_probability > 0.0))
            throw std::invalid_argument("A qubit cannot collapse onto an outcome that has zero probability.");
        const double scale = 1.0 / std::sqrt(outcome_probability);
        const std::size_t mask = std::size_t{1} << target;
        pool_.parallel_for(0U, state.size() / 2U, [&](const std::size_t pair)
        {
            const std::size_t low = insert_zero_bit(pair, target);
            const std::size_t high = low | mask;
            if (outcome)
            {
                state[low] = Complex{};
                state[high] *= scale;
            }
            else
            {
                state[high] = Complex{};
                state[low] *= scale;
            }
        }, 2048U);
    }
}
