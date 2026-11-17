#pragma once

// Iterative (semiclassical-QFT) quantum phase estimation on the existing QuantumAttack
// state-vector simulator. This is the one-control-qubit form of the quantum part of Shor's
// algorithms: instead of a counting register of t qubits followed by an inverse QFT, a
// single control qubit is prepared, used, measured and reset t times, and each measured
// bit classically selects the phase correction of the following rounds. The measured
// integers follow the same distribution as in the textbook circuit.
//
// Simulator operations used per round:
//   apply_hadamard, apply_controlled_permutation, apply_phase_shift, apply_hadamard,
//   measure_qubit, and apply_x to reset the control qubit after a 1 outcome.
//
// What is simulated: the work register, the control qubit, every controlled power of the
// unitary, and every mid-circuit measurement. What is NOT simulated: the decomposition of
// a controlled permutation (a modular multiplication or an elliptic-curve point addition)
// into elementary gates. Each controlled permutation is applied as one exact reversible
// basis-state permutation, which is how the existing toy Shor experiment models it too.

#include "QuantumAttack/Backend/QuantumBackendTypes.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace crypto::educational_quantum_attack
{
    struct PhaseEstimationStage
    {
        std::string label;
        // Number of phase bits measured for this unitary (1 to 62).
        std::size_t bits = 0U;
        // Fills `permutation` (already sized to 2^work_qubits) with the action of
        // U^(2^power) on the work-register basis states: state x is sent to permutation[x].
        std::function<void(std::size_t power, std::vector<std::size_t>& permutation)> controlled_power;
    };

    struct PhaseEstimationRequest
    {
        std::size_t work_qubits = 0U;
        std::size_t initial_work_state = 0U;
        // The stages run one after another on the same work register, so later stages act
        // on the state the earlier measurements left behind. Shor's discrete logarithm uses
        // two stages (the generator and the public key); order finding uses one.
        std::vector<PhaseEstimationStage> stages;
        std::uint64_t seed = 1U;
        quantum::QuantumExecutionOptions execution{};
        std::size_t simulator_qubit_limit = 26U;
    };

    struct PhaseEstimationResult
    {
        // One measured integer y per stage; y / 2^bits approximates the phase.
        std::vector<std::uint64_t> phase_integers;

        // Operations executed on the simulator.
        std::uint64_t controlled_permutations = 0U;
        std::uint64_t hadamard_gates = 0U;
        std::uint64_t phase_shift_gates = 0U;
        std::uint64_t reset_x_gates = 0U;
        std::uint64_t measurements = 0U;
        std::uint64_t simulator_gate_count = 0U;
        std::uint64_t simulator_operation_depth = 0U;

        std::size_t qubits = 0U;
        std::size_t state_vector_bytes = 0U;
        double simulation_wall_ms = 0.0;        // gate application and measurement
        double permutation_table_ms = 0.0;      // classical table construction (simulation setup)
        quantum::QuantumBackendStatistics backend{};
    };

    // Throws std::invalid_argument for an invalid request and propagates simulator errors.
    [[nodiscard]] PhaseEstimationResult run_iterative_phase_estimation(const PhaseEstimationRequest& request);
}
