#pragma once

// Logical resource models and scenario time estimates. Nothing in this file is executed on
// the simulator: every number is either an exact count from a stated circuit construction
// ("computed") or the output of a published scaling formula under stated assumptions
// ("estimated"). Quantities with no defensible model are returned as NOT MODELED.
//
// The Shor Toffoli-count formulas and the two scenario rates are the ones the standard
// CryptoSetAnalysis module already uses (CryptoSetAnalysis/Detail/AttackTimeModel.h), and
// the register-size illustration comes from QuantumAttack/Standard/Models. They are reused
// here rather than duplicated.

#include "EducationalQuantumAttack/Common/QuantumAttackTypes.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace crypto::educational_quantum_attack
{
    // ---- Grover-type circuits -----------------------------------------------------------
    //
    // Construction: an initial Hadamard layer, then per iteration one oracle call followed
    // by the diffusion operator H^n X^n (C^(n-1) Z) X^n H^n. The multi-controlled Z is a
    // multi-controlled NOT between two Hadamards on its target; with c = n - 1 controls it
    // costs 1 CNOT (c = 1), 1 Toffoli (c = 2) or 2c - 3 Toffolis with c - 2 clean ancillas
    // (c >= 3, V-chain). The oracle is a black box: its gates, depth and workspace are
    // excluded and reported separately as NOT MODELED.
    struct GroverLogicalCost
    {
        std::uint64_t search_qubits = 0U;
        std::uint64_t diffusion_ancilla_qubits = 0U;
        std::uint64_t hadamard_gates = 0U;
        std::uint64_t pauli_x_gates = 0U;
        std::uint64_t pauli_z_gates = 0U;
        std::uint64_t cnot_gates = 0U;
        std::uint64_t toffoli_gates = 0U;
        std::uint64_t gates_excluding_oracle = 0U;
        std::uint64_t deepest_run_depth_excluding_oracle = 0U;
        std::uint64_t oracle_calls = 0U;
    };

    [[nodiscard]] GroverLogicalCost grover_logical_cost(
        std::size_t search_qubits,
        std::uint64_t total_iterations,
        std::uint64_t circuit_runs,
        std::uint64_t deepest_run_iterations);

    // Writes a Grover logical model into `model`. `oracle_cost` states what one oracle call
    // contains; `quantum_memory` is the quantum-accessible memory the oracle needs, if any.
    void write_grover_logical_model(
        CircuitResources& model,
        const GroverLogicalCost& cost,
        std::string oracle_cost,
        Metric quantum_memory);

    // Scenario estimate for time category B of a Grover-type attack.
    void write_grover_time_estimate(
        TimeMeasurements& time,
        std::uint64_t grover_iterations,
        const HardwareScenario& scenario,
        const std::string& what_is_counted);

    // ---- Shor: integer factoring --------------------------------------------------------

    struct ShorFactoringModel
    {
        std::size_t modulus_bits = 0U;
        std::uint64_t work_register_qubits = 0U;            // n
        std::uint64_t one_control_circuit_qubits = 0U;      // 2n + 3 (Beauregard 2003)
        std::uint64_t textbook_register_qubits = 0U;        // existing QuantumResourceModel figure
        std::uint64_t controlled_modular_multiplications = 0U; // 2n
        bool toffoli_estimate_available = false;
        long double toffoli_estimate = 0.0L;                // existing project formula
    };

    [[nodiscard]] ShorFactoringModel shor_factoring_model(std::size_t modulus_bits);
    void write_shor_factoring_logical_model(CircuitResources& model, const ShorFactoringModel& values);
    void write_shor_factoring_time_estimate(
        TimeMeasurements& time, const ShorFactoringModel& values, const HardwareScenario& scenario);

    // ---- Shor: elliptic-curve discrete logarithm ----------------------------------------

    struct ShorEcdlpModel
    {
        std::size_t field_bits = 0U;
        std::uint64_t point_register_qubits = 0U;           // 2n: the x and y coordinates
        std::uint64_t total_qubits = 0U;                    // 9n + 2*ceil(log2 n) + 10
        std::uint64_t textbook_register_qubits = 0U;        // existing QuantumResourceModel figure
        bool toffoli_estimate_available = false;
        long double toffoli_estimate = 0.0L;                // existing project formula
    };

    [[nodiscard]] ShorEcdlpModel shor_ecdlp_model(std::size_t field_bits);
    void write_shor_ecdlp_logical_model(CircuitResources& model, const ShorEcdlpModel& values);
    void write_shor_ecdlp_time_estimate(
        TimeMeasurements& time, const ShorEcdlpModel& values, const HardwareScenario& scenario);

    // Assumptions shared by every time estimate of category B.
    [[nodiscard]] std::string scenario_assumption_text(const HardwareScenario& scenario);
}
