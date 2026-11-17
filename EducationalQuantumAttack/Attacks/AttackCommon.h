#pragma once

// Helpers shared by the component attacks: filling the "executed on the simulator" section
// of a report from an engine result, and small formatting utilities.

#include "EducationalQuantumAttack/Common/QuantumAttackSupport.h"
#include "EducationalQuantumAttack/Common/QuantumAttackTypes.h"
#include "EducationalQuantumAttack/Engine/GroverEngine.h"
#include "EducationalQuantumAttack/Engine/PhaseEstimationEngine.h"

#include <cstdint>
#include <span>
#include <string>

namespace crypto::educational_quantum_attack
{
    [[nodiscard]] std::string hex_string(std::span<const std::uint8_t> bytes);
    [[nodiscard]] std::string hex_value(std::uint64_t value, std::size_t minimum_digits = 1U);
    // Replaces control characters so that arbitrary plaintext can be printed on one line.
    [[nodiscard]] std::string printable(const std::string& text, std::size_t maximum_length = 96U);

    // Fills report.simulated and the measured part of report.time from a Grover engine run.
    void write_simulated_grover(
        AttackResult& report,
        const GroverSearchResult& search,
        double oracle_table_ms,
        const std::string& oracle_table_description);

    // Accumulates one phase-estimation run into running totals (several runs may be needed).
    struct PhaseEstimationTotals
    {
        std::uint64_t circuit_runs = 0U;
        std::uint64_t controlled_permutations = 0U;
        std::uint64_t hadamard_gates = 0U;
        std::uint64_t phase_shift_gates = 0U;
        std::uint64_t reset_x_gates = 0U;
        std::uint64_t measurements = 0U;
        std::uint64_t simulator_gate_count = 0U;
        std::uint64_t deepest_run_operation_depth = 0U;
        std::size_t qubits = 0U;
        std::size_t state_vector_bytes = 0U;
        double simulation_wall_ms = 0.0;
        double permutation_table_ms = 0.0;
        quantum::QuantumBackendStatistics backend{};

        void add(const PhaseEstimationResult& run);
    };

    // Fills report.simulated and the measured part of report.time from phase-estimation runs.
    void write_simulated_phase_estimation(
        AttackResult& report,
        const PhaseEstimationTotals& totals,
        const std::string& controlled_operation_name,
        const std::string& scope);

    // Marks a report as theory-only: the circuit exists but was not run.
    void mark_not_executed(AttackResult& report, const std::string& reason);
    // Marks a report as failed because the simulation raised an error.
    void mark_error(AttackResult& report, const std::string& what);
}
