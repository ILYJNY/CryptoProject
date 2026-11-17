#pragma once

// Comparison of the quantum-attack results of the three independent educational sets.
//
// The comparison never merges the sets into one cryptosystem and never adds the estimated
// attack times of different attack models into a single "time to break everything":
// those estimates rest on different assumptions and leave out different costs.

#include "EducationalQuantumAttack/Common/QuantumAttackTypes.h"

#include <cstddef>
#include <string>
#include <vector>

namespace crypto::integrated_educational_quantum_attack
{
    namespace eqa = educational_quantum_attack;

    // One attack of one set, reduced to the quantities that are compared.
    struct ComparisonRow
    {
        std::string set_name;
        std::string target;
        std::string algorithm;
        std::string attack_id;
        eqa::ExecutionStatus execution = eqa::ExecutionStatus::NotModeled;
        eqa::AttackOutcome outcome = eqa::AttackOutcome::NotAttempted;
        bool circuit_implemented = false;
        bool simulator_executed = false;

        eqa::Metric simulated_qubits;           // circuit executed on the simulator
        eqa::Metric simulated_operations;
        eqa::Metric simulated_depth;
        eqa::Metric model_qubits;               // logical resource model (never executed)
        eqa::Metric model_gates;
        eqa::Metric model_depth;
        eqa::Metric oracle_calls;
        eqa::Metric quantum_memory_bits;

        eqa::Metric simulator_runtime_ms;       // time A
        eqa::Metric simulator_setup_ms;
        eqa::Metric estimated_quantum_seconds;  // time B
        eqa::Metric classical_runtime_ms;       // time C

        eqa::Metric state_vector_bytes;
        eqa::Metric process_peak_memory_bytes;
        eqa::Metric cpu_threads;
        std::string backend_used;
        bool gpu_executed = false;
        std::string gpu_status;
        eqa::Metric gpu_kernel_ms;
        eqa::Metric gpu_transfer_ms;

        std::string applicability;
    };

    // The attack that is best under one criterion, or "not available" when no attack has a
    // value for that criterion.
    struct Highlight
    {
        std::string criterion;
        bool available = false;
        std::string set_name;
        std::string target;
        std::string algorithm;
        eqa::Metric value;
        std::string unit;
        std::string caveat;
    };

    struct Comparison
    {
        std::vector<ComparisonRow> rows;

        std::size_t attacks_total = 0U;
        std::size_t attacks_executed = 0U;
        std::size_t attacks_succeeded = 0U;
        std::size_t attacks_failed = 0U;        // executed without success, or raised an error
        std::size_t attacks_theory_only = 0U;
        std::size_t attacks_not_modeled = 0U;

        // Sums of measured values over the attacks that have them.
        eqa::Metric total_simulator_runtime_ms;
        eqa::Metric total_simulator_setup_ms;
        eqa::Metric total_classical_runtime_ms;

        Highlight fewest_simulated_qubits;
        Highlight fewest_model_qubits;
        Highlight shallowest_model_depth;
        Highlight fastest_simulation;

        std::vector<std::string> applicability;         // one line per attack model
        std::vector<std::string> not_modeled_items;     // everything without a value, and why
        std::vector<std::string> assumptions;           // de-duplicated
    };

    [[nodiscard]] Comparison compare_quantum_attacks(const std::vector<eqa::SetAttackReport>& sets);

    [[nodiscard]] std::string format_comparison_table(const Comparison& comparison);
    [[nodiscard]] std::string format_resource_usage_table(const Comparison& comparison);
    [[nodiscard]] std::string format_highlight(const Highlight& highlight);

    [[nodiscard]] std::string comparison_csv(const Comparison& comparison);
    [[nodiscard]] std::string aggregate_metrics_csv(const Comparison& comparison, eqa::SetStatus overall_status);
}
