#pragma once

// EducationalQuantumAttack (CryptoProject 2.3.5)
//
// Shared data model for the independent quantum-attack analysis of the three educational
// cryptosystem sets. Three rules shape every type in this file:
//
//   1. A number is always tagged with how it was obtained (measured / computed / estimated)
//      or with the reason it is absent (NOT MODELED / NOT EXECUTED / N/A / UNKNOWN). An
//      absent value is never stored or printed as 0.
//   2. Three different times are kept in three different fields:
//        A. quantum simulator runtime      - measured wall time of the classical simulation
//        B. estimated quantum attack time  - scenario estimate under stated assumptions
//        C. classical attack runtime       - measured wall time of the existing classical attack
//   3. Resources of the circuit that was really executed on the state-vector simulator are
//      kept apart from the logical resource model, which is computed and never executed.

#include "QuantumAttack/Backend/QuantumBackendTypes.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace crypto::educational_quantum_attack
{
    // ------------------------------------------------------------------------------------
    // Metric: a value together with its provenance.
    // ------------------------------------------------------------------------------------

    enum class MetricKind
    {
        Measured,       // observed while running on this computer
        Computed,       // exact count derived from the executed circuit or a closed formula
        Estimated,      // model or scenario estimate; the assumptions are stated in `note`
        NotModeled,     // no defensible model is implemented
        NotApplicable,
        NotExecuted,    // would have been measured, but the circuit was not run
        Unknown
    };

    struct Metric
    {
        MetricKind kind = MetricKind::NotModeled;
        long double value = 0.0L;
        std::string note;

        [[nodiscard]] bool has_value() const noexcept
        {
            return kind == MetricKind::Measured || kind == MetricKind::Computed ||
                   kind == MetricKind::Estimated;
        }

        [[nodiscard]] static Metric measured(const long double v, std::string n = {})
        {
            return {MetricKind::Measured, v, std::move(n)};
        }
        [[nodiscard]] static Metric computed(const long double v, std::string n = {})
        {
            return {MetricKind::Computed, v, std::move(n)};
        }
        [[nodiscard]] static Metric estimated(const long double v, std::string n = {})
        {
            return {MetricKind::Estimated, v, std::move(n)};
        }
        [[nodiscard]] static Metric not_modeled(std::string n = {})
        {
            return {MetricKind::NotModeled, 0.0L, std::move(n)};
        }
        [[nodiscard]] static Metric not_applicable(std::string n = {})
        {
            return {MetricKind::NotApplicable, 0.0L, std::move(n)};
        }
        [[nodiscard]] static Metric not_executed(std::string n = {})
        {
            return {MetricKind::NotExecuted, 0.0L, std::move(n)};
        }
        [[nodiscard]] static Metric unknown(std::string n = {})
        {
            return {MetricKind::Unknown, 0.0L, std::move(n)};
        }
    };

    // ------------------------------------------------------------------------------------
    // Attack classification.
    // ------------------------------------------------------------------------------------

    enum class AttackKind
    {
        AesKeySearch,           // Grover search over the restricted AES key space
        ShaPreimage,            // Grover preimage search on the truncated digest
        ShaCollision,           // Brassard-Hoyer-Tapp collision search (not plain Grover)
        EccDiscreteLog,         // Shor's algorithm for the elliptic-curve discrete logarithm
        RsaFactoring,           // Shor's algorithm for integer factoring (order finding)
        ModuleLweSecretSearch   // explicit generic secret-candidate search model (never Shor)
    };

    enum class ExecutionStatus
    {
        Simulated,      // the attack circuit ran on the state-vector simulator
        TheoryOnly,     // the circuit is defined but was not executed; estimates only
        NotModeled,     // no circuit-level model exists in this project
        Error           // the simulation raised an error
    };

    enum class AttackOutcome
    {
        Succeeded,      // the secret was recovered and classically verified
        Failed,         // the circuit ran but no verified secret was recovered
        NotAttempted    // not executed or not modeled; neither a success nor a failure
    };

    enum class SetId
    {
        AesShaEcdsa,
        AesShaRsaPss,
        ShaAesMlKem
    };

    enum class SetStatus
    {
        AllSucceeded,   // every attack was executed and succeeded
        Partial,        // nothing failed, but at least one attack was not executed or not modeled
        Failed          // at least one executed attack failed or raised an error
    };

    using NamedValues = std::vector<std::pair<std::string, std::string>>;

    // ------------------------------------------------------------------------------------
    // Circuit resources. Used twice per attack: once for the circuit that was executed on
    // the simulator and once for the logical resource model.
    // ------------------------------------------------------------------------------------

    struct CircuitResources
    {
        std::string scope;                  // what these numbers cover and what they exclude
        Metric logical_qubits;              // data / register qubits
        Metric ancilla_qubits;
        Metric total_qubits;
        Metric gate_count;
        std::vector<std::pair<std::string, std::uint64_t>> gates_by_type;
        Metric circuit_depth;
        Metric oracle_calls;                // quantum oracle invocations
        Metric quantum_memory_bits;         // quantum-accessible memory (for example QRAM)
        std::string oracle_cost;            // statement about the cost inside one oracle call
    };

    // ------------------------------------------------------------------------------------
    // The three time categories. They are never added together.
    // ------------------------------------------------------------------------------------

    struct TimeMeasurements
    {
        // A. Quantum simulator runtime: classical wall time spent simulating the circuit.
        Metric simulator_runtime_ms;
        // Classical precomputation that only the simulation needs (oracle truth tables,
        // permutation tables). Reported next to A, never as part of the quantum algorithm.
        Metric simulator_setup_ms;
        Metric simulator_cpu_time_ms;

        // B. Estimated quantum attack time on hypothetical quantum hardware.
        Metric estimated_quantum_attack_seconds;
        std::string estimated_quantum_attack_basis;

        // C. Classical attack runtime: the existing educational classical attack, measured.
        Metric classical_attack_runtime_ms;
        Metric classical_attack_work;
        std::string classical_attack_description;
    };

    // ------------------------------------------------------------------------------------
    // Computer resources used by the classical simulation.
    // ------------------------------------------------------------------------------------

    struct ComputeResources
    {
        std::string backend_requested;
        std::string backend_used;
        Metric cpu_threads;
        Metric state_vector_bytes;              // exact: 16 bytes * 2^qubits
        Metric working_memory_bytes;            // modeled simulator working set
        Metric process_peak_memory_bytes;       // process-wide high-water mark, monotonic
        bool gpu_requested = false;
        bool gpu_executed = false;
        std::string gpu_status = "NOT USED (CPU backend selected)";
        std::string gpu_device;
        Metric gpu_operations = Metric::not_applicable();
        Metric gpu_kernel_ms = Metric::not_applicable();
        Metric gpu_transfer_ms = Metric::not_applicable();
        Metric cpu_fallback_operations = Metric::not_applicable();
    };

    // A separate algorithm-validation run, for example Shor on N = 15. It demonstrates that
    // the algorithm works on a tiny input; it is never evidence of an attack on the target.
    struct ValidationExperiment
    {
        bool included = false;
        std::string title;
        std::string description;
        std::string status;
        bool passed = false;
        Metric simulator_runtime_ms = Metric::not_executed();
        Metric qubits = Metric::not_executed();
        std::string disclaimer;
    };

    // A theory-only full-size reference (for example AES-128). Never simulated and always
    // printed apart from the toy attack.
    struct ReferenceScenario
    {
        bool included = false;
        std::string title;
        NamedValues lines;
        std::string disclaimer;
    };

    struct AttackResult
    {
        AttackKind kind = AttackKind::AesKeySearch;
        std::string id;                     // stable machine-readable identifier
        std::string system_name;            // the cryptosystem set this attack belongs to
        std::string target;                 // attacked component
        std::string mathematical_problem;   // the underlying hard problem
        std::string algorithm;              // attack algorithm, with its variant
        std::string algorithm_family;       // short label: Grover, BHT, Shor factoring, ...
        std::string applicability;          // scope in which the model is valid
        NamedValues parameters;             // actual input parameters of the attacked instance

        ExecutionStatus execution = ExecutionStatus::NotModeled;
        bool circuit_implemented = false;
        bool simulator_executed = false;
        std::string execution_note;

        AttackOutcome outcome = AttackOutcome::NotAttempted;
        bool verified_against_public_instance = false;
        std::optional<bool> matches_ground_truth;
        NamedValues recovered;

        CircuitResources simulated;         // executed on the state-vector simulator
        CircuitResources logical_model;     // computed logical resource model, not executed
        TimeMeasurements time;
        ComputeResources compute;

        std::vector<std::string> assumptions;
        std::vector<std::string> limitations;
        std::vector<std::string> notes;

        ValidationExperiment validation;
        ReferenceScenario reference;
    };

    struct SetAttackReport
    {
        SetId id = SetId::AesShaEcdsa;
        std::string name;
        std::string composition;
        std::string disclaimer;
        NamedValues instance;               // public description of the attacked set instance
        std::vector<AttackResult> attacks;
        SetStatus status = SetStatus::Partial;
        double wall_ms = 0.0;               // wall time of the whole analysis of this set
    };

    // ------------------------------------------------------------------------------------
    // Configuration.
    // ------------------------------------------------------------------------------------

    // Explicit hardware-scenario assumptions behind time category B. They default to the
    // scenario rates the standard CryptoSetAnalysis module already uses.
    struct HardwareScenario
    {
        long double seconds_per_grover_iteration = 1.0e-6L;
        long double seconds_per_toffoli_gate = 1.0e-6L;
    };

    // The state-vector simulation is refused, and only theory is reported, when a circuit
    // exceeds either limit. The memory requirement is computed before anything is allocated.
    struct SimulationBudget
    {
        std::size_t max_qubits = 26U;
        std::uint64_t max_working_memory_bytes = 2ULL * 1024ULL * 1024ULL * 1024ULL;
    };

    struct QuantumAttackConfig
    {
        quantum::QuantumExecutionOptions execution{};
        SimulationBudget budget{};
        HardwareScenario scenario{};

        // 0 selects a fresh seed from the operating-system random source.
        std::uint64_t seed = 0U;

        // Number of times a quantum circuit may be re-run when its measured result does
        // not verify. A run that still fails afterwards is reported as a failure.
        std::size_t max_quantum_attempts = 4U;

        bool run_classical_baselines = true;
        bool run_validation_experiments = true;
        bool include_reference_scenarios = true;

        // Optional progress sink for long simulations (for example the console menu).
        std::function<void(const std::string&)> progress;
    };
}
