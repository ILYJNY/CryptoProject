#include "ResourceModel.h"

#include "CryptoSetAnalysis/Detail/AttackTimeModel.h"
#include "EducationalQuantumAttack/Common/QuantumAttackSupport.h"
#include "QuantumAttack/Standard/Models/QuantumResourceModel.h"

#include <cmath>
#include <sstream>

namespace crypto::educational_quantum_attack
{
    namespace
    {
        namespace existing_model = set_analysis::detail::attack_time_model;
    }

    // ---- Grover-type circuits -----------------------------------------------------------

    GroverLogicalCost grover_logical_cost(
        const std::size_t search_qubits,
        const std::uint64_t total_iterations,
        const std::uint64_t circuit_runs,
        const std::uint64_t deepest_run_iterations)
    {
        GroverLogicalCost cost;
        const std::uint64_t n = search_qubits;
        cost.search_qubits = n;
        cost.oracle_calls = total_iterations;
        if (n == 0U) return cost;

        // Multi-controlled Z on n qubits: c = n - 1 controls.
        const std::uint64_t controls = n - 1U;
        std::uint64_t reflection_hadamards = 0U;
        std::uint64_t reflection_depth = 0U;
        std::uint64_t z_per_iteration = 0U;
        std::uint64_t cnot_per_iteration = 0U;
        std::uint64_t toffoli_per_iteration = 0U;
        if (controls == 0U)
        {
            z_per_iteration = 1U;
            reflection_depth = 1U;
        }
        else if (controls == 1U)
        {
            reflection_hadamards = 2U;
            cnot_per_iteration = 1U;
            reflection_depth = 3U;
        }
        else if (controls == 2U)
        {
            reflection_hadamards = 2U;
            toffoli_per_iteration = 1U;
            reflection_depth = 3U;
        }
        else
        {
            reflection_hadamards = 2U;
            toffoli_per_iteration = 2U * controls - 3U;
            cost.diffusion_ancilla_qubits = controls - 2U;
            reflection_depth = 2U + toffoli_per_iteration;
        }

        // Diffusion = H^n X^n (reflection) X^n H^n; the initial layer is H^n per circuit run.
        cost.hadamard_gates = circuit_runs * n + total_iterations * (2U * n + reflection_hadamards);
        cost.pauli_x_gates = total_iterations * 2U * n;
        cost.pauli_z_gates = total_iterations * z_per_iteration;
        cost.cnot_gates = total_iterations * cnot_per_iteration;
        cost.toffoli_gates = total_iterations * toffoli_per_iteration;
        cost.gates_excluding_oracle = cost.hadamard_gates + cost.pauli_x_gates + cost.pauli_z_gates +
                                      cost.cnot_gates + cost.toffoli_gates;
        // One layer each for H^n, X^n, X^n, H^n, plus the reflection, per iteration.
        cost.deepest_run_depth_excluding_oracle = 1U + deepest_run_iterations * (4U + reflection_depth);
        return cost;
    }

    void write_grover_logical_model(
        CircuitResources& model,
        const GroverLogicalCost& cost,
        std::string oracle_cost,
        Metric quantum_memory)
    {
        model.scope =
            "Computed from an explicit construction: search register, initial Hadamard layer and the "
            "diffusion operator decomposed into H, X and Toffoli gates (multi-controlled Z as a Toffoli "
            "V-chain with clean ancillas). Every gate, layer and workspace qubit INSIDE the oracle is "
            "excluded, so all figures are lower bounds for the complete attack circuit. Logical qubits "
            "only: no error-correction overhead, no physical-qubit count.";
        model.logical_qubits = Metric::computed(static_cast<long double>(cost.search_qubits), "search register");
        model.ancilla_qubits = Metric::computed(
            static_cast<long double>(cost.diffusion_ancilla_qubits),
            "diffusion operator only; oracle workspace NOT MODELED");
        model.total_qubits = Metric::computed(
            static_cast<long double>(cost.search_qubits + cost.diffusion_ancilla_qubits),
            "lower bound; excludes oracle workspace");
        model.gate_count = Metric::computed(
            static_cast<long double>(cost.gates_excluding_oracle), "all circuit runs; excludes oracle internals");
        model.gates_by_type.clear();
        model.gates_by_type.emplace_back("H", cost.hadamard_gates);
        model.gates_by_type.emplace_back("X", cost.pauli_x_gates);
        if (cost.pauli_z_gates != 0U) model.gates_by_type.emplace_back("Z", cost.pauli_z_gates);
        if (cost.cnot_gates != 0U) model.gates_by_type.emplace_back("CNOT", cost.cnot_gates);
        model.gates_by_type.emplace_back("Toffoli", cost.toffoli_gates);
        model.circuit_depth = Metric::computed(
            static_cast<long double>(cost.deepest_run_depth_excluding_oracle),
            "deepest single circuit run; excludes oracle depth");
        model.oracle_calls = Metric::computed(
            static_cast<long double>(cost.oracle_calls), "quantum oracle invocations over all circuit runs");
        model.quantum_memory_bits = std::move(quantum_memory);
        model.oracle_cost = std::move(oracle_cost);
    }

    void write_grover_time_estimate(
        TimeMeasurements& time,
        const std::uint64_t grover_iterations,
        const HardwareScenario& scenario,
        const std::string& what_is_counted)
    {
        const long double seconds =
            static_cast<long double>(grover_iterations) * scenario.seconds_per_grover_iteration;
        time.estimated_quantum_attack_seconds = Metric::estimated(seconds, "scenario estimate, not a measurement");
        std::ostringstream basis;
        basis << grover_iterations << " Grover iterations (" << what_is_counted << ") x "
              << format_seconds(scenario.seconds_per_grover_iteration)
              << " assumed per iteration (oracle call plus diffusion). The oracle's internal circuit is not "
                 "modeled, so this rate is an assumption, not a derived value.";
        time.estimated_quantum_attack_basis = basis.str();
    }

    // ---- Shor: integer factoring --------------------------------------------------------

    ShorFactoringModel shor_factoring_model(const std::size_t modulus_bits)
    {
        ShorFactoringModel values;
        values.modulus_bits = modulus_bits;
        const std::uint64_t n = modulus_bits;
        values.work_register_qubits = n;
        values.one_control_circuit_qubits = 2U * n + 3U;
        values.controlled_modular_multiplications = 2U * n;
        if (modulus_bits >= 1U && modulus_bits <= 4096U)
        {
            values.textbook_register_qubits = quantum::estimate_quantum_resources(
                quantum::CryptoTarget::RSA, modulus_bits).estimated_register_qubits;
        }
        // The formula is real-valued; a gate count is reported in whole gates.
        const long double toffoli = std::round(existing_model::estimate_rsa_shor_toffoli_gates(modulus_bits));
        values.toffoli_estimate_available = toffoli > 0.0L;
        values.toffoli_estimate = toffoli;
        return values;
    }

    void write_shor_factoring_logical_model(CircuitResources& model, const ShorFactoringModel& values)
    {
        const long double n = static_cast<long double>(values.modulus_bits);
        model.scope =
            "Published constructions evaluated at this modulus size; not executed. Qubits: the "
            "one-control-qubit circuit of Beauregard (2003), 2n+3 logical qubits. Toffoli count: the "
            "interpolation formula already used by CryptoSetAnalysis, (64*(log2 n - 2) + 29.46) * n^3. "
            "That formula describes the growth for cryptographic sizes; at a toy size it is an "
            "extrapolation and only indicates the order of magnitude. Logical qubits only: no "
            "error-correction overhead, no physical-qubit count.";
        model.logical_qubits = Metric::estimated(n + 1.0L, "n-qubit work register plus one control qubit");
        model.ancilla_qubits = Metric::estimated(
            n + 2.0L, "remaining arithmetic workspace of the 2n+3-qubit construction");
        model.total_qubits = Metric::estimated(
            static_cast<long double>(values.one_control_circuit_qubits), "2n+3 (Beauregard 2003)");
        model.gates_by_type.clear();
        model.gates_by_type.emplace_back(
            "controlled modular multiplications (2n)", values.controlled_modular_multiplications);
        if (values.toffoli_estimate_available)
        {
            model.gate_count = Metric::estimated(
                values.toffoli_estimate, "Toffoli gates; formula extrapolated to this toy size");
            model.circuit_depth = Metric::estimated(
                values.toffoli_estimate, "upper bound: Toffoli gates executed strictly one after another");
            model.gates_by_type.emplace_back(
                "Toffoli (formula estimate)", static_cast<std::uint64_t>(values.toffoli_estimate));
        }
        else
        {
            model.gate_count = Metric::not_modeled("the Toffoli formula is not defined below 8-bit moduli");
            model.circuit_depth = Metric::not_modeled("no gate-count model at this size");
        }
        model.oracle_calls = Metric::not_applicable(
            "Shor's algorithm uses no black-box oracle; it applies 2n controlled modular multiplications");
        model.quantum_memory_bits = Metric::not_applicable("no quantum-accessible classical memory is needed");
        model.oracle_cost =
            "Not an oracle algorithm. Each controlled modular multiplication is built from modular adders; "
            "its Toffoli cost is included in the estimated total above.";
    }

    void write_shor_factoring_time_estimate(
        TimeMeasurements& time, const ShorFactoringModel& values, const HardwareScenario& scenario)
    {
        if (!values.toffoli_estimate_available)
        {
            time.estimated_quantum_attack_seconds =
                Metric::not_modeled("no gate-count model is defined at this modulus size");
            time.estimated_quantum_attack_basis = "NOT MODELED";
            return;
        }
        time.estimated_quantum_attack_seconds = Metric::estimated(
            values.toffoli_estimate * scenario.seconds_per_toffoli_gate, "scenario estimate, not a measurement");
        std::ostringstream basis;
        basis << format_number(values.toffoli_estimate) << " estimated Toffoli gates x "
              << format_seconds(scenario.seconds_per_toffoli_gate)
              << " assumed per serially executed logical Toffoli gate. The Toffoli count is an extrapolation "
                 "of a formula fitted to cryptographic sizes.";
        time.estimated_quantum_attack_basis = basis.str();
    }

    // ---- Shor: elliptic-curve discrete logarithm ----------------------------------------

    ShorEcdlpModel shor_ecdlp_model(const std::size_t field_bits)
    {
        ShorEcdlpModel values;
        values.field_bits = field_bits;
        const std::uint64_t n = field_bits;
        values.point_register_qubits = 2U * n;
        values.total_qubits = 9U * n + 2U * static_cast<std::uint64_t>(ceil_log2(n)) + 10U;
        if (field_bits >= 1U && field_bits <= 4096U)
        {
            values.textbook_register_qubits = quantum::estimate_quantum_resources(
                quantum::CryptoTarget::ECC, field_bits).estimated_register_qubits;
        }
        // The formula is real-valued; a gate count is reported in whole gates.
        const long double toffoli = std::round(existing_model::estimate_ecc_shor_toffoli_gates(field_bits));
        values.toffoli_estimate_available = toffoli > 0.0L;
        values.toffoli_estimate = toffoli;
        return values;
    }

    void write_shor_ecdlp_logical_model(CircuitResources& model, const ShorEcdlpModel& values)
    {
        const long double point_register = static_cast<long double>(values.point_register_qubits);
        const long double total = static_cast<long double>(values.total_qubits);
        model.scope =
            "Published resource formulas of Roetteler, Naehrig, Svore and Lauter (2017) evaluated at this "
            "field size; not executed. Qubits: 9n + 2*ceil(log2 n) + 10. Toffoli gates: "
            "448*n^3*log2(n) + 4090*n^3, the formula already used by CryptoSetAnalysis. Both were derived "
            "for prime fields of cryptographic size; at a 7-bit toy field they are an extrapolation and "
            "only indicate the order of magnitude. Logical qubits only: no error-correction overhead, no "
            "physical-qubit count.";
        model.logical_qubits = Metric::estimated(
            point_register + 1.0L, "2n-qubit point register (x and y) plus one control qubit");
        model.ancilla_qubits = Metric::estimated(
            total - point_register - 1.0L, "reversible field-arithmetic workspace");
        model.total_qubits = Metric::estimated(total, "9n + 2*ceil(log2 n) + 10");
        model.gates_by_type.clear();
        if (values.toffoli_estimate_available)
        {
            model.gate_count = Metric::estimated(
                values.toffoli_estimate, "Toffoli gates; formula extrapolated to this toy size");
            model.circuit_depth = Metric::estimated(
                values.toffoli_estimate, "upper bound: Toffoli gates executed strictly one after another");
            model.gates_by_type.emplace_back(
                "Toffoli (formula estimate)", static_cast<std::uint64_t>(values.toffoli_estimate));
        }
        else
        {
            model.gate_count = Metric::not_modeled("the Toffoli formula is not defined at this field size");
            model.circuit_depth = Metric::not_modeled("no gate-count model at this size");
        }
        model.oracle_calls = Metric::not_applicable(
            "Shor's algorithm uses no black-box oracle; it applies controlled point additions");
        model.quantum_memory_bits = Metric::not_applicable("no quantum-accessible classical memory is needed");
        model.oracle_cost =
            "Not an oracle algorithm. Each controlled point addition is built from reversible modular "
            "arithmetic in F_p; its Toffoli cost is included in the estimated total above.";
    }

    void write_shor_ecdlp_time_estimate(
        TimeMeasurements& time, const ShorEcdlpModel& values, const HardwareScenario& scenario)
    {
        if (!values.toffoli_estimate_available)
        {
            time.estimated_quantum_attack_seconds =
                Metric::not_modeled("no gate-count model is defined at this field size");
            time.estimated_quantum_attack_basis = "NOT MODELED";
            return;
        }
        time.estimated_quantum_attack_seconds = Metric::estimated(
            values.toffoli_estimate * scenario.seconds_per_toffoli_gate, "scenario estimate, not a measurement");
        std::ostringstream basis;
        basis << format_number(values.toffoli_estimate) << " estimated Toffoli gates x "
              << format_seconds(scenario.seconds_per_toffoli_gate)
              << " assumed per serially executed logical Toffoli gate. The Toffoli count is an extrapolation "
                 "of a formula fitted to cryptographic field sizes.";
        time.estimated_quantum_attack_basis = basis.str();
    }

    std::string scenario_assumption_text(const HardwareScenario& scenario)
    {
        std::ostringstream text;
        text << "Estimated quantum attack time assumes an idealized, error-free logical quantum computer: "
             << format_seconds(scenario.seconds_per_grover_iteration) << " per Grover iteration and "
             << format_seconds(scenario.seconds_per_toffoli_gate)
             << " per serially executed logical Toffoli gate. These rates are scenario assumptions, not "
                "hardware measurements. Error correction, physical qubits, routing, state preparation and "
                "measurement overhead are excluded.";
        return text.str();
    }
}
