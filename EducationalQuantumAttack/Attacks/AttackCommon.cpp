#include "AttackCommon.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace crypto::educational_quantum_attack
{
    std::string hex_string(const std::span<const std::uint8_t> bytes)
    {
        std::ostringstream out;
        out << std::hex << std::uppercase << std::setfill('0');
        for (const std::uint8_t byte : bytes) out << std::setw(2) << static_cast<unsigned int>(byte);
        return out.str();
    }

    std::string hex_value(const std::uint64_t value, const std::size_t minimum_digits)
    {
        std::ostringstream out;
        out << "0x" << std::hex << std::uppercase << std::setfill('0')
            << std::setw(static_cast<int>(minimum_digits)) << value;
        return out.str();
    }

    std::string printable(const std::string& text, const std::size_t maximum_length)
    {
        std::string result;
        result.reserve(std::min(text.size(), maximum_length));
        for (const char character : text)
        {
            if (result.size() >= maximum_length) break;
            const auto code = static_cast<unsigned char>(character);
            result += (code < 0x20U || code == 0x7FU) ? '?' : character;
        }
        if (text.size() > maximum_length) result += "...";
        return result;
    }

    void write_simulated_grover(
        AttackResult& report,
        const GroverSearchResult& search,
        const double oracle_table_ms,
        const std::string& oracle_table_description)
    {
        CircuitResources& simulated = report.simulated;
        simulated.scope =
            "Executed on the QuantumAttack state-vector simulator. The search register and every Grover "
            "iteration are simulated exactly. The oracle is applied through its truth table (one phase "
            "flip per marked candidate) and the diffusion operator is one native simulator operation, so "
            "the operation counts below are simulator operations, not elementary logical gates.";
        const auto qubits = static_cast<long double>(search.qubits);
        simulated.logical_qubits = Metric::measured(qubits, "search register held in the state vector");
        simulated.ancilla_qubits = Metric::measured(
            0.0L, "none simulated: the oracle and the reflection act directly on the state vector");
        simulated.total_qubits = Metric::measured(qubits);
        simulated.gate_count = Metric::measured(
            static_cast<long double>(search.simulator_gate_count),
            "simulator operations over " + std::to_string(search.circuit_runs) + " circuit run(s)");
        simulated.gates_by_type.clear();
        simulated.gates_by_type.emplace_back("H", search.hadamard_gates);
        simulated.gates_by_type.emplace_back("oracle phase flip (per marked state)", search.phase_flip_operations);
        simulated.gates_by_type.emplace_back("diffusion", search.diffusion_operations);
        simulated.gates_by_type.emplace_back("measurement (whole register)", search.measurements);
        simulated.circuit_depth = Metric::measured(
            static_cast<long double>(search.deepest_run_operation_depth),
            "sequential simulator operations in the deepest circuit run");
        simulated.oracle_calls = Metric::measured(
            static_cast<long double>(search.total_grover_iterations),
            "quantum oracle calls = Grover iterations, summed over all circuit runs");
        simulated.quantum_memory_bits = Metric::not_applicable("no quantum-accessible memory is simulated");
        simulated.oracle_cost = oracle_table_description;

        report.time.simulator_runtime_ms = Metric::measured(
            static_cast<long double>(search.simulation_wall_ms),
            "wall time of the classical state-vector simulation of the circuit run(s)");
        report.time.simulator_setup_ms = Metric::measured(
            static_cast<long double>(oracle_table_ms),
            "classical construction of the oracle truth table; needed only by the simulation");
    }

    void PhaseEstimationTotals::add(const PhaseEstimationResult& run)
    {
        ++circuit_runs;
        controlled_permutations += run.controlled_permutations;
        hadamard_gates += run.hadamard_gates;
        phase_shift_gates += run.phase_shift_gates;
        reset_x_gates += run.reset_x_gates;
        measurements += run.measurements;
        simulator_gate_count += run.simulator_gate_count;
        deepest_run_operation_depth = std::max(deepest_run_operation_depth, run.simulator_operation_depth);
        qubits = run.qubits;
        state_vector_bytes = run.state_vector_bytes;
        simulation_wall_ms += run.simulation_wall_ms;
        permutation_table_ms += run.permutation_table_ms;

        backend.cpu_operations += run.backend.cpu_operations;
        backend.gpu_operations += run.backend.gpu_operations;
        backend.cpu_fallback_operations += run.backend.cpu_fallback_operations;
        backend.cpu_wall_time_ms += run.backend.cpu_wall_time_ms;
        backend.gpu_kernel_time_ms += run.backend.gpu_kernel_time_ms;
        backend.gpu_transfer_time_ms += run.backend.gpu_transfer_time_ms;
        backend.gpu_initialization_time_ms += run.backend.gpu_initialization_time_ms;
        backend.cpu_threads_used = run.backend.cpu_threads_used;
        backend.gpu_device_used = run.backend.gpu_device_used;
        backend.gpu_devices_used = run.backend.gpu_devices_used;
    }

    void write_simulated_phase_estimation(
        AttackResult& report,
        const PhaseEstimationTotals& totals,
        const std::string& controlled_operation_name,
        const std::string& scope)
    {
        CircuitResources& simulated = report.simulated;
        simulated.scope = scope;
        const auto qubits = static_cast<long double>(totals.qubits);
        simulated.logical_qubits = Metric::measured(
            qubits, "work register plus one control qubit held in the state vector");
        simulated.ancilla_qubits = Metric::measured(
            0.0L, "none simulated: each controlled operation is one exact basis-state permutation");
        simulated.total_qubits = Metric::measured(qubits);
        simulated.gate_count = Metric::measured(
            static_cast<long double>(totals.simulator_gate_count),
            "simulator gate operations over " + std::to_string(totals.circuit_runs) +
            " circuit run(s); measurements are counted separately");
        simulated.gates_by_type.clear();
        simulated.gates_by_type.emplace_back(controlled_operation_name, totals.controlled_permutations);
        simulated.gates_by_type.emplace_back("H", totals.hadamard_gates);
        simulated.gates_by_type.emplace_back("phase shift (classically controlled)", totals.phase_shift_gates);
        simulated.gates_by_type.emplace_back("X (control-qubit reset)", totals.reset_x_gates);
        simulated.gates_by_type.emplace_back("mid-circuit measurement", totals.measurements);
        simulated.circuit_depth = Metric::measured(
            static_cast<long double>(totals.deepest_run_operation_depth),
            "sequential simulator operations in the deepest circuit run");
        simulated.oracle_calls = Metric::not_applicable("Shor's algorithm uses no black-box oracle");
        simulated.quantum_memory_bits = Metric::not_applicable("no quantum-accessible memory is simulated");
        simulated.oracle_cost =
            "Not an oracle algorithm. Each " + controlled_operation_name +
            " is applied as one exact reversible permutation; its elementary-gate cost is not simulated.";

        report.time.simulator_runtime_ms = Metric::measured(
            static_cast<long double>(totals.simulation_wall_ms),
            "wall time of the classical state-vector simulation of the circuit run(s)");
        report.time.simulator_setup_ms = Metric::measured(
            static_cast<long double>(totals.permutation_table_ms),
            "classical construction of the permutation tables; needed only by the simulation");
    }

    void mark_not_executed(AttackResult& report, const std::string& reason)
    {
        report.execution = ExecutionStatus::TheoryOnly;
        report.simulator_executed = false;
        report.execution_note = reason;
        report.outcome = AttackOutcome::NotAttempted;
        report.verified_against_public_instance = false;

        CircuitResources& simulated = report.simulated;
        simulated.scope = "The circuit was NOT executed on the simulator: " + reason;
        simulated.logical_qubits = Metric::not_executed();
        simulated.ancilla_qubits = Metric::not_executed();
        simulated.total_qubits = Metric::not_executed();
        simulated.gate_count = Metric::not_executed();
        simulated.gates_by_type.clear();
        simulated.circuit_depth = Metric::not_executed();
        simulated.oracle_calls = Metric::not_executed();
        simulated.quantum_memory_bits = Metric::not_executed();
        simulated.oracle_cost.clear();

        report.time.simulator_runtime_ms = Metric::not_executed("the circuit was not simulated");
        report.time.simulator_setup_ms = Metric::not_executed("the circuit was not simulated");
        report.time.simulator_cpu_time_ms = Metric::not_executed("the circuit was not simulated");
    }

    void mark_error(AttackResult& report, const std::string& what)
    {
        report.execution = ExecutionStatus::Error;
        report.execution_note = "The simulation raised an error: " + what;
        report.outcome = AttackOutcome::Failed;
        report.verified_against_public_instance = false;
    }
}
