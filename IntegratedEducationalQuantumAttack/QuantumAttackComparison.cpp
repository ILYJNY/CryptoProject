#include "QuantumAttackComparison.h"

#include "EducationalQuantumAttack/Common/QuantumAttackReport.h"
#include "EducationalQuantumAttack/Common/QuantumAttackSupport.h"

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <sstream>

namespace crypto::integrated_educational_quantum_attack
{
    namespace
    {
        // A short cell for the fixed-width tables: a compact number, or the reason no value exists.
        [[nodiscard]] std::string cell(const eqa::Metric& metric)
        {
            if (!metric.has_value()) return std::string(eqa::metric_kind_label(metric.kind));
            const long double value = metric.value;
            std::ostringstream out;
            if (std::fabs(value) >= 1.0e7L) out << std::scientific << std::setprecision(2) << value;
            else if (std::floor(value) == value) out << std::fixed << std::setprecision(0) << value;
            else out << std::fixed << std::setprecision(3) << value;
            return out.str();
        }

        [[nodiscard]] std::string seconds_cell(const eqa::Metric& metric)
        {
            if (!metric.has_value()) return std::string(eqa::metric_kind_label(metric.kind));
            return eqa::format_seconds(metric.value);
        }

        [[nodiscard]] std::string bytes_cell(const eqa::Metric& metric)
        {
            if (!metric.has_value()) return std::string(eqa::metric_kind_label(metric.kind));
            return eqa::format_bytes(metric.value);
        }

        [[nodiscard]] std::string short_status(const eqa::ExecutionStatus status)
        {
            switch (status)
            {
                case eqa::ExecutionStatus::Simulated: return "SIMULATED";
                case eqa::ExecutionStatus::TheoryOnly: return "THEORY ONLY";
                case eqa::ExecutionStatus::NotModeled: return "NOT MODELED";
                case eqa::ExecutionStatus::Error: return "ERROR";
            }
            return "UNKNOWN";
        }

        void consider_minimum(
            Highlight& highlight, const ComparisonRow& row, const eqa::Metric& candidate)
        {
            if (!candidate.has_value()) return;
            if (highlight.available && candidate.value >= highlight.value.value) return;
            highlight.available = true;
            highlight.set_name = row.set_name;
            highlight.target = row.target;
            highlight.algorithm = row.algorithm;
            highlight.value = candidate;
        }

        void add_unique(std::vector<std::string>& list, const std::string& value)
        {
            if (std::find(list.begin(), list.end(), value) == list.end()) list.push_back(value);
        }

        // Records one value that does not exist, with the reason, so that a missing value is
        // listed explicitly instead of silently disappearing from the comparison.
        void note_absent(
            std::vector<std::string>& list, const ComparisonRow& row,
            const char* quantity, const eqa::Metric& metric)
        {
            if (metric.has_value() || metric.kind == eqa::MetricKind::NotApplicable) return;
            std::string line = row.set_name + " / " + row.target + " (" + row.algorithm + "): " + quantity +
                               " = " + std::string(eqa::metric_kind_label(metric.kind));
            if (!metric.note.empty()) line += " - " + metric.note;
            list.push_back(std::move(line));
        }

        void accumulate(eqa::Metric& total, const eqa::Metric& value, bool& any)
        {
            if (value.kind != eqa::MetricKind::Measured) return;
            total.value += value.value;
            any = true;
        }
    }

    Comparison compare_quantum_attacks(const std::vector<eqa::SetAttackReport>& sets)
    {
        Comparison comparison;
        comparison.fewest_simulated_qubits.unit = "qubits";
        comparison.fewest_model_qubits.unit = "logical qubits";
        comparison.shallowest_model_depth.unit = "layers";
        comparison.fastest_simulation.unit = "ms";
        comparison.fewest_simulated_qubits.criterion = "Fewest qubits among the circuits executed on the simulator";
        comparison.fewest_simulated_qubits.caveat =
            "Counts simulated qubits only; oracle workspace is not simulated for Grover-type circuits.";
        comparison.fewest_model_qubits.criterion = "Smallest quantum resource requirement (logical qubits of the resource model)";
        comparison.fewest_model_qubits.caveat =
            "Indicative only: Grover-type models are lower bounds that exclude the oracle's workspace, while "
            "the Shor models are formula extrapolations to toy sizes. Attacks that are NOT MODELED cannot win or lose.";
        comparison.shallowest_model_depth.criterion = "Smallest circuit depth (resource model)";
        comparison.shallowest_model_depth.caveat =
            "Indicative only: Grover-type depths exclude the depth of every oracle call, while the Shor depths "
            "are serial upper bounds from extrapolated gate counts.";
        comparison.fastest_simulation.criterion = "Fastest simulator run (classical simulation wall time, category A)";
        comparison.fastest_simulation.caveat =
            "A classical simulation time on this computer. It says nothing about quantum attack time.";

        bool any_runtime = false;
        bool any_setup = false;
        bool any_classical = false;
        comparison.total_simulator_runtime_ms = eqa::Metric::measured(0.0L, "sum over the circuits that were executed");
        comparison.total_simulator_setup_ms = eqa::Metric::measured(0.0L, "sum of the simulation-only precomputation");
        comparison.total_classical_runtime_ms = eqa::Metric::measured(0.0L, "sum over the classical attacks that were run");

        for (const eqa::SetAttackReport& set : sets)
        {
            for (const eqa::AttackResult& attack : set.attacks)
            {
                ComparisonRow row;
                row.set_name = set.name;
                row.target = std::string(eqa::attack_kind_label(attack.kind));
                row.algorithm = attack.algorithm_family;
                row.attack_id = attack.id;
                row.execution = attack.execution;
                row.outcome = attack.outcome;
                row.circuit_implemented = attack.circuit_implemented;
                row.simulator_executed = attack.simulator_executed;
                row.simulated_qubits = attack.simulated.total_qubits;
                row.simulated_operations = attack.simulated.gate_count;
                row.simulated_depth = attack.simulated.circuit_depth;
                row.model_qubits = attack.logical_model.total_qubits;
                row.model_gates = attack.logical_model.gate_count;
                row.model_depth = attack.logical_model.circuit_depth;
                row.oracle_calls = attack.simulator_executed
                    ? attack.simulated.oracle_calls : attack.logical_model.oracle_calls;
                row.quantum_memory_bits = attack.logical_model.quantum_memory_bits;
                row.simulator_runtime_ms = attack.time.simulator_runtime_ms;
                row.simulator_setup_ms = attack.time.simulator_setup_ms;
                row.estimated_quantum_seconds = attack.time.estimated_quantum_attack_seconds;
                row.classical_runtime_ms = attack.time.classical_attack_runtime_ms;
                row.state_vector_bytes = attack.compute.state_vector_bytes;
                row.process_peak_memory_bytes = attack.compute.process_peak_memory_bytes;
                row.cpu_threads = attack.compute.cpu_threads;
                row.backend_used = attack.compute.backend_used;
                row.gpu_executed = attack.compute.gpu_executed;
                row.gpu_status = attack.compute.gpu_status;
                row.gpu_kernel_ms = attack.compute.gpu_kernel_ms;
                row.gpu_transfer_ms = attack.compute.gpu_transfer_ms;
                row.applicability = attack.applicability;

                ++comparison.attacks_total;
                if (attack.simulator_executed) ++comparison.attacks_executed;
                if (attack.outcome == eqa::AttackOutcome::Succeeded) ++comparison.attacks_succeeded;
                if (attack.outcome == eqa::AttackOutcome::Failed ||
                    attack.execution == eqa::ExecutionStatus::Error)
                {
                    ++comparison.attacks_failed;
                }
                if (attack.execution == eqa::ExecutionStatus::TheoryOnly) ++comparison.attacks_theory_only;
                if (attack.execution == eqa::ExecutionStatus::NotModeled) ++comparison.attacks_not_modeled;

                accumulate(comparison.total_simulator_runtime_ms, row.simulator_runtime_ms, any_runtime);
                accumulate(comparison.total_simulator_setup_ms, row.simulator_setup_ms, any_setup);
                accumulate(comparison.total_classical_runtime_ms, row.classical_runtime_ms, any_classical);

                if (attack.simulator_executed)
                {
                    consider_minimum(comparison.fewest_simulated_qubits, row, row.simulated_qubits);
                    consider_minimum(comparison.fastest_simulation, row, row.simulator_runtime_ms);
                }
                consider_minimum(comparison.fewest_model_qubits, row, row.model_qubits);
                consider_minimum(comparison.shallowest_model_depth, row, row.model_depth);

                comparison.applicability.push_back(
                    set.name + " / " + row.target + " (" + row.algorithm + ") [" +
                    short_status(attack.execution) + "]: " + attack.applicability);

                if (attack.execution != eqa::ExecutionStatus::Simulated)
                {
                    comparison.not_modeled_items.push_back(
                        set.name + " / " + row.target + " (" + row.algorithm + "): " +
                        short_status(attack.execution) + " - " + attack.execution_note);
                }
                note_absent(comparison.not_modeled_items, row, "logical-model qubits", row.model_qubits);
                note_absent(comparison.not_modeled_items, row, "logical-model gate count", row.model_gates);
                note_absent(comparison.not_modeled_items, row, "logical-model circuit depth", row.model_depth);
                note_absent(comparison.not_modeled_items, row, "estimated quantum attack time", row.estimated_quantum_seconds);
                if (!attack.logical_model.oracle_cost.empty() &&
                    attack.logical_model.oracle_cost.find("NOT MODELED") != std::string::npos &&
                    attack.execution == eqa::ExecutionStatus::Simulated)
                {
                    comparison.not_modeled_items.push_back(
                        set.name + " / " + row.target + " (" + row.algorithm +
                        "): the gate count, depth and workspace qubits inside one oracle call = NOT MODELED");
                }

                for (const std::string& assumption : attack.assumptions) add_unique(comparison.assumptions, assumption);
                comparison.rows.push_back(std::move(row));
            }
        }

        if (!any_runtime)
            comparison.total_simulator_runtime_ms = eqa::Metric::not_executed("no circuit was executed");
        if (!any_setup)
            comparison.total_simulator_setup_ms = eqa::Metric::not_executed("no circuit was executed");
        if (!any_classical)
            comparison.total_classical_runtime_ms = eqa::Metric::not_executed("no classical baseline was run");
        return comparison;
    }

    std::string format_highlight(const Highlight& highlight)
    {
        std::ostringstream out;
        out << highlight.criterion << ":\n";
        if (highlight.available)
        {
            out << "    " << highlight.set_name << " / " << highlight.target << " (" << highlight.algorithm
                << "): " << eqa::format_metric(highlight.value, highlight.unit) << '\n';
        }
        else
        {
            out << "    NOT AVAILABLE (no attack has a value for this criterion)\n";
        }
        out << "    Caveat: " << highlight.caveat << '\n';
        return out.str();
    }

    std::string format_comparison_table(const Comparison& comparison)
    {
        std::ostringstream out;
        out << std::left
            << std::setw(16) << "Set" << std::setw(19) << "Target" << std::setw(18) << "Algorithm"
            << std::setw(13) << "Execution" << std::setw(15) << "Outcome"
            << std::setw(14) << "Qubits(sim)" << std::setw(14) << "Qubits(model)"
            << std::setw(14) << "Gates(model)" << std::setw(14) << "Depth(model)"
            << std::setw(14) << "Oracle calls" << std::setw(16) << "Simulator ms(A)"
            << std::setw(22) << "Est. quantum time(B)" << "Classical ms(C)\n";
        for (const ComparisonRow& row : comparison.rows)
        {
            // The set names differ only in their middle part; keep the table narrow.
            std::string set_label = row.set_name;
            const std::string prefix = "Educational ";
            if (set_label.rfind(prefix, 0U) == 0U) set_label.erase(0U, prefix.size());
            const std::string suffix = " analogue";
            if (set_label.size() > suffix.size() &&
                set_label.compare(set_label.size() - suffix.size(), suffix.size(), suffix) == 0)
            {
                set_label.erase(set_label.size() - suffix.size());
            }
            out << std::left
                << std::setw(16) << set_label << std::setw(19) << row.target << std::setw(18) << row.algorithm
                << std::setw(13) << short_status(row.execution)
                << std::setw(15) << eqa::attack_outcome_label(row.outcome)
                << std::setw(14) << cell(row.simulated_qubits) << std::setw(14) << cell(row.model_qubits)
                << std::setw(14) << cell(row.model_gates) << std::setw(14) << cell(row.model_depth)
                << std::setw(14) << cell(row.oracle_calls) << std::setw(16) << cell(row.simulator_runtime_ms)
                << std::setw(22) << seconds_cell(row.estimated_quantum_seconds)
                << cell(row.classical_runtime_ms) << '\n';
        }
        out << "\nColumn notes:\n"
            << "  Qubits(sim)     - qubits of the circuit executed on the state-vector simulator (measured).\n"
            << "  Qubits/Gates/Depth(model) - logical resource model (computed or estimated, never executed);\n"
            << "                    Grover-type rows exclude everything inside the oracle (lower bounds).\n"
            << "  Simulator ms(A) - classical simulation wall time. NOT quantum attack time.\n"
            << "  Est. quantum time(B) - scenario estimate under the stated assumptions. NOT a measurement.\n"
            << "  Classical ms(C) - measured runtime of the existing classical attack on the same instance.\n"
            << "  NOT EXECUTED / NOT MODELED / N/A - no value exists; never read these as zero.\n";
        return out.str();
    }

    std::string format_resource_usage_table(const Comparison& comparison)
    {
        std::ostringstream out;
        out << std::left
            << std::setw(16) << "Set" << std::setw(19) << "Target" << std::setw(30) << "Backend used"
            << std::setw(14) << "CPU threads" << std::setw(16) << "State vector" << std::setw(16) << "Peak memory"
            << std::setw(18) << "Quantum mem bits" << std::setw(8) << "GPU run" << std::setw(16) << "GPU kernel ms"
            << "GPU transfer ms\n";
        for (const ComparisonRow& row : comparison.rows)
        {
            std::string set_label = row.set_name;
            const std::string prefix = "Educational ";
            if (set_label.rfind(prefix, 0U) == 0U) set_label.erase(0U, prefix.size());
            const std::string suffix = " analogue";
            if (set_label.size() > suffix.size() &&
                set_label.compare(set_label.size() - suffix.size(), suffix.size(), suffix) == 0)
            {
                set_label.erase(set_label.size() - suffix.size());
            }
            out << std::left
                << std::setw(16) << set_label << std::setw(19) << row.target << std::setw(30) << row.backend_used
                << std::setw(14) << cell(row.cpu_threads) << std::setw(16) << bytes_cell(row.state_vector_bytes)
                << std::setw(16) << bytes_cell(row.process_peak_memory_bytes)
                << std::setw(18) << cell(row.quantum_memory_bits)
                << std::setw(8) << (row.gpu_executed ? "YES" : "NO")
                << std::setw(16) << cell(row.gpu_kernel_ms) << cell(row.gpu_transfer_ms) << '\n';
        }
        out << "\nPeak memory is the process-wide high-water mark at the end of each attack; it cannot decrease,\n"
               "so it bounds an attack's memory from above. A GPU value is shown only when GPU kernels really ran.\n";
        return out.str();
    }

    std::string comparison_csv(const Comparison& comparison)
    {
        const auto cells = [](std::ostringstream& out, const eqa::Metric& metric)
        {
            out << ',' << eqa::csv_field(eqa::metric_cell(metric)) << ','
                << eqa::csv_field(std::string(eqa::metric_kind_label(metric.kind)));
        };
        std::ostringstream out;
        out << "set,target,algorithm,attack_id,execution_status,attack_outcome,circuit_implemented,simulator_executed,"
               "simulated_qubits,simulated_qubits_kind,simulated_operations,simulated_operations_kind,"
               "simulated_depth_operations,simulated_depth_operations_kind,"
               "model_logical_qubits,model_logical_qubits_kind,model_gates,model_gates_kind,"
               "model_depth_layers,model_depth_layers_kind,oracle_calls,oracle_calls_kind,"
               "quantum_memory_bits,quantum_memory_bits_kind,"
               "time_a_simulator_runtime_ms,time_a_simulator_runtime_ms_kind,"
               "time_a_simulator_setup_ms,time_a_simulator_setup_ms_kind,"
               "time_b_estimated_quantum_attack_seconds,time_b_estimated_quantum_attack_seconds_kind,"
               "time_c_classical_attack_runtime_ms,time_c_classical_attack_runtime_ms_kind,"
               "state_vector_bytes,state_vector_bytes_kind,process_peak_memory_bytes,process_peak_memory_bytes_kind,"
               "cpu_threads,cpu_threads_kind,backend_used,gpu_executed,gpu_status,"
               "gpu_kernel_ms,gpu_kernel_ms_kind,gpu_transfer_ms,gpu_transfer_ms_kind,applicability\n";
        for (const ComparisonRow& row : comparison.rows)
        {
            out << eqa::csv_field(row.set_name) << ',' << eqa::csv_field(row.target) << ','
                << eqa::csv_field(row.algorithm) << ',' << eqa::csv_field(row.attack_id) << ','
                << eqa::csv_field(std::string(eqa::execution_status_label(row.execution))) << ','
                << eqa::csv_field(std::string(eqa::attack_outcome_label(row.outcome))) << ','
                << (row.circuit_implemented ? "YES" : "NO") << ',' << (row.simulator_executed ? "YES" : "NO");
            cells(out, row.simulated_qubits);
            cells(out, row.simulated_operations);
            cells(out, row.simulated_depth);
            cells(out, row.model_qubits);
            cells(out, row.model_gates);
            cells(out, row.model_depth);
            cells(out, row.oracle_calls);
            cells(out, row.quantum_memory_bits);
            cells(out, row.simulator_runtime_ms);
            cells(out, row.simulator_setup_ms);
            cells(out, row.estimated_quantum_seconds);
            cells(out, row.classical_runtime_ms);
            cells(out, row.state_vector_bytes);
            cells(out, row.process_peak_memory_bytes);
            cells(out, row.cpu_threads);
            out << ',' << eqa::csv_field(row.backend_used) << ',' << (row.gpu_executed ? "YES" : "NO") << ','
                << eqa::csv_field(row.gpu_status);
            cells(out, row.gpu_kernel_ms);
            cells(out, row.gpu_transfer_ms);
            out << ',' << eqa::csv_field(row.applicability) << '\n';
        }
        return out.str();
    }

    std::string aggregate_metrics_csv(const Comparison& comparison, const eqa::SetStatus overall_status)
    {
        std::ostringstream out;
        out << "metric,value,unit,kind,scope\n";
        const auto count = [&out](const char* name, const std::size_t value, const char* scope)
        {
            out << name << ',' << value << ",attacks,computed," << eqa::csv_field(scope) << '\n';
        };
        const auto metric = [&out](const char* name, const eqa::Metric& value, const char* unit, const std::string& scope)
        {
            out << name << ',' << eqa::csv_field(eqa::metric_cell(value)) << ',' << unit << ','
                << eqa::csv_field(std::string(eqa::metric_kind_label(value.kind))) << ','
                << eqa::csv_field(scope) << '\n';
        };
        const auto highlight = [&out](const char* name, const Highlight& value, const char* unit)
        {
            out << name << ',';
            if (value.available) out << eqa::csv_field(eqa::metric_cell(value.value));
            else out << "NOT AVAILABLE";
            out << ',' << unit << ','
                << (value.available ? eqa::csv_field(std::string(eqa::metric_kind_label(value.value.kind))) : std::string("N/A"))
                << ','
                << eqa::csv_field(value.available
                       ? value.set_name + " / " + value.target + " (" + value.algorithm + "). " + value.caveat
                       : value.caveat)
                << '\n';
        };

        out << "overall_status," << eqa::csv_field(std::string(eqa::set_status_label(overall_status)))
            << ",status,computed,three independent sets; no set is merged with another\n";
        count("attacks_total", comparison.attacks_total, "all attacks of the three sets");
        count("attacks_executed_on_simulator", comparison.attacks_executed, "circuits that really ran on the state-vector simulator");
        count("attacks_succeeded", comparison.attacks_succeeded, "executed and classically verified");
        count("attacks_failed", comparison.attacks_failed, "executed without a verified result, or raised an error");
        count("attacks_theory_only", comparison.attacks_theory_only, "resource model only; circuit not executed");
        count("attacks_not_modeled", comparison.attacks_not_modeled, "no circuit-level model exists");
        metric("time_a_total_simulator_runtime_ms", comparison.total_simulator_runtime_ms, "ms",
               "sum of classical simulation wall time over executed circuits; NOT quantum attack time");
        metric("time_a_total_simulator_setup_ms", comparison.total_simulator_setup_ms, "ms",
               "sum of classical precomputation needed only by the simulation");
        metric("time_c_total_classical_attack_runtime_ms", comparison.total_classical_runtime_ms, "ms",
               "sum of the measured runtimes of the existing classical attacks");
        out << "time_b_total_estimated_quantum_attack_seconds,NOT SUMMED,seconds,N/A,"
            << eqa::csv_field("estimates of different attack models rest on different assumptions and are never added")
            << '\n';
        highlight("fewest_simulated_qubits", comparison.fewest_simulated_qubits, "qubits");
        highlight("smallest_model_logical_qubits", comparison.fewest_model_qubits, "qubits");
        highlight("smallest_model_circuit_depth", comparison.shallowest_model_depth, "layers");
        highlight("fastest_simulator_runtime_ms", comparison.fastest_simulation, "ms");
        return out.str();
    }
}
