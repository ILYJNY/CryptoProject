#include "QuantumAttackReport.h"

#include "QuantumAttackSupport.h"

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace crypto::educational_quantum_attack
{
    namespace
    {
        constexpr const char* kRule =
            "--------------------------------------------------------------------------------";
        constexpr const char* kDoubleRule =
            "================================================================================";

        [[nodiscard]] const char* yes_no(const bool value) { return value ? "YES" : "NO"; }

        [[nodiscard]] std::string ground_truth_text(const AttackResult& attack)
        {
            if (attack.matches_ground_truth.has_value()) return *attack.matches_ground_truth ? "YES" : "NO";
            if (attack.outcome == AttackOutcome::Succeeded)
                return "N/A (this problem has no withheld secret; the result is verified by recomputation)";
            return "NOT CHECKED (nothing was recovered)";
        }

        [[nodiscard]] std::string gates_text(const std::vector<std::pair<std::string, std::uint64_t>>& gates)
        {
            if (gates.empty()) return "none listed";
            std::ostringstream out;
            bool first = true;
            for (const auto& [name, count] : gates)
            {
                if (!first) out << "; ";
                first = false;
                out << name << " = " << count;
            }
            return out.str();
        }

        void write_named_values(std::ostringstream& out, const NamedValues& values)
        {
            for (const auto& [name, value] : values) out << "    " << name << ": " << value << '\n';
        }

        void write_list(std::ostringstream& out, const char* title, const std::vector<std::string>& items)
        {
            if (items.empty()) return;
            out << title << '\n';
            for (const std::string& item : items) out << "  - " << item << '\n';
        }

        void write_resources(std::ostringstream& out, const CircuitResources& resources)
        {
            out << "  Scope            : " << resources.scope << '\n'
                << "  Logical qubits   : " << format_metric(resources.logical_qubits) << '\n'
                << "  Ancilla qubits   : " << format_metric(resources.ancilla_qubits) << '\n'
                << "  Total qubits     : " << format_metric(resources.total_qubits) << '\n'
                << "  Gate count       : " << format_metric(resources.gate_count) << '\n'
                << "  Gates by type    : " << gates_text(resources.gates_by_type) << '\n'
                << "  Circuit depth    : " << format_metric(resources.circuit_depth) << '\n'
                << "  Oracle calls     : " << format_metric(resources.oracle_calls) << '\n'
                << "  Quantum memory   : " << format_metric(resources.quantum_memory_bits, "bits") << '\n';
            if (!resources.oracle_cost.empty())
                out << "  Oracle cost      : " << resources.oracle_cost << '\n';
        }

        [[nodiscard]] std::string seconds_text(const Metric& metric)
        {
            if (!metric.has_value()) return format_metric(metric);
            std::ostringstream out;
            out << format_seconds(metric.value) << " [" << metric_kind_label(metric.kind) << ']';
            if (!metric.note.empty()) out << " (" << metric.note << ')';
            return out.str();
        }

        [[nodiscard]] std::string bytes_text(const Metric& metric)
        {
            if (!metric.has_value()) return format_metric(metric);
            std::ostringstream out;
            out << format_bytes(metric.value) << " [" << metric_kind_label(metric.kind) << ']';
            if (!metric.note.empty()) out << " (" << metric.note << ')';
            return out.str();
        }

        void append_metric_cells(std::ostringstream& out, const Metric& metric)
        {
            out << ',' << csv_field(metric_cell(metric)) << ',' << csv_field(std::string(metric_kind_label(metric.kind)));
        }

        void append_json_metric(std::ostringstream& out, const char* name, const Metric& metric, const bool trailing_comma = true)
        {
            out << json_string(name) << ": {\"kind\": " << json_string(std::string(metric_kind_label(metric.kind)))
                << ", \"value\": ";
            if (metric.has_value()) out << metric_cell(metric);
            else out << "null";
            out << ", \"note\": " << json_string(metric.note) << '}';
            if (trailing_comma) out << ", ";
        }

        void append_json_resources(std::ostringstream& out, const CircuitResources& resources)
        {
            out << "{\"scope\": " << json_string(resources.scope) << ", ";
            append_json_metric(out, "logical_qubits", resources.logical_qubits);
            append_json_metric(out, "ancilla_qubits", resources.ancilla_qubits);
            append_json_metric(out, "total_qubits", resources.total_qubits);
            append_json_metric(out, "gate_count", resources.gate_count);
            out << "\"gates_by_type\": {";
            bool first = true;
            for (const auto& [name, count] : resources.gates_by_type)
            {
                if (!first) out << ", ";
                first = false;
                out << json_string(name) << ": " << count;
            }
            out << "}, ";
            append_json_metric(out, "circuit_depth", resources.circuit_depth);
            append_json_metric(out, "oracle_calls", resources.oracle_calls);
            append_json_metric(out, "quantum_memory_bits", resources.quantum_memory_bits);
            out << "\"oracle_cost\": " << json_string(resources.oracle_cost) << '}';
        }

        void append_json_named_values(std::ostringstream& out, const NamedValues& values)
        {
            out << '{';
            bool first = true;
            for (const auto& [name, value] : values)
            {
                if (!first) out << ", ";
                first = false;
                out << json_string(name) << ": " << json_string(value);
            }
            out << '}';
        }

        void append_json_strings(std::ostringstream& out, const std::vector<std::string>& values)
        {
            out << '[';
            bool first = true;
            for (const std::string& value : values)
            {
                if (!first) out << ", ";
                first = false;
                out << json_string(value);
            }
            out << ']';
        }
    }

    std::string csv_field(const std::string& value)
    {
        if (value.find_first_of(",\"\r\n") == std::string::npos) return value;
        std::string result = "\"";
        for (const char character : value)
        {
            if (character == '"') result += "\"\"";
            else if (character == '\r' || character == '\n') result += ' ';
            else result += character;
        }
        result += '"';
        return result;
    }

    std::string json_string(const std::string& value)
    {
        std::ostringstream out;
        out << '"';
        for (const char character : value)
        {
            const auto code = static_cast<unsigned char>(character);
            switch (character)
            {
                case '"': out << "\\\""; break;
                case '\\': out << "\\\\"; break;
                case '\n': out << "\\n"; break;
                case '\r': out << "\\r"; break;
                case '\t': out << "\\t"; break;
                default:
                    if (code < 0x20U)
                    {
                        out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                            << static_cast<unsigned int>(code) << std::dec << std::setfill(' ');
                    }
                    else
                    {
                        out << character;
                    }
            }
        }
        out << '"';
        return out.str();
    }

    std::string format_attack_report(const AttackResult& attack)
    {
        std::ostringstream out;
        out << kRule << '\n'
            << '[' << attack_kind_label(attack.kind) << "] " << attack.algorithm_family << "  |  "
            << execution_status_label(attack.execution) << "  |  " << attack_outcome_label(attack.outcome) << '\n'
            << kRule << '\n'
            << "Cryptosystem set        : " << attack.system_name << '\n'
            << "Attack target           : " << attack.target << '\n'
            << "Mathematical problem    : " << attack.mathematical_problem << '\n'
            << "Attack algorithm        : " << attack.algorithm << '\n'
            << "Attack model scope      : " << attack.applicability << '\n'
            << "Actual input parameters :\n";
        write_named_values(out, attack.parameters);
        out << "Execution status        : " << execution_status_label(attack.execution) << '\n'
            << "Circuit implemented     : " << yes_no(attack.circuit_implemented) << '\n'
            << "Executed on simulator   : " << yes_no(attack.simulator_executed) << '\n';
        if (!attack.execution_note.empty())
            out << "Execution note          : " << attack.execution_note << '\n';
        out << "Attack outcome          : " << attack_outcome_label(attack.outcome) << '\n'
            << "Verified against the public instance : " << yes_no(attack.verified_against_public_instance) << '\n'
            << "Matches the withheld ground truth    : " << ground_truth_text(attack) << '\n';
        if (!attack.recovered.empty())
        {
            out << "Recovered values        :\n";
            write_named_values(out, attack.recovered);
        }

        out << "\n[1] CIRCUIT EXECUTED ON THE STATE-VECTOR SIMULATOR\n";
        write_resources(out, attack.simulated);

        out << "\n[2] LOGICAL RESOURCE MODEL (computed or estimated; never executed)\n";
        write_resources(out, attack.logical_model);

        out << "\n[3] TIME - three different quantities; they are never added together\n"
            << "  A. Quantum simulator runtime - a classical computer simulating the circuit (measured)\n"
            << "       simulation            : " << format_metric(attack.time.simulator_runtime_ms, "ms") << '\n'
            << "       simulation-only setup : " << format_metric(attack.time.simulator_setup_ms, "ms") << '\n'
            << "       process CPU time      : " << format_metric(attack.time.simulator_cpu_time_ms, "ms") << '\n'
            << "  B. Estimated quantum attack time - hypothetical quantum hardware (scenario estimate)\n"
            << "       estimate              : " << seconds_text(attack.time.estimated_quantum_attack_seconds) << '\n'
            << "       basis                 : " << attack.time.estimated_quantum_attack_basis << '\n'
            << "  C. Classical attack runtime - the existing classical attack on this CPU (measured)\n"
            << "       runtime               : " << format_metric(attack.time.classical_attack_runtime_ms, "ms") << '\n'
            << "       work                  : " << format_metric(attack.time.classical_attack_work) << '\n'
            << "       method                : " << attack.time.classical_attack_description << '\n';

        const ComputeResources& compute = attack.compute;
        out << "\n[4] COMPUTER RESOURCES OF THE CLASSICAL SIMULATION\n"
            << "  Backend requested      : " << compute.backend_requested << '\n'
            << "  Backend used           : " << compute.backend_used << '\n'
            << "  CPU threads            : " << format_metric(compute.cpu_threads) << '\n'
            << "  State vector           : " << bytes_text(compute.state_vector_bytes) << '\n'
            << "  Working memory (model) : " << bytes_text(compute.working_memory_bytes) << '\n'
            << "  Process peak memory    : " << bytes_text(compute.process_peak_memory_bytes) << '\n'
            << "  GPU requested          : " << yes_no(compute.gpu_requested) << '\n'
            << "  GPU actually executed  : " << yes_no(compute.gpu_executed) << '\n'
            << "  GPU status             : " << compute.gpu_status << '\n'
            << "  GPU device             : " << (compute.gpu_device.empty() ? "N/A" : compute.gpu_device) << '\n'
            << "  GPU operations         : " << format_metric(compute.gpu_operations) << '\n'
            << "  GPU kernel runtime     : " << format_metric(compute.gpu_kernel_ms, "ms") << '\n'
            << "  GPU transfer runtime   : " << format_metric(compute.gpu_transfer_ms, "ms") << '\n'
            << "  CPU fallback operations: " << format_metric(compute.cpu_fallback_operations) << '\n';

        out << '\n';
        write_list(out, "Assumptions:", attack.assumptions);
        write_list(out, "Limitations:", attack.limitations);
        write_list(out, "Notes:", attack.notes);

        if (attack.validation.included)
        {
            const ValidationExperiment& validation = attack.validation;
            out << "\n[SEPARATE ALGORITHM-VALIDATION EXPERIMENT - NOT AN ATTACK ON THE TARGET ABOVE]\n"
                << "  " << validation.title << '\n'
                << "  What it runs : " << validation.description << '\n'
                << "  Result       : " << (validation.passed ? "PASS" : "CHECK") << " (" << validation.status << ")\n"
                << "  Qubits       : " << format_metric(validation.qubits) << '\n'
                << "  Runtime      : " << format_metric(validation.simulator_runtime_ms, "ms") << '\n'
                << "  Disclaimer   : " << validation.disclaimer << '\n';
        }
        if (attack.reference.included)
        {
            out << "\n[REFERENCE SCENARIO - THEORY ONLY]\n"
                << "  " << attack.reference.title << '\n';
            write_named_values(out, attack.reference.lines);
            out << "  Disclaimer   : " << attack.reference.disclaimer << '\n';
        }
        out << '\n';
        return out.str();
    }

    std::string format_set_report(const SetAttackReport& report)
    {
        std::ostringstream out;
        out << kDoubleRule << '\n'
            << "EDUCATIONAL QUANTUM ATTACK ANALYSIS - " << report.name << '\n'
            << kDoubleRule << '\n'
            << "Composition : " << report.composition << '\n'
            << "Disclaimer  : " << report.disclaimer << '\n'
            << "Set status  : " << set_status_label(report.status) << '\n'
            << "Analysis wall time (everything, classical): " << std::fixed << std::setprecision(3)
            << report.wall_ms << " ms\n"
            << "Attacked instance:\n";
        out.unsetf(std::ios::floatfield);
        write_named_values(out, report.instance);
        out << "\nReading guide:\n"
            << "  - [1] holds what was really executed on the classical state-vector simulator.\n"
            << "  - [2] holds a logical resource model that was computed, not executed.\n"
            << "  - Simulator runtime (A) is NOT quantum attack time (B); neither is the classical attack runtime (C).\n"
            << "  - NOT MODELED / NOT EXECUTED / N/A mean that no value exists; they never mean zero.\n"
            << "  - All qubit counts are logical qubits; error-correction overhead is excluded throughout.\n\n";
        for (const AttackResult& attack : report.attacks) out << format_attack_report(attack);
        return out.str();
    }

    std::string format_set_overview(const std::vector<SetAttackReport>& reports)
    {
        std::ostringstream out;
        out << std::left << std::setw(38) << "Set" << std::setw(20) << "Target" << std::setw(20) << "Algorithm"
            << std::setw(30) << "Execution" << "Outcome\n";
        for (const SetAttackReport& report : reports)
        {
            for (const AttackResult& attack : report.attacks)
            {
                out << std::left << std::setw(38) << report.name
                    << std::setw(20) << attack_kind_label(attack.kind)
                    << std::setw(20) << attack.algorithm_family
                    << std::setw(30) << execution_status_label(attack.execution)
                    << attack_outcome_label(attack.outcome) << '\n';
            }
            out << std::left << std::setw(38) << "" << "-> set status: " << set_status_label(report.status) << '\n';
        }
        return out.str();
    }

    std::string metrics_csv_header()
    {
        return
            "set,attack_id,target,mathematical_problem,algorithm_family,algorithm,execution_status,"
            "circuit_implemented,simulator_executed,attack_outcome,verified_against_public_instance,"
            "matches_ground_truth,"
            "simulated_scope,simulated_logical_qubits,simulated_logical_qubits_kind,"
            "simulated_ancilla_qubits,simulated_ancilla_qubits_kind,"
            "simulated_total_qubits,simulated_total_qubits_kind,"
            "simulated_gate_count_operations,simulated_gate_count_operations_kind,simulated_gates_by_type,"
            "simulated_circuit_depth_operations,simulated_circuit_depth_operations_kind,"
            "simulated_oracle_calls,simulated_oracle_calls_kind,"
            "simulated_quantum_memory_bits,simulated_quantum_memory_bits_kind,"
            "model_scope,model_logical_qubits,model_logical_qubits_kind,"
            "model_ancilla_qubits,model_ancilla_qubits_kind,"
            "model_total_qubits,model_total_qubits_kind,"
            "model_gate_count_gates,model_gate_count_gates_kind,model_gates_by_type,"
            "model_circuit_depth_layers,model_circuit_depth_layers_kind,"
            "model_oracle_calls,model_oracle_calls_kind,"
            "model_quantum_memory_bits,model_quantum_memory_bits_kind,"
            "time_a_simulator_runtime_ms,time_a_simulator_runtime_ms_kind,"
            "time_a_simulator_setup_ms,time_a_simulator_setup_ms_kind,"
            "time_a_simulator_cpu_time_ms,time_a_simulator_cpu_time_ms_kind,"
            "time_b_estimated_quantum_attack_seconds,time_b_estimated_quantum_attack_seconds_kind,time_b_basis,"
            "time_c_classical_attack_runtime_ms,time_c_classical_attack_runtime_ms_kind,"
            "time_c_classical_attack_work_units,time_c_classical_attack_work_units_kind,time_c_method,"
            "backend_requested,backend_used,cpu_threads,cpu_threads_kind,"
            "state_vector_bytes,state_vector_bytes_kind,"
            "working_memory_bytes,working_memory_bytes_kind,"
            "process_peak_memory_bytes,process_peak_memory_bytes_kind,"
            "gpu_requested,gpu_executed,gpu_status,gpu_device,"
            "gpu_operations,gpu_operations_kind,gpu_kernel_ms,gpu_kernel_ms_kind,"
            "gpu_transfer_ms,gpu_transfer_ms_kind,cpu_fallback_operations,cpu_fallback_operations_kind,"
            "execution_note";
    }

    std::string metrics_csv_row(const SetAttackReport& set, const AttackResult& attack)
    {
        std::ostringstream out;
        out << csv_field(set.name) << ',' << csv_field(attack.id) << ',' << csv_field(attack.target) << ','
            << csv_field(attack.mathematical_problem) << ',' << csv_field(attack.algorithm_family) << ','
            << csv_field(attack.algorithm) << ','
            << csv_field(std::string(execution_status_label(attack.execution))) << ','
            << yes_no(attack.circuit_implemented) << ',' << yes_no(attack.simulator_executed) << ','
            << csv_field(std::string(attack_outcome_label(attack.outcome))) << ','
            << yes_no(attack.verified_against_public_instance) << ','
            << (attack.matches_ground_truth.has_value()
                    ? yes_no(*attack.matches_ground_truth)
                    : (attack.outcome == AttackOutcome::Succeeded ? "N/A" : "NOT CHECKED"));

        for (const CircuitResources* resources : {&attack.simulated, &attack.logical_model})
        {
            out << ',' << csv_field(resources->scope);
            append_metric_cells(out, resources->logical_qubits);
            append_metric_cells(out, resources->ancilla_qubits);
            append_metric_cells(out, resources->total_qubits);
            append_metric_cells(out, resources->gate_count);
            out << ',' << csv_field(gates_text(resources->gates_by_type));
            append_metric_cells(out, resources->circuit_depth);
            append_metric_cells(out, resources->oracle_calls);
            append_metric_cells(out, resources->quantum_memory_bits);
        }

        append_metric_cells(out, attack.time.simulator_runtime_ms);
        append_metric_cells(out, attack.time.simulator_setup_ms);
        append_metric_cells(out, attack.time.simulator_cpu_time_ms);
        append_metric_cells(out, attack.time.estimated_quantum_attack_seconds);
        out << ',' << csv_field(attack.time.estimated_quantum_attack_basis);
        append_metric_cells(out, attack.time.classical_attack_runtime_ms);
        append_metric_cells(out, attack.time.classical_attack_work);
        out << ',' << csv_field(attack.time.classical_attack_description);

        const ComputeResources& compute = attack.compute;
        out << ',' << csv_field(compute.backend_requested) << ',' << csv_field(compute.backend_used);
        append_metric_cells(out, compute.cpu_threads);
        append_metric_cells(out, compute.state_vector_bytes);
        append_metric_cells(out, compute.working_memory_bytes);
        append_metric_cells(out, compute.process_peak_memory_bytes);
        out << ',' << yes_no(compute.gpu_requested) << ',' << yes_no(compute.gpu_executed) << ','
            << csv_field(compute.gpu_status) << ',' << csv_field(compute.gpu_device.empty() ? "N/A" : compute.gpu_device);
        append_metric_cells(out, compute.gpu_operations);
        append_metric_cells(out, compute.gpu_kernel_ms);
        append_metric_cells(out, compute.gpu_transfer_ms);
        append_metric_cells(out, compute.cpu_fallback_operations);
        out << ',' << csv_field(attack.execution_note);
        return out.str();
    }

    std::string metrics_csv(const std::vector<SetAttackReport>& reports)
    {
        std::ostringstream out;
        out << metrics_csv_header() << '\n';
        for (const SetAttackReport& report : reports)
            for (const AttackResult& attack : report.attacks) out << metrics_csv_row(report, attack) << '\n';
        return out.str();
    }

    std::string metrics_json(const std::vector<SetAttackReport>& reports)
    {
        std::ostringstream out;
        out << "{\n  \"schema\": \"CryptoProject educational quantum attack metrics\",\n"
            << "  \"reading_guide\": " << json_string(
                   "value is null when kind is NOT MODELED, NOT EXECUTED, N/A or UNKNOWN; null never means zero. "
                   "time_a is measured classical simulation time, time_b is a scenario estimate for hypothetical "
                   "quantum hardware, time_c is the measured runtime of the existing classical attack.")
            << ",\n  \"sets\": [\n";
        for (std::size_t set_index = 0U; set_index < reports.size(); ++set_index)
        {
            const SetAttackReport& report = reports[set_index];
            out << "    {\"name\": " << json_string(report.name)
                << ", \"composition\": " << json_string(report.composition)
                << ", \"status\": " << json_string(std::string(set_status_label(report.status)))
                << ", \"analysis_wall_ms\": " << std::setprecision(12) << report.wall_ms
                << ", \"instance\": ";
            append_json_named_values(out, report.instance);
            out << ",\n     \"attacks\": [\n";
            for (std::size_t attack_index = 0U; attack_index < report.attacks.size(); ++attack_index)
            {
                const AttackResult& attack = report.attacks[attack_index];
                out << "       {\"id\": " << json_string(attack.id)
                    << ", \"target\": " << json_string(attack.target)
                    << ", \"mathematical_problem\": " << json_string(attack.mathematical_problem)
                    << ", \"algorithm_family\": " << json_string(attack.algorithm_family)
                    << ", \"algorithm\": " << json_string(attack.algorithm)
                    << ", \"applicability\": " << json_string(attack.applicability)
                    << ", \"parameters\": ";
                append_json_named_values(out, attack.parameters);
                out << ", \"execution_status\": " << json_string(std::string(execution_status_label(attack.execution)))
                    << ", \"circuit_implemented\": " << (attack.circuit_implemented ? "true" : "false")
                    << ", \"simulator_executed\": " << (attack.simulator_executed ? "true" : "false")
                    << ", \"execution_note\": " << json_string(attack.execution_note)
                    << ", \"attack_outcome\": " << json_string(std::string(attack_outcome_label(attack.outcome)))
                    << ", \"verified_against_public_instance\": "
                    << (attack.verified_against_public_instance ? "true" : "false")
                    << ", \"matches_ground_truth\": "
                    << (attack.matches_ground_truth.has_value() ? (*attack.matches_ground_truth ? "true" : "false") : "null")
                    << ", \"recovered\": ";
                append_json_named_values(out, attack.recovered);
                out << ", \"simulated_circuit\": ";
                append_json_resources(out, attack.simulated);
                out << ", \"logical_model\": ";
                append_json_resources(out, attack.logical_model);
                out << ", \"time\": {";
                append_json_metric(out, "a_simulator_runtime_ms", attack.time.simulator_runtime_ms);
                append_json_metric(out, "a_simulator_setup_ms", attack.time.simulator_setup_ms);
                append_json_metric(out, "a_simulator_cpu_time_ms", attack.time.simulator_cpu_time_ms);
                append_json_metric(out, "b_estimated_quantum_attack_seconds", attack.time.estimated_quantum_attack_seconds);
                out << "\"b_basis\": " << json_string(attack.time.estimated_quantum_attack_basis) << ", ";
                append_json_metric(out, "c_classical_attack_runtime_ms", attack.time.classical_attack_runtime_ms);
                append_json_metric(out, "c_classical_attack_work_units", attack.time.classical_attack_work);
                out << "\"c_method\": " << json_string(attack.time.classical_attack_description) << "}";
                const ComputeResources& compute = attack.compute;
                out << ", \"compute\": {\"backend_requested\": " << json_string(compute.backend_requested)
                    << ", \"backend_used\": " << json_string(compute.backend_used) << ", ";
                append_json_metric(out, "cpu_threads", compute.cpu_threads);
                append_json_metric(out, "state_vector_bytes", compute.state_vector_bytes);
                append_json_metric(out, "working_memory_bytes", compute.working_memory_bytes);
                append_json_metric(out, "process_peak_memory_bytes", compute.process_peak_memory_bytes);
                out << "\"gpu_requested\": " << (compute.gpu_requested ? "true" : "false")
                    << ", \"gpu_executed\": " << (compute.gpu_executed ? "true" : "false")
                    << ", \"gpu_status\": " << json_string(compute.gpu_status)
                    << ", \"gpu_device\": " << json_string(compute.gpu_device) << ", ";
                append_json_metric(out, "gpu_operations", compute.gpu_operations);
                append_json_metric(out, "gpu_kernel_ms", compute.gpu_kernel_ms);
                append_json_metric(out, "gpu_transfer_ms", compute.gpu_transfer_ms);
                append_json_metric(out, "cpu_fallback_operations", compute.cpu_fallback_operations, false);
                out << "}, \"assumptions\": ";
                append_json_strings(out, attack.assumptions);
                out << ", \"limitations\": ";
                append_json_strings(out, attack.limitations);
                out << ", \"notes\": ";
                append_json_strings(out, attack.notes);
                out << '}' << (attack_index + 1U < report.attacks.size() ? "," : "") << '\n';
            }
            out << "     ]}" << (set_index + 1U < reports.size() ? "," : "") << '\n';
        }
        out << "  ]\n}\n";
        return out.str();
    }

    bool export_quantum_attack_reports(
        const std::vector<SetAttackReport>& reports,
        const std::string& directory,
        ExportedFiles& files)
    {
        try
        {
            std::filesystem::create_directories(directory);
            const auto abs = [](const std::string& path)
            {
                try { return std::filesystem::weakly_canonical(std::filesystem::absolute(path)).string(); }
                catch (const std::exception&) { return path; }
            };
            files = {};
            for (const SetAttackReport& report : reports)
            {
                const std::string path = directory + "/" + std::string(set_file_stem(report.id)) + "_quantum_report.txt";
                std::ofstream output(path, std::ios::out | std::ios::trunc);
                if (!output) return false;
                output << format_set_report(report);
                if (!output) return false;
                files.set_reports.push_back(abs(path));
            }
            files.metrics_csv = abs(directory + "/quantum_attack_metrics.csv");
            {
                std::ofstream output(files.metrics_csv, std::ios::out | std::ios::trunc);
                if (!output) return false;
                output << metrics_csv(reports);
                if (!output) return false;
            }
            files.metrics_json = abs(directory + "/quantum_attack_metrics.json");
            {
                std::ofstream output(files.metrics_json, std::ios::out | std::ios::trunc);
                if (!output) return false;
                output << metrics_json(reports);
                if (!output) return false;
            }
            return true;
        }
        catch (const std::exception&)
        {
            return false;
        }
    }
}
