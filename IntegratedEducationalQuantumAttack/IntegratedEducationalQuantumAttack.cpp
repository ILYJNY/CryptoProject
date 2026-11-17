#include "IntegratedEducationalQuantumAttack.h"

#include "EducationalQuantumAttack/Common/QuantumAttackReport.h"
#include "EducationalQuantumAttack/Common/QuantumAttackSupport.h"
#include "EducationalQuantumAttack/EducationalQuantumAttack.h"

#include <iomanip>
#include <sstream>

namespace crypto::integrated_educational_quantum_attack
{
    namespace
    {
        constexpr const char* kDoubleRule =
            "================================================================================";

        void write_list(std::ostringstream& out, const std::vector<std::string>& items, const char* when_empty)
        {
            if (items.empty())
            {
                out << "  " << when_empty << '\n';
                return;
            }
            for (const std::string& item : items) out << "  - " << item << '\n';
        }
    }

    IntegratedResult integrate(std::vector<eqa::SetAttackReport> sets, const double wall_ms)
    {
        IntegratedResult result;
        result.sets = std::move(sets);
        result.wall_ms = wall_ms;
        result.comparison = compare_quantum_attacks(result.sets);

        // Failure propagation: one failed set makes the integrated result FAILED.
        bool all_succeeded = !result.sets.empty();
        for (const eqa::SetAttackReport& set : result.sets)
        {
            if (set.status == eqa::SetStatus::Failed) result.any_failure = true;
            if (set.status != eqa::SetStatus::AllSucceeded) all_succeeded = false;
        }
        // A set report whose status was not kept in sync is still caught by the counters.
        if (result.comparison.attacks_failed != 0U) result.any_failure = true;
        result.status = result.any_failure
            ? eqa::SetStatus::Failed
            : (all_succeeded ? eqa::SetStatus::AllSucceeded : eqa::SetStatus::Partial);

        result.report = format_integrated_report(result);
        return result;
    }

    IntegratedResult run(const std::string& plaintext, const eqa::QuantumAttackConfig& config)
    {
        const eqa::Stopwatch stopwatch;
        std::vector<eqa::SetAttackReport> sets = eqa::run_all_quantum_attacks(plaintext, config);
        return integrate(std::move(sets), stopwatch.elapsed_ms());
    }

    std::string format_integrated_report(const IntegratedResult& result)
    {
        const Comparison& comparison = result.comparison;
        std::ostringstream out;
        out << kDoubleRule << '\n'
            << "INTEGRATED EDUCATIONAL QUANTUM ATTACK ANALYSIS\n"
            << kDoubleRule << '\n'
            << "The three educational sets were analyzed independently, each on its own instance. They are NOT\n"
               "merged into one cryptosystem. This report only gathers and compares their quantum-attack results.\n\n"
            << "Overall status : " << eqa::set_status_label(result.status) << '\n';
        for (const eqa::SetAttackReport& set : result.sets)
            out << "  " << std::left << std::setw(38) << set.name << eqa::set_status_label(set.status) << '\n';
        out << "Attacks        : " << comparison.attacks_total << " in total; "
            << comparison.attacks_executed << " executed on the simulator; "
            << comparison.attacks_succeeded << " succeeded; "
            << comparison.attacks_failed << " failed; "
            << comparison.attacks_theory_only << " theory only (not executed); "
            << comparison.attacks_not_modeled << " NOT MODELED\n"
            << "Integrated analysis wall time (everything, classical): " << std::fixed << std::setprecision(3)
            << result.wall_ms << " ms\n\n";
        out.unsetf(std::ios::floatfield);

        out << "[1] COMPARISON OF THE ATTACK MODELS\n" << format_comparison_table(comparison) << '\n';

        out << "[2] COMPUTER RESOURCES OF THE CLASSICAL SIMULATIONS (CPU / GPU / MEMORY)\n"
            << format_resource_usage_table(comparison) << '\n';

        out << "[3] AGGREGATED MEASUREMENTS\n"
            << "  A. Total quantum simulator runtime (classical simulation, measured): "
            << eqa::format_metric(comparison.total_simulator_runtime_ms, "ms") << '\n'
            << "     Total simulation-only setup                                     : "
            << eqa::format_metric(comparison.total_simulator_setup_ms, "ms") << '\n'
            << "  B. Total estimated quantum attack time                             : NOT SUMMED\n"
            << "     The estimates of different attack models rest on different assumptions and leave out\n"
            << "     different costs; adding them would not give a time to break any of the three sets.\n"
            << "  C. Total classical attack runtime (existing classical attacks, measured): "
            << eqa::format_metric(comparison.total_classical_runtime_ms, "ms") << "\n\n";

        out << "[4] HIGHLIGHTS\n"
            << format_highlight(comparison.fewest_model_qubits)
            << format_highlight(comparison.shallowest_model_depth)
            << format_highlight(comparison.fastest_simulation)
            << format_highlight(comparison.fewest_simulated_qubits) << '\n';

        out << "[5] APPLICABILITY OF EACH ATTACK MODEL\n";
        write_list(out, comparison.applicability, "none");
        out << '\n';

        out << "[6] NOT EXECUTED AND NOT MODELED ITEMS (no value exists for these; they are not zero)\n";
        write_list(out, comparison.not_modeled_items, "none: every quantity of every attack has a value");
        out << '\n';

        out << "[7] ASSUMPTIONS BEHIND THE ESTIMATES\n";
        write_list(out, comparison.assumptions, "none");
        out << '\n';

        out << "[8] LIMITS OF INTERPRETATION\n"
            << "  - Simulator runtime is the time a classical computer needs to simulate a circuit. It is not the\n"
            << "    time a quantum computer would need, and it grows exponentially with the number of qubits.\n"
            << "  - Estimated quantum attack time is a scenario figure under the stated assumptions, on error-free\n"
            << "    logical qubits. Error correction and physical qubits are excluded everywhere.\n"
            << "  - The attack models differ in what they include: Grover-type models leave out the oracle circuit,\n"
            << "    Shor models are formula extrapolations, and Module-LWE has no model at all. Their numbers\n"
            << "    cannot be ranked into a meaningful order of 'which system falls first'.\n"
            << "  - No figure in this report is a time to break a complete cryptosystem, toy or real.\n"
            << "  - A success against a deliberately tiny toy parameter says nothing about AES-128, SHA-256,\n"
            << "    P-256, RSA-2048 or ML-KEM-768.\n\n";

        out << "[9] INDIVIDUAL SET REPORTS\n\n";
        for (const eqa::SetAttackReport& set : result.sets) out << eqa::format_set_report(set) << '\n';
        return out.str();
    }
}
