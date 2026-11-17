#include "ToyPublicKeyAnalysis.h"

#include "AttackCommon.h"
#include "EducationalQuantumAttack/Engine/ResourceModel.h"
#include "QuantumAttack/Standard/Algorithms/QuantumAlgorithms.h"
#include "QuantumAttack/Standard/Models/QuantumResourceModel.h"

#include <exception>
#include <sstream>

namespace crypto::educational_quantum_attack
{
    namespace
    {
        // Fills the sections that describe a circuit which was never run.
        void write_not_executed_sections(
            AttackResult& report,
            const std::string& reason,
            const std::size_t illustrated_register_qubits,
            const QuantumAttackConfig& config)
        {
            mark_not_executed(report, reason);
            report.circuit_implemented = false;

            const ResolvedBackend backend = resolve_backend(config.execution);
            const SimulationFeasibility feasibility = check_simulation_budget(
                illustrated_register_qubits, ControlledPermutationWorkingMemoryFactor, config.budget);
            fill_compute_resources(report.compute, backend, quantum::QuantumBackendStatistics{}, feasibility, false);
            report.compute.state_vector_bytes.note =
                "state vector a textbook-register simulation would need (" +
                std::to_string(illustrated_register_qubits) + " qubits); nothing was allocated";
            if (report.compute.working_memory_bytes.has_value())
                report.compute.working_memory_bytes.note = "would-be working set; nothing was allocated";

            std::ostringstream note;
            note << "Existing QuantumResourceModel register illustration: " << illustrated_register_qubits
                 << " register qubits. " << feasibility.reason
                 << " This is a register-size illustration only; it is not a circuit and was not simulated.";
            report.notes.push_back(note.str());
        }

        void disable_classical_baseline(AttackResult& report)
        {
            report.time.classical_attack_runtime_ms = Metric::not_executed("classical baseline disabled");
            report.time.classical_attack_work = Metric::not_executed("classical baseline disabled");
            report.time.classical_attack_description = "Classical baseline disabled in the configuration.";
        }
    }

    // =====================================================================================
    // Toy ECC: Shor (ECDLP) - correspondence and resource model only
    // =====================================================================================

    AttackResult analyze_toy_ecc_shor_theory(
        const educational::ToyEccPublicInstance& instance,
        const QuantumAttackConfig& config)
    {
        AttackResult report;
        report.kind = AttackKind::EccDiscreteLog;
        report.id = "toy_ecc_shor_ecdlp";
        report.algorithm_family = "Shor (ECDLP)";
        report.algorithm =
            "Shor's algorithm for the elliptic-curve discrete logarithm - resource model only; "
            "the circuit is NOT IMPLEMENTED in this release";
        report.mathematical_problem =
            "Elliptic-curve discrete logarithm: given the base point G and the public point Q on the "
            "toy curve, find the scalar k with Q = k*G.";
        report.applicability =
            "Shor's algorithm applies in principle to the elliptic-curve discrete logarithm. This "
            "release does not implement that circuit. The existing QuantumAttack toy Shor experiment "
            "performs integer order finding for factoring N <= 15; it is not an elliptic-curve circuit "
            "and is therefore NOT reported as an attack on this curve.";

        const educational::ToyEccCurveParameters curve = educational::toy_ecc_curve_parameters();
        const std::size_t field_bits = bit_length(curve.field_prime);
        const educational::ToyEccPoint public_point{instance.public_x, instance.public_y, false};
        const bool on_curve = educational::toy_ecc_is_on_curve(public_point);

        report.target = "Toy ECC: curve over F_" + std::to_string(curve.field_prime) +
                        " with a base point of order " + std::to_string(curve.base_point_order);
        report.parameters.emplace_back(
            "Curve", "y^2 = x^3 + " + std::to_string(curve.coefficient_a) + "x + " +
            std::to_string(curve.coefficient_b) + " over F_" + std::to_string(curve.field_prime));
        report.parameters.emplace_back("Field size", std::to_string(field_bits) + " bits");
        report.parameters.emplace_back(
            "Base point G", "(" + std::to_string(curve.base_x) + ", " + std::to_string(curve.base_y) + ")");
        report.parameters.emplace_back("Order of G", std::to_string(curve.base_point_order));
        report.parameters.emplace_back(
            "Public point Q", "(" + std::to_string(instance.public_x) + ", " +
            std::to_string(instance.public_y) + ")" + (on_curve ? "" : "  [NOT on the curve]"));
        report.parameters.emplace_back("Unknown", "private scalar k in [1, order - 1]");

        report.assumptions.push_back(scenario_assumption_text(config.scenario));
        report.limitations.push_back(
            "No quantum circuit was executed and no private scalar was recovered by a quantum method.");
        report.limitations.push_back(
            "The resource figures come from formulas derived for cryptographic field sizes; at a 7-bit "
            "field they are an extrapolation that only indicates the order of magnitude.");

        const ShorEcdlpModel model = shor_ecdlp_model(field_bits);
        write_not_executed_sections(
            report,
            "No elliptic-curve discrete-logarithm circuit is implemented in this release, so nothing was "
            "executed on the simulator.",
            static_cast<std::size_t>(model.textbook_register_qubits), config);
        write_shor_ecdlp_logical_model(report.logical_model, model);
        write_shor_ecdlp_time_estimate(report.time, model, config.scenario);

        if (!on_curve)
        {
            report.notes.push_back("The supplied public point is not on the toy curve; the instance is invalid.");
        }

        // C. Classical attack runtime: the existing scalar scan on the same public point.
        if (config.run_classical_baselines)
        {
            const Stopwatch classical_timer;
            const educational::ToyEccAnalysis classical = educational::analyze_toy_ecc(instance);
            report.time.classical_attack_runtime_ms = Metric::measured(
                static_cast<long double>(classical_timer.elapsed_ms()), "wall time on this CPU, single thread");
            report.time.classical_attack_work = Metric::measured(
                static_cast<long double>(classical.attempts), "candidate scalars tested");
            report.time.classical_attack_description =
                std::string("Existing educational::analyze_toy_ecc on the same public point: sequential scan "
                            "of the scalars (status ") + classical.status + ").";
        }
        else
        {
            disable_classical_baseline(report);
        }

        if (config.include_reference_scenarios)
        {
            const ShorEcdlpModel reference_model = shor_ecdlp_model(256U);
            ReferenceScenario& reference = report.reference;
            reference.included = true;
            reference.title = "NIST P-256 discrete logarithm (theory only; NOT simulated; NOT the toy curve above)";
            reference.lines.emplace_back("Field size", "256 bits");
            reference.lines.emplace_back(
                "Logical qubits (9n + 2*ceil(log2 n) + 10)", std::to_string(reference_model.total_qubits));
            reference.lines.emplace_back(
                "Toffoli gates (448*n^3*log2 n + 4090*n^3)", format_number(reference_model.toffoli_estimate));
            reference.lines.emplace_back(
                "Scenario time at the assumed serial Toffoli rate",
                format_seconds(reference_model.toffoli_estimate * config.scenario.seconds_per_toffoli_gate));
            reference.disclaimer =
                "Formula values from Roetteler, Naehrig, Svore and Lauter (2017), as already used by "
                "CryptoSetAnalysis. Not a fault-tolerant hardware forecast and not an attack result.";
        }
        return report;
    }

    // =====================================================================================
    // Toy RSA: Shor (factoring) - correspondence and resource model only
    // =====================================================================================

    AttackResult analyze_toy_rsa_shor_theory(
        const educational::ToyRsaPublicInstance& instance,
        const QuantumAttackConfig& config)
    {
        AttackResult report;
        report.kind = AttackKind::RsaFactoring;
        report.id = "toy_rsa_shor_factoring";
        report.algorithm_family = "Shor (factoring)";
        report.algorithm =
            "Shor's algorithm for integer factoring (order finding) - resource model only; a circuit "
            "for this modulus is NOT IMPLEMENTED in this release";
        report.mathematical_problem =
            "Integer factoring: given the public RSA modulus N, find its prime factors p and q.";
        report.applicability =
            "Shor's algorithm applies in principle to factoring the RSA modulus. This release does not "
            "implement a Shor circuit for a modulus of this size. The existing QuantumAttack toy Shor "
            "experiment is restricted to odd composite N <= 15 and is run below only as a separate "
            "algorithm-validation experiment; its success says nothing about this modulus.";

        const std::size_t modulus_bits = bit_length(instance.modulus);
        report.target = "Toy RSA: " + std::to_string(modulus_bits) + "-bit public modulus";
        report.parameters.emplace_back("Public modulus N", std::to_string(instance.modulus));
        report.parameters.emplace_back("Modulus size", std::to_string(modulus_bits) + " bits");
        report.parameters.emplace_back("Public exponent e", std::to_string(instance.public_exponent));
        report.parameters.emplace_back("Ciphertext c", std::to_string(instance.ciphertext));
        report.parameters.emplace_back(
            "Recovery target", "the prime factors p and q of N (and from them the private exponent)");

        report.assumptions.push_back(scenario_assumption_text(config.scenario));
        report.limitations.push_back(
            "No quantum circuit was executed for this modulus and no factor was recovered by a quantum method.");
        report.limitations.push_back(
            "The Toffoli-count formula describes cryptographic modulus sizes; at a toy size it is an "
            "extrapolation that only indicates the order of magnitude.");

        const ShorFactoringModel model = shor_factoring_model(modulus_bits);
        write_not_executed_sections(
            report,
            "No Shor circuit for a modulus of this size is implemented in this release (the existing toy "
            "experiment accepts only N <= 15), so nothing was executed on the simulator for this modulus.",
            static_cast<std::size_t>(model.textbook_register_qubits), config);
        write_shor_factoring_logical_model(report.logical_model, model);
        write_shor_factoring_time_estimate(report.time, model, config.scenario);

        // Separate algorithm-validation experiment: the EXISTING toy Shor run on N = 15.
        if (config.run_validation_experiments)
        {
            ValidationExperiment& validation = report.validation;
            validation.included = true;
            validation.title = "Existing toy Shor experiment on the fixed number N = 15 (algorithm validation only)";
            validation.description =
                "QuantumAttack run_shor_toy_experiment(15, 2): order finding on a small state vector.";
            validation.disclaimer =
                "This experiment factors the fixed number 15. It does not use the toy RSA modulus N = " +
                std::to_string(instance.modulus) + " and is NOT an attack on it.";
            try
            {
                const ResolvedBackend backend = resolve_backend(config.execution);
                const quantum::ShorToyResult toy =
                    quantum::run_shor_toy_experiment(15U, 2U, 1024U, backend.options);
                validation.passed = toy.factored && toy.factor_a * toy.factor_b == 15U;
                validation.status = toy.status;
                validation.simulator_runtime_ms = Metric::measured(
                    static_cast<long double>(toy.elapsed_ms), "classical simulation wall time, N = 15 only");
                validation.qubits = Metric::measured(
                    static_cast<long double>(toy.qubits), "simulated qubits, N = 15 only");
            }
            catch (const std::exception& exception)
            {
                validation.passed = false;
                validation.status = std::string("ERROR: ") + exception.what();
            }
        }

        // C. Classical attack runtime: the existing trial-division attack on the same modulus.
        if (config.run_classical_baselines)
        {
            const Stopwatch classical_timer;
            const educational::ToyRsaAnalysis classical = educational::analyze_toy_rsa(instance);
            report.time.classical_attack_runtime_ms = Metric::measured(
                static_cast<long double>(classical_timer.elapsed_ms()), "wall time on this CPU, single thread");
            report.time.classical_attack_work = Metric::measured(
                static_cast<long double>(classical.trial_divisions), "trial divisions");
            report.time.classical_attack_description =
                std::string("Existing educational::analyze_toy_rsa on the same modulus: trial division, then "
                            "private-exponent and plaintext recovery (status ") + classical.status + ").";
        }
        else
        {
            disable_classical_baseline(report);
        }

        if (config.include_reference_scenarios)
        {
            const ShorFactoringModel reference_model = shor_factoring_model(2048U);
            ReferenceScenario& reference = report.reference;
            reference.included = true;
            reference.title = "RSA-2048 factoring (theory only; NOT simulated; NOT the toy modulus above)";
            reference.lines.emplace_back("Modulus size", "2048 bits");
            reference.lines.emplace_back(
                "Logical qubits (2n + 3)", std::to_string(reference_model.one_control_circuit_qubits));
            reference.lines.emplace_back(
                "Toffoli gates ((64*(log2 n - 2) + 29.46) * n^3)", format_number(reference_model.toffoli_estimate));
            reference.lines.emplace_back(
                "Scenario time at the assumed serial Toffoli rate",
                format_seconds(reference_model.toffoli_estimate * config.scenario.seconds_per_toffoli_gate));
            reference.disclaimer =
                "Formula values as already used by CryptoSetAnalysis. Not a fault-tolerant hardware "
                "forecast and not an attack result.";
        }
        return report;
    }

    // =====================================================================================
    // Toy Module-LWE: NOT MODELED
    // =====================================================================================

    AttackResult analyze_toy_module_lwe_not_modeled(
        const educational::ToyLwePublicInstance& instance,
        const QuantumAttackConfig& config)
    {
        AttackResult report;
        report.kind = AttackKind::ModuleLweSecretSearch;
        report.id = "toy_module_lwe_not_modeled";
        report.algorithm_family = "NOT MODELED";
        report.algorithm = "NOT MODELED (no circuit-level quantum attack model is implemented)";
        report.mathematical_problem =
            "Module-LWE: given the public matrix A and the vector b = A*s + e over R_q, find the small "
            "secret vector s.";
        report.applicability =
            "Shor's algorithm does NOT apply: Module-LWE is not an integer-factoring or discrete-logarithm "
            "problem. This project implements no circuit-level quantum attack model for Module-LWE, "
            "neither for these toy parameters nor for ML-KEM-768, so it reports no qubit count, gate "
            "count, circuit depth or attack time for it.";
        report.target = "Toy Module-LWE: n = " + std::to_string(educational::ToyModuleDegree) +
                        ", k = " + std::to_string(educational::ToyModuleRank) +
                        ", q = " + std::to_string(educational::ToyModuleQ);
        report.parameters.emplace_back("Ring", "R_q = Z_q[x] / (x^n + 1)");
        report.parameters.emplace_back("Polynomial degree n", std::to_string(educational::ToyModuleDegree));
        report.parameters.emplace_back("Module rank k", std::to_string(educational::ToyModuleRank));
        report.parameters.emplace_back("Modulus q", std::to_string(educational::ToyModuleQ));
        report.parameters.emplace_back("Secret and error coefficients", "{-1, 0, 1}");
        report.parameters.emplace_back(
            "Secret candidate space", "3^(n*k) = " + std::to_string(educational::ToyModuleSecretCandidateCount));

        report.execution = ExecutionStatus::NotModeled;
        report.circuit_implemented = false;
        report.simulator_executed = false;
        report.execution_note = "No quantum attack circuit or resource model exists for this component.";
        report.outcome = AttackOutcome::NotAttempted;

        const std::string reason = "no circuit-level model";
        for (CircuitResources* resources : {&report.simulated, &report.logical_model})
        {
            resources->scope = "NOT MODELED: this project has no circuit-level quantum attack model for Module-LWE.";
            resources->logical_qubits = Metric::not_modeled(reason);
            resources->ancilla_qubits = Metric::not_modeled(reason);
            resources->total_qubits = Metric::not_modeled(reason);
            resources->gate_count = Metric::not_modeled(reason);
            resources->circuit_depth = Metric::not_modeled(reason);
            resources->oracle_calls = Metric::not_modeled(reason);
            resources->quantum_memory_bits = Metric::not_modeled(reason);
            resources->oracle_cost = "NOT MODELED";
        }
        report.time.simulator_runtime_ms = Metric::not_modeled("no circuit to simulate");
        report.time.simulator_setup_ms = Metric::not_modeled("no circuit to simulate");
        report.time.simulator_cpu_time_ms = Metric::not_modeled("no circuit to simulate");
        report.time.estimated_quantum_attack_seconds = Metric::not_modeled("no attack model");
        report.time.estimated_quantum_attack_basis = "NOT MODELED";

        report.compute.backend_requested = backend_label(config.execution.backend);
        report.compute.backend_used = "NONE (nothing was simulated)";
        report.compute.cpu_threads = Metric::not_modeled("nothing was simulated");
        report.compute.state_vector_bytes = Metric::not_modeled("nothing was simulated");
        report.compute.working_memory_bytes = Metric::not_modeled("nothing was simulated");
        report.compute.process_peak_memory_bytes = Metric::not_modeled("nothing was simulated");
        report.compute.gpu_requested = false;
        report.compute.gpu_executed = false;
        report.compute.gpu_status = "NOT USED (nothing was simulated)";
        report.compute.gpu_operations = Metric::not_modeled("nothing was simulated");
        report.compute.gpu_kernel_ms = Metric::not_modeled("nothing was simulated");
        report.compute.gpu_transfer_ms = Metric::not_modeled("nothing was simulated");
        report.compute.cpu_fallback_operations = Metric::not_modeled("nothing was simulated");

        report.limitations.push_back(
            "No quantum figure of any kind is given for this component; an absent figure must not be read as zero.");
        report.limitations.push_back(
            "The AES and SHA results of this set concern only its symmetric and hash components and are "
            "not a quantum attack on the Module-LWE component.");

        // C. Classical attack runtime: the existing exhaustive secret search on the same instance.
        if (config.run_classical_baselines)
        {
            const Stopwatch classical_timer;
            const educational::ToyLweAnalysis classical = educational::analyze_toy_lwe(instance);
            report.time.classical_attack_runtime_ms = Metric::measured(
                static_cast<long double>(classical_timer.elapsed_ms()), "wall time on this CPU, single thread");
            report.time.classical_attack_work = Metric::measured(
                static_cast<long double>(classical.candidates_tested), "candidate secret vectors tested");
            report.time.classical_attack_description =
                std::string("Existing educational::analyze_toy_lwe on the same instance: exhaustive scan of "
                            "the small-secret candidates (status ") + classical.status + ").";
        }
        else
        {
            disable_classical_baseline(report);
        }

        if (config.include_reference_scenarios)
        {
            ReferenceScenario& reference = report.reference;
            reference.included = true;
            reference.title = "ML-KEM-768 (NOT MODELED)";
            reference.lines.emplace_back("Shor's algorithm", "not applicable to Module-LWE");
            reference.lines.emplace_back("Quantum attack cost", "NOT MODELED by this project");
            reference.disclaimer = "No figure is given, by design.";
        }
        return report;
    }
}
