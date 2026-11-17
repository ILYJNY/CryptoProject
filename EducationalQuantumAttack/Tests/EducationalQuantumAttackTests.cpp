// Tests for the independent educational quantum-attack analysis (CryptoProject 2.3.5).
//
// Individual analyses covered here:
//   - Toy AES Grover analysis
//   - Toy SHA preimage analysis (Grover)
//   - Toy SHA collision analysis (BHT, never plain Grover)
//   - Toy ECC Shor analysis: explicit "circuit not implemented" handling
//   - Toy RSA Shor analysis: explicit "circuit not implemented" handling, with the N = 15
//     experiment kept as a separate validation run
//   - Toy Module-LWE: NOT MODELED handling, and never Shor
// plus the engines, the provenance rules (an absent value is never 0), the three separate
// time categories, GPU honesty, the three independent sets and the file exports.

#include "EducationalQuantumAttack/Attacks/ToyAesGroverAttack.h"
#include "EducationalQuantumAttack/Attacks/ToyModuleLweGroverAttack.h"
#include "EducationalQuantumAttack/Attacks/ToyPublicKeyAnalysis.h"
#include "EducationalQuantumAttack/Attacks/ToyShaQuantumAttack.h"
#include "EducationalQuantumAttack/Common/QuantumAttackSupport.h"
#include "EducationalQuantumAttack/EducateAnalysis.h"
#include "EducationalQuantumAttack/EducationalQuantumAttack.h"
#include "EducationalQuantumAttack/Engine/GroverEngine.h"
#include "EducationalQuantumAttack/Engine/PhaseEstimationEngine.h"
#include "EducationalQuantumAttack/Engine/ResourceModel.h"
#include "EducationalQuantumAttack/Engine/ShorEcdlp.h"
#include "EducationalQuantumAttack/Engine/ShorFactoring.h"
#include "EducationalQuantumAttack/Sets/SetCommon.h"

#include "CryptoSystem/Educational/ECC/ToyECC.h"
#include "CryptoSystem/Educational/EducationalParameters.h"
#include "CryptoSystem/Educational/ModuleLWE/ToyModuleLWE.h"
#include "CryptoSystem/Educational/RSA/ToyRSA.h"
#include "CryptoSystem/Educational/SHA/ToySha256.h"
#include "QuantumAttack/Backend/CUDA/CUDAQuantumBackend.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
    using namespace crypto::educational_quantum_attack;
    namespace educational = crypto::educational;

    void require(const bool condition, const std::string& message)
    {
        if (!condition) throw std::runtime_error(message);
    }

    [[nodiscard]] bool contains(const std::string& text, const std::string& part)
    {
        return text.find(part) != std::string::npos;
    }

    [[nodiscard]] QuantumAttackConfig test_config(const std::uint64_t seed)
    {
        QuantumAttackConfig config;
        config.seed = seed;
        config.execution.backend = crypto::quantum::QuantumBackendType::CpuMultiThread;
        config.execution.cpu_threads = 2U;
        return config;
    }

    // Splits one CSV record into fields, honoring quoted fields.
    [[nodiscard]] std::vector<std::string> split_csv(const std::string& line)
    {
        std::vector<std::string> fields;
        std::string current;
        bool quoted = false;
        for (std::size_t index = 0U; index < line.size(); ++index)
        {
            const char character = line[index];
            if (quoted)
            {
                if (character == '"' && index + 1U < line.size() && line[index + 1U] == '"')
                {
                    current += '"';
                    ++index;
                }
                else if (character == '"') quoted = false;
                else current += character;
            }
            else if (character == '"') quoted = true;
            else if (character == ',')
            {
                fields.push_back(current);
                current.clear();
            }
            else current += character;
        }
        fields.push_back(current);
        return fields;
    }

    [[nodiscard]] std::string read_file(const std::string& path)
    {
        std::ifstream input(path);
        std::ostringstream buffer;
        buffer << input.rdbuf();
        return buffer.str();
    }

    // ---------------------------------------------------------------------------------
    // Provenance rules and helpers
    // ---------------------------------------------------------------------------------
    void test_metric_rules()
    {
        require(format_metric(Metric::not_modeled()) == "NOT MODELED", "NOT MODELED must be printed as text.");
        require(metric_cell(Metric::not_executed()) == "NOT EXECUTED", "NOT EXECUTED must be a CSV text cell.");
        require(metric_cell(Metric::not_applicable()) == "N/A", "N/A must be a CSV text cell.");
        require(metric_cell(Metric::unknown()) == "UNKNOWN", "UNKNOWN must be a CSV text cell.");
        require(!Metric::not_modeled().has_value(), "An unmodeled metric must not claim to have a value.");
        require(metric_cell(Metric::not_modeled()) != "0", "An absent value must never be written as 0.");
        require(metric_cell(Metric::computed(12.0L)) == "12", "A computed integer must print without decimals.");
        require(contains(format_metric(Metric::measured(3.5L), "ms"), "[measured]"),
                "A measured value must carry its provenance tag.");
        require(contains(format_metric(Metric::estimated(2.0L)), "[estimated]"),
                "An estimated value must carry its provenance tag.");

        const SimulationBudget budget;
        const auto small = check_simulation_budget(12U, GroverWorkingMemoryFactor, budget);
        require(small.feasible && small.state_vector_bytes == 16U * 4096U,
                "A 12-qubit state vector must need exactly 65536 bytes and fit the default budget.");
        const auto large = check_simulation_budget(30U, GroverWorkingMemoryFactor, budget);
        require(!large.feasible && !large.reason.empty(), "A 30-qubit circuit must be refused with a reason.");
        const auto huge = check_simulation_budget(73U, ControlledPermutationWorkingMemoryFactor, budget);
        require(!huge.feasible, "A 73-qubit circuit must be refused.");

        require(ceil_log2(6561U) == 13U && ceil_log2(4096U) == 12U && ceil_log2(1U) == 0U, "ceil_log2 is wrong.");
        require(bit_length(97U) == 7U && bit_length(0U) == 0U, "bit_length is wrong.");
        require(mod_pow(7U, 4U, 15U) == 1U && gcd_u64(48U, 18U) == 6U, "Modular helpers are wrong.");
        require(mod_inverse(3U, 50U).value_or(0U) == 17U && !mod_inverse(10U, 50U).has_value(),
                "mod_inverse is wrong.");
        require(derive_seed(1U, "a") != derive_seed(1U, "b") && derive_seed(1U, "a") == derive_seed(1U, "a"),
                "Seed derivation must be deterministic and label dependent.");
        require(resolve_seed(42U) == 42U && resolve_seed(0U) != 0U, "Seed resolution is wrong.");
    }

    void test_resource_models()
    {
        require(optimal_grover_iterations(4096.0, 1.0) == 50U, "Grover on 2^12 keys needs 50 iterations.");
        require(grover_success_probability(4096.0, 1.0, 50U) > 0.999, "Grover success probability is wrong.");
        require(optimal_grover_iterations(16.0, 0.0) == 0U, "No solutions means no iteration count.");

        // n = 12: 2n - 5 = 19 Toffolis per iteration, n - 3 = 9 ancillas, depth 1 + R*(2n+1).
        const GroverLogicalCost cost = grover_logical_cost(12U, 50U, 1U, 50U);
        require(cost.toffoli_gates == 950U, "Diffusion Toffoli count is wrong.");
        require(cost.diffusion_ancilla_qubits == 9U, "Diffusion ancilla count is wrong.");
        require(cost.pauli_x_gates == 1200U && cost.hadamard_gates == 12U + 50U * 26U, "H/X counts are wrong.");
        require(cost.deepest_run_depth_excluding_oracle == 1251U, "Diffusion depth is wrong.");
        require(cost.oracle_calls == 50U, "Oracle calls must equal the Grover iterations.");

        const ShorFactoringModel rsa = shor_factoring_model(24U);
        require(rsa.one_control_circuit_qubits == 51U && rsa.controlled_modular_multiplications == 48U,
                "Shor factoring qubit model is wrong.");
        require(rsa.toffoli_estimate_available && rsa.toffoli_estimate > 1.0e6L,
                "The existing Toffoli formula must produce a value at 24 bits.");
        require(!shor_factoring_model(4U).toffoli_estimate_available,
                "The Toffoli formula is undefined below 8 bits and must not invent a value.");

        const ShorEcdlpModel ecc = shor_ecdlp_model(7U);
        require(ecc.total_qubits == 9U * 7U + 2U * 3U + 10U, "Shor ECDLP qubit formula is wrong.");
        require(shor_ecdlp_model(256U).total_qubits == 2330U, "P-256 must give the published 2330 logical qubits.");
    }

    void test_backend_resolution()
    {
        crypto::quantum::QuantumExecutionOptions cpu;
        cpu.backend = crypto::quantum::QuantumBackendType::CpuSingleThread;
        const ResolvedBackend resolved_cpu = resolve_backend(cpu);
        require(!resolved_cpu.gpu_requested && resolved_cpu.used == "CPU-SINGLE", "CPU backend resolution is wrong.");

        if (!crypto::quantum::cuda_backend::CUDAQuantumBackend::is_available())
        {
            crypto::quantum::QuantumExecutionOptions gpu;
            gpu.backend = crypto::quantum::QuantumBackendType::CudaGpu;
            const ResolvedBackend resolved = resolve_backend(gpu);
            require(resolved.gpu_requested && !resolved.gpu_available, "An unavailable GPU must be reported as unavailable.");
            require(resolved.used == "CPU-MULTI" && resolved.requested == "CUDA-GPU",
                    "A CPU fallback must be labeled as CPU, not as GPU.");
            require(contains(resolved.gpu_status, "UNAVAILABLE"), "The GPU status must say UNAVAILABLE.");
        }
    }

    // ---------------------------------------------------------------------------------
    // Engines on the existing simulator
    // ---------------------------------------------------------------------------------
    void test_grover_engine()
    {
        GroverSearchRequest request;
        request.search_qubits = 8U;
        request.marked_indices = {173U};
        request.classical_verifier = [](const std::size_t index) { return index == 173U; };
        request.seed = 5U;
        const GroverSearchResult found = run_grover_search(request);
        require(found.found && found.found_index == 173U, "Grover engine did not find the marked state.");
        require(found.planned_iterations == 12U, "Grover on 2^8 states needs 12 iterations.");
        require(found.total_grover_iterations % 12U == 0U && found.qubits == 8U, "Grover engine counters are wrong.");
        require(found.attempts.front().success_probability > 0.99, "Grover amplification is too weak.");

        GroverSearchRequest unknown = request;
        unknown.marked_indices = {3U, 77U, 200U};
        unknown.classical_verifier = [](const std::size_t index) { return index == 3U || index == 77U || index == 200U; };
        unknown.strategy = GroverStrategy::UnknownSolutionCount;
        const GroverSearchResult found_unknown = run_grover_search(unknown);
        require(found_unknown.found, "The unknown-solution-count schedule did not find a marked state.");

        GroverSearchRequest none = request;
        none.marked_indices.clear();
        none.classical_verifier = [](const std::size_t) { return false; };
        const GroverSearchResult not_found = run_grover_search(none);
        require(!not_found.found && !not_found.failure_reason.empty(),
                "A search without solutions must fail with a reason instead of reporting success.");

        bool rejected = false;
        try
        {
            GroverSearchRequest invalid = request;
            invalid.marked_indices = {1000U};
            (void)run_grover_search(invalid);
        }
        catch (const std::invalid_argument&) { rejected = true; }
        require(rejected, "A marked index outside the register must be rejected.");
    }

    void test_phase_estimation_engine()
    {
        // Pure simulator test: the cyclic shift x -> x + s (mod 8) on a 3-qubit register has
        // the eigenphases j*s/8. The first stage projects the register onto one eigenvector;
        // estimating the same shift again must return the same phase, and estimating the
        // doubled shift must return the doubled phase (mod 1).
        const auto shift = [](const std::size_t step)
        {
            return [step](const std::size_t power, std::vector<std::size_t>& permutation)
            {
                const std::size_t amount = (step << power) % permutation.size();
                for (std::size_t value = 0U; value < permutation.size(); ++value)
                    permutation[value] = (value + amount) % permutation.size();
            };
        };
        for (std::uint64_t seed = 1U; seed <= 12U; ++seed)
        {
            PhaseEstimationRequest request;
            request.work_qubits = 3U;
            request.initial_work_state = 0U;
            request.seed = seed;
            request.stages.push_back({"shift by 1", 3U, shift(1U)});
            request.stages.push_back({"shift by 1 again", 3U, shift(1U)});
            request.stages.push_back({"shift by 2", 3U, shift(2U)});
            const PhaseEstimationResult result = run_iterative_phase_estimation(request);
            require(result.phase_integers.size() == 3U, "Phase estimation must return one integer per stage.");
            require(result.phase_integers[0] == result.phase_integers[1],
                    "Repeated phase estimation of the same unitary must return the same phase.");
            require(result.phase_integers[2] == (2U * result.phase_integers[0]) % 8U,
                    "The phase of the squared unitary must be the doubled phase.");
            require(result.qubits == 4U && result.measurements == 9U && result.controlled_permutations == 9U,
                    "Phase estimation operation counters are wrong.");
        }
    }

    // ---------------------------------------------------------------------------------
    // Toy AES: Grover
    // ---------------------------------------------------------------------------------
    void test_toy_aes_grover()
    {
        const QuantumAttackConfig config = test_config(1001U);
        const auto sample = educational::generate_toy_aes_sample(educational::ToySetAesUnknownKeyBits, "Hello");
        const ToyAesGroverAttack attack = attack_toy_aes_with_grover(sample.public_instance, config, 77U);
        const AttackResult& report = attack.report;

        require(report.kind == AttackKind::AesKeySearch && report.algorithm_family == "Grover",
                "Toy AES must be attacked with Grover.");
        require(report.execution == ExecutionStatus::Simulated && report.simulator_executed && report.circuit_implemented,
                "The Toy AES Grover circuit must be executed on the simulator.");
        require(report.outcome == AttackOutcome::Succeeded && report.verified_against_public_instance,
                "The Toy AES Grover attack must succeed and be verified.");
        require(attack.key_recovered && attack.recovered_key == sample.ground_truth.key,
                "The recovered AES key must equal the withheld key.");
        require(attack.recovered_plaintext == "Hello", "The recovered plaintext must equal the message.");

        require(report.simulated.total_qubits.kind == MetricKind::Measured && report.simulated.total_qubits.value == 12.0L,
                "The simulated register must have the real 12 key bits.");
        require(report.simulated.oracle_calls.has_value() && report.simulated.oracle_calls.value >= 50.0L,
                "The oracle-call count must be recorded.");
        require(report.logical_model.total_qubits.kind == MetricKind::Computed &&
                report.logical_model.total_qubits.value == 21.0L,
                "The logical model must report 12 search qubits plus 9 diffusion ancillas.");
        require(contains(report.logical_model.oracle_cost, "NOT MODELED"),
                "The oracle circuit cost must be declared NOT MODELED.");

        // Three separate time categories with three different provenances.
        require(report.time.simulator_runtime_ms.kind == MetricKind::Measured &&
                report.time.simulator_runtime_ms.value > 0.0L, "Simulator runtime (A) must be measured.");
        require(report.time.estimated_quantum_attack_seconds.kind == MetricKind::Estimated,
                "Quantum attack time (B) must be an estimate.");
        require(report.time.classical_attack_runtime_ms.kind == MetricKind::Measured,
                "Classical attack runtime (C) must be measured.");
        require(!report.time.estimated_quantum_attack_basis.empty(), "The estimate must state its basis.");

        // GPU honesty on a CPU run.
        require(!report.compute.gpu_executed && report.compute.gpu_kernel_ms.kind == MetricKind::NotApplicable,
                "A CPU run must not report GPU measurements.");
        require(report.compute.backend_used == "CPU-MULTI", "The used backend must be labeled.");
        require(report.reference.included && contains(report.reference.title, "NOT the toy instance"),
                "The AES-128 reference must be labeled as separate from the toy instance.");

        // A 4-bit key space works too.
        const auto small = educational::generate_toy_aes_sample(4U, "tiny");
        const ToyAesGroverAttack small_attack = attack_toy_aes_with_grover(small.public_instance, config, 78U);
        require(small_attack.key_recovered && small_attack.recovered_key == small.ground_truth.key,
                "Grover on a 4-bit Toy AES key space failed.");

        // A record no key authenticates: the attack must fail, not report success.
        auto tampered = sample.public_instance;
        tampered.ciphertext.tag[0] = static_cast<std::uint8_t>(tampered.ciphertext.tag[0] ^ 0x01U);
        const ToyAesGroverAttack failed = attack_toy_aes_with_grover(tampered, config, 79U);
        require(failed.report.execution == ExecutionStatus::Simulated &&
                failed.report.outcome == AttackOutcome::Failed && !failed.key_recovered,
                "An unbreakable record must be reported as a failed attack.");
        require(!failed.report.verified_against_public_instance, "A failed attack must not claim verification.");

        // Outside the simulation budget: theory only, nothing measured, nothing printed as 0.
        QuantumAttackConfig tight = config;
        tight.budget.max_qubits = 8U;
        const ToyAesGroverAttack skipped = attack_toy_aes_with_grover(sample.public_instance, tight, 80U);
        require(skipped.report.execution == ExecutionStatus::TheoryOnly && !skipped.report.simulator_executed,
                "A circuit outside the budget must not be executed.");
        require(skipped.report.outcome == AttackOutcome::NotAttempted && !skipped.key_recovered,
                "A circuit that was not executed must not be reported as a success.");
        require(skipped.report.time.simulator_runtime_ms.kind == MetricKind::NotExecuted,
                "A circuit that was not executed has no simulator runtime.");
        require(skipped.report.logical_model.total_qubits.has_value(),
                "The logical model must still be available when the circuit is not executed.");
        require(contains(format_attack_report(skipped.report), "NOT EXECUTED"),
                "The report must print NOT EXECUTED.");

        // An invalid instance is an error, not a success.
        auto invalid = sample.public_instance;
        invalid.unknown_bits = 3U;
        const ToyAesGroverAttack rejected = attack_toy_aes_with_grover(invalid, config, 81U);
        require(rejected.report.execution == ExecutionStatus::Error && rejected.report.outcome == AttackOutcome::Failed,
                "An invalid Toy AES instance must be reported as an error.");
    }

    // ---------------------------------------------------------------------------------
    // Toy SHA: preimage (Grover) and collision (BHT) are separate analyses
    // ---------------------------------------------------------------------------------
    void test_toy_sha_preimage()
    {
        const QuantumAttackConfig config = test_config(2002U);
        const std::size_t bits = educational::ToySetShaOutputBits;
        const std::uint32_t target = educational::truncated_sha256("Hello", bits);
        const ToyShaPreimageAttack attack =
            attack_toy_sha_preimage_with_grover(target, bits, "QA test preimage:", config, 91U);
        const AttackResult& report = attack.report;
        require(report.kind == AttackKind::ShaPreimage && report.algorithm_family == "Grover",
                "The preimage search must be a Grover analysis.");
        require(report.execution == ExecutionStatus::Simulated && report.outcome == AttackOutcome::Succeeded,
                "The Toy SHA preimage attack must be executed and succeed.");
        require(attack.preimage_found && educational::truncated_sha256(attack.message, bits) == target,
                "The found message must hash to the target digest.");
        require(report.simulated.total_qubits.value == 18.0L, "The preimage register must have b + 2 qubits.");
        require(contains(report.mathematical_problem, "Preimage"), "The report must name the preimage problem.");
        require(report.time.simulator_runtime_ms.kind == MetricKind::Measured &&
                report.time.estimated_quantum_attack_seconds.kind == MetricKind::Estimated,
                "The preimage report must keep time A and time B apart.");

        // The digest width is configurable.
        const std::uint32_t small_target = educational::truncated_sha256("Hello", 8U);
        const ToyShaPreimageAttack small =
            attack_toy_sha_preimage_with_grover(small_target, 8U, "QA test preimage 8:", config, 92U);
        require(small.preimage_found && educational::truncated_sha256(small.message, 8U) == small_target,
                "The 8-bit preimage search failed.");

        const ToyShaPreimageAttack invalid =
            attack_toy_sha_preimage_with_grover(0U, 3U, "QA test preimage:", config, 93U);
        require(invalid.report.execution == ExecutionStatus::Error && !invalid.preimage_found,
                "An invalid digest width must be reported as an error.");
    }

    void test_toy_sha_collision()
    {
        const QuantumAttackConfig config = test_config(3003U);
        const std::size_t bits = educational::ToySetShaOutputBits;
        const ToyShaCollisionAttack attack =
            attack_toy_sha_collision_with_bht(bits, "QA test collision:", config, 101U);
        const AttackResult& report = attack.report;
        require(report.kind == AttackKind::ShaCollision, "The collision search has its own attack kind.");
        require(report.algorithm_family == "BHT", "The collision search must be labeled BHT, not Grover.");
        require(contains(report.algorithm, "Brassard-Hoyer-Tapp") && report.algorithm_family != "Grover",
                "The collision algorithm must be Brassard-Hoyer-Tapp.");
        require(report.execution == ExecutionStatus::Simulated && report.outcome == AttackOutcome::Succeeded,
                "The Toy SHA collision attack must be executed and succeed.");
        require(attack.collision_found && attack.first_message != attack.second_message,
                "A collision needs two different messages.");
        require(educational::truncated_sha256(attack.first_message, bits) ==
                educational::truncated_sha256(attack.second_message, bits),
                "The two messages must have the same Toy SHA digest.");
        require(report.logical_model.quantum_memory_bits.has_value() &&
                report.logical_model.quantum_memory_bits.value > 0.0L &&
                report.logical_model.quantum_memory_bits.value <= 40.0L * 16.0L,
                "BHT must report its quantum-accessible table memory (about 2^(b/3) x b bits).");
        require(report.simulated.total_qubits.value == 16.0L, "The BHT search register must have b qubits.");
        require(contains(report.applicability, "COLLISION"), "The report must say this is a collision attack.");

        const ToyShaCollisionAttack small =
            attack_toy_sha_collision_with_bht(8U, "QA test collision 8:", config, 102U);
        require(small.collision_found && small.first_message != small.second_message &&
                educational::truncated_sha256(small.first_message, 8U) ==
                    educational::truncated_sha256(small.second_message, 8U),
                "The 8-bit BHT collision search failed.");

        // Preimage and collision are two different reports.
        const ToyShaPreimageAttack preimage = attack_toy_sha_preimage_with_grover(
            educational::truncated_sha256("Hello", 8U), 8U, "QA test preimage 8:", config, 103U);
        require(preimage.report.id != small.report.id && preimage.report.kind != small.report.kind,
                "Preimage and collision results must not be merged.");
    }

    // ---------------------------------------------------------------------------------
    // Public-key components: explicit "not implemented" / NOT MODELED handling
    // ---------------------------------------------------------------------------------
    void test_toy_ecc_shor_handling()
    {
        const QuantumAttackConfig config = test_config(4004U);
        const auto sample = educational::generate_toy_ecc_sample();
        const AttackResult report = analyze_toy_ecc_shor_theory(sample.public_instance, config);
        require(report.kind == AttackKind::EccDiscreteLog && contains(report.algorithm_family, "ECDLP"),
                "Toy ECC must be matched with Shor's ECDLP algorithm.");
        require(report.execution == ExecutionStatus::TheoryOnly && !report.circuit_implemented &&
                !report.simulator_executed, "The ECDLP circuit is not implemented and must say so.");
        require(report.outcome == AttackOutcome::NotAttempted && report.recovered.empty() &&
                !report.verified_against_public_instance,
                "No ECC secret may be reported as recovered by a quantum method.");
        require(report.simulated.total_qubits.kind == MetricKind::NotExecuted &&
                report.time.simulator_runtime_ms.kind == MetricKind::NotExecuted,
                "Nothing was simulated for ECC, so nothing may be reported as measured.");
        require(report.logical_model.total_qubits.kind == MetricKind::Estimated &&
                report.logical_model.total_qubits.value == 79.0L,
                "The ECC resource model must come from the published formula.");
        require(report.time.estimated_quantum_attack_seconds.kind == MetricKind::Estimated,
                "The ECC time must be an estimate.");
        require(report.time.classical_attack_runtime_ms.kind == MetricKind::Measured,
                "The existing classical ECC attack must be measured.");
        require(!report.validation.included,
                "The N = 15 factoring experiment is not an ECDLP circuit and must not appear for ECC.");
        bool has_public_point = false;
        for (const auto& [name, value] : report.parameters)
        {
            if (name == "Public point Q" &&
                contains(value, std::to_string(sample.public_instance.public_x)) &&
                contains(value, std::to_string(sample.public_instance.public_y)))
            {
                has_public_point = true;
            }
        }
        require(has_public_point, "The ECC report must show the actual public point.");
        require(contains(report.applicability, "not an elliptic-curve circuit"),
                "The report must say the toy factoring experiment is not an ECDLP circuit.");
    }

    void test_toy_rsa_shor_handling()
    {
        const QuantumAttackConfig config = test_config(5005U);
        const auto sample = educational::generate_toy_rsa_sample(educational::ToySetRsaModulusBits);
        const AttackResult report = analyze_toy_rsa_shor_theory(sample.public_instance, config);
        require(report.kind == AttackKind::RsaFactoring && contains(report.algorithm_family, "factoring"),
                "Toy RSA must be matched with Shor's factoring algorithm.");
        require(report.execution == ExecutionStatus::TheoryOnly && !report.circuit_implemented &&
                !report.simulator_executed, "The factoring circuit for this modulus is not implemented.");
        require(report.outcome == AttackOutcome::NotAttempted && report.recovered.empty(),
                "No RSA factor may be reported as recovered by a quantum method.");
        require(report.logical_model.total_qubits.value == 51.0L, "The RSA model must report 2n + 3 qubits.");
        require(report.time.simulator_runtime_ms.kind == MetricKind::NotExecuted,
                "Nothing was simulated for this modulus.");

        bool has_modulus = false;
        bool has_bits = false;
        for (const auto& [name, value] : report.parameters)
        {
            if (name == "Public modulus N" && value == std::to_string(sample.public_instance.modulus)) has_modulus = true;
            if (name == "Modulus size" && value == "24 bits") has_bits = true;
        }
        require(has_modulus && has_bits, "The RSA report must show the actual modulus and its size.");

        // The N = 15 experiment is a separate validation run and never an attack on N.
        require(report.validation.included && report.validation.passed,
                "The existing N = 15 experiment must be run as a validation experiment.");
        require(contains(report.validation.disclaimer, "NOT an attack"),
                "The validation experiment must be disclaimed.");
        require(contains(report.validation.disclaimer, std::to_string(sample.public_instance.modulus)),
                "The disclaimer must name the real modulus it is not about.");
        require(report.outcome != AttackOutcome::Succeeded,
                "A successful N = 15 run must not turn the RSA analysis into a success.");

        QuantumAttackConfig without_validation = config;
        without_validation.run_validation_experiments = false;
        without_validation.run_classical_baselines = false;
        const AttackResult plain = analyze_toy_rsa_shor_theory(sample.public_instance, without_validation);
        require(!plain.validation.included, "The validation experiment must be optional.");
        require(plain.time.classical_attack_runtime_ms.kind == MetricKind::NotExecuted,
                "A disabled classical baseline must be NOT EXECUTED, not 0.");
    }

    void test_toy_module_lwe_handling()
    {
        const QuantumAttackConfig config = test_config(6006U);
        const auto sample = educational::generate_toy_lwe_sample();
        const AttackResult report = analyze_toy_module_lwe_not_modeled(sample.public_instance, config);
        require(report.kind == AttackKind::ModuleLweSecretSearch, "Module-LWE has its own attack kind.");
        require(report.execution == ExecutionStatus::NotModeled && report.algorithm_family == "NOT MODELED",
                "Module-LWE must be reported as NOT MODELED.");
        require(!contains(report.algorithm, "Shor") && !contains(report.algorithm_family, "Shor"),
                "Shor's algorithm must never be assigned to Module-LWE.");
        require(contains(report.applicability, "does NOT apply"),
                "The report must say that Shor does not apply to Module-LWE.");
        require(report.outcome == AttackOutcome::NotAttempted && report.recovered.empty(),
                "No Module-LWE secret may be reported as recovered by a quantum method.");
        require(report.logical_model.total_qubits.kind == MetricKind::NotModeled &&
                report.logical_model.gate_count.kind == MetricKind::NotModeled &&
                report.logical_model.circuit_depth.kind == MetricKind::NotModeled,
                "No qubit, gate or depth figure may be invented for Module-LWE.");
        require(report.time.estimated_quantum_attack_seconds.kind == MetricKind::NotModeled,
                "No attack time may be invented for Module-LWE.");
        require(report.time.classical_attack_runtime_ms.kind == MetricKind::Measured,
                "The existing classical Module-LWE attack must still be measured.");
        const std::string text = format_attack_report(report);
        require(contains(text, "NOT MODELED") && !contains(text, "Total qubits     : 0"),
                "The Module-LWE report must print NOT MODELED, never 0.");
    }

    // ---------------------------------------------------------------------------------
    // The three independent sets, their reports and exports
    // ---------------------------------------------------------------------------------
    void test_set_status_logic()
    {
        AttackResult succeeded;
        succeeded.execution = ExecutionStatus::Simulated;
        succeeded.outcome = AttackOutcome::Succeeded;
        AttackResult theory;
        theory.execution = ExecutionStatus::TheoryOnly;
        theory.outcome = AttackOutcome::NotAttempted;
        AttackResult failed;
        failed.execution = ExecutionStatus::Simulated;
        failed.outcome = AttackOutcome::Failed;
        AttackResult error;
        error.execution = ExecutionStatus::Error;
        error.outcome = AttackOutcome::NotAttempted;

        require(evaluate_set_status({succeeded, succeeded}) == SetStatus::AllSucceeded, "All-success status is wrong.");
        require(evaluate_set_status({succeeded, theory}) == SetStatus::Partial,
                "A set with a non-executed attack must be PARTIAL, not a success.");
        require(evaluate_set_status({succeeded, theory, failed}) == SetStatus::Failed, "A failed attack must fail the set.");
        require(evaluate_set_status({succeeded, error}) == SetStatus::Failed, "An error must fail the set.");
        require(evaluate_set_status({}) == SetStatus::Partial, "An empty set is not a success.");
    }

    void test_three_independent_sets()
    {
        const QuantumAttackConfig config = test_config(7007U);
        const std::vector<SetAttackReport> reports = run_all_quantum_attacks("Hello", config);
        require(reports.size() == 3U, "Exactly three independent sets are expected.");
        require(reports[0].id == SetId::AesShaEcdsa && reports[1].id == SetId::AesShaRsaPss &&
                reports[2].id == SetId::ShaAesMlKem, "The three sets are in the wrong order.");

        const AttackKind expected_last[3] = {
            AttackKind::EccDiscreteLog, AttackKind::RsaFactoring, AttackKind::ModuleLweSecretSearch};
        std::vector<std::string> preimage_families;
        for (std::size_t index = 0U; index < reports.size(); ++index)
        {
            const SetAttackReport& report = reports[index];
            require(report.attacks.size() == 4U, "Each set has four analyses.");
            require(report.attacks[0].kind == AttackKind::AesKeySearch &&
                    report.attacks[1].kind == AttackKind::ShaPreimage &&
                    report.attacks[2].kind == AttackKind::ShaCollision &&
                    report.attacks[3].kind == expected_last[index], "A set has the wrong analyses.");
            for (const AttackResult& attack : report.attacks)
                require(attack.system_name == report.name, "Each analysis must name its own set.");
            require(report.attacks[0].outcome == AttackOutcome::Succeeded &&
                    report.attacks[0].matches_ground_truth.value_or(false),
                    "Each set's own Toy AES key must be recovered.");
            require(report.attacks[1].outcome == AttackOutcome::Succeeded &&
                    report.attacks[2].outcome == AttackOutcome::Succeeded,
                    "Each set's Toy SHA analyses must succeed.");
            // Honest status: the public-key component was not attacked by a circuit.
            require(report.status == SetStatus::Partial, "A set with a non-executed analysis must be PARTIAL.");
            require(!report.instance.empty() && report.wall_ms > 0.0, "The set instance must be described.");
            for (const auto& [name, value] : report.attacks[1].parameters)
                if (name == "Message family") preimage_families.push_back(value);

            const std::string text = format_set_report(report);
            require(contains(text, "A. Quantum simulator runtime") &&
                    contains(text, "B. Estimated quantum attack time") &&
                    contains(text, "C. Classical attack runtime"),
                    "The set report must print the three time categories separately.");
            require(contains(text, "never added together"), "The report must say the times are not added.");
            require(contains(text, "logical qubits"), "The report must say that qubits are logical qubits.");
        }
        require(preimage_families.size() == 3U && preimage_families[0] != preimage_families[1] &&
                preimage_families[1] != preimage_families[2],
                "Each set must run its own Toy SHA experiment.");
        require(reports[2].attacks[3].execution == ExecutionStatus::NotModeled,
                "The Module-LWE component must be NOT MODELED.");
        require(contains(format_set_report(reports[2]), "NOT MODELED"), "The report must print NOT MODELED.");

        // CSV: header and every row have the same number of columns; units are in the names.
        const std::string csv = metrics_csv(reports);
        std::istringstream lines(csv);
        std::string line;
        std::size_t columns = 0U;
        std::size_t rows = 0U;
        while (std::getline(lines, line))
        {
            if (line.empty()) continue;
            const std::size_t count = split_csv(line).size();
            if (columns == 0U) columns = count;
            else
            {
                require(count == columns, "A CSV row has a different number of columns than the header.");
                ++rows;
            }
        }
        require(rows == 12U, "The CSV must contain one row per analysis.");
        const std::string header = metrics_csv_header();
        require(contains(header, "time_a_simulator_runtime_ms") &&
                contains(header, "time_b_estimated_quantum_attack_seconds") &&
                contains(header, "time_c_classical_attack_runtime_ms") &&
                contains(header, "state_vector_bytes") && contains(header, "_kind"),
                "CSV column names must carry units and provenance columns.");
        require(contains(csv, "NOT MODELED") && contains(csv, "NOT EXECUTED"),
                "Absent values must be written as text in the CSV.");

        // JSON: structurally balanced outside string literals.
        const std::string json = metrics_json(reports);
        long braces = 0;
        long brackets = 0;
        bool in_string = false;
        for (std::size_t index = 0U; index < json.size(); ++index)
        {
            const char character = json[index];
            if (in_string)
            {
                if (character == '\\') ++index;
                else if (character == '"') in_string = false;
            }
            else if (character == '"') in_string = true;
            else if (character == '{') ++braces;
            else if (character == '}') --braces;
            else if (character == '[') ++brackets;
            else if (character == ']') --brackets;
        }
        require(braces == 0 && brackets == 0 && !in_string, "The JSON export is not balanced.");
        require(contains(json, "\"value\": null"), "Absent JSON values must be null, not 0.");

        // File export.
        const std::string directory = "EducationalQuantumAttackTestOutput";
        std::filesystem::remove_all(directory);
        ExportedFiles files;
        require(export_quantum_attack_reports(reports, directory, files), "The report export failed.");
        require(files.set_reports.size() == 3U, "One text report per set is expected.");
        for (const std::string& path : files.set_reports)
            require(std::filesystem::exists(path) && std::filesystem::file_size(path) > 0U, "A set report file is missing.");
        require(contains(files.set_reports[0], "aes_sha_ecdsa_quantum_report.txt") &&
                contains(files.set_reports[1], "aes_sha_rsapss_quantum_report.txt") &&
                contains(files.set_reports[2], "sha_aes_mlkem_quantum_report.txt"), "Report file names are wrong.");
        require(contains(read_file(files.metrics_csv), "toy_sha_collision_bht"), "The metrics CSV is incomplete.");
        require(std::filesystem::file_size(files.metrics_json) > 0U, "The metrics JSON is empty.");
        std::filesystem::remove_all(directory);
    }

    void test_individual_set_entry_points()
    {
        const QuantumAttackConfig config = test_config(8008U);
        // An empty message falls back to the default demonstration message.
        const SetAttackReport ecdsa = run_aes_sha_ecdsa_quantum_attack(std::string(), config);
        require(ecdsa.id == SetId::AesShaEcdsa && ecdsa.attacks.size() == 4U, "The ECDSA-analogue set failed to run.");
        bool default_message = false;
        for (const auto& [name, value] : ecdsa.instance)
            if (name == "Message" && value == std::string(DefaultQuantumAttackMessage)) default_message = true;
        require(default_message, "An empty message must be replaced by the default message.");

        // A set analysis works on exactly the instance it is given.
        const AesShaRsaPssTarget target = generate_aes_sha_rsapss_target("Hello", 16U);
        require(target.rsa.modulus_bits == 16U, "The requested RSA modulus size was not generated.");
        const SetAttackReport rsa = run_aes_sha_rsapss_quantum_attack(target, config);
        bool modulus_reported = false;
        for (const auto& [name, value] : rsa.attacks[3].parameters)
            if (name == "Public modulus N" && value == std::to_string(target.rsa.public_instance.modulus))
                modulus_reported = true;
        require(modulus_reported, "The RSA analysis must use the modulus of the instance it was given.");

        const SetAttackReport mlkem = run_sha_aes_mlkem_quantum_attack("Hello", config);
        require(mlkem.id == SetId::ShaAesMlKem && mlkem.attacks[3].execution == ExecutionStatus::NotModeled,
                "The ML-KEM-analogue set failed to run.");
    }

    // ---------------------------------------------------------------------------------
    // Real Shor factoring, real Shor ECDLP, real custom Module-LWE Grover (executed attacks)
    // ---------------------------------------------------------------------------------
    void test_real_shor_factoring()
    {
        // 3233 = 61 * 53 is a genuine odd composite; Shor order finding must factor it.
        ShorFactoringOptions options;
        options.execution.backend = crypto::quantum::QuantumBackendType::CpuSingleThread;
        options.seed = 42U;
        options.qubit_budget = 26U;
        const ShorFactoringResult result = run_shor_factoring(3233U, options);
        require(result.executed, "Shor factoring must execute within the budget for N = 3233.");
        require(result.factored && result.factor_p * result.factor_q == 3233U,
                "Shor must actually factor 3233 (a real executed attack, not an estimate).");
        require((result.factor_p == 61U || result.factor_p == 53U) &&
                (result.factor_q == 61U || result.factor_q == 53U),
                "The recovered factors of 3233 must be 61 and 53.");
        require(result.total_qubits == bit_length(3233U) + 1U,
                "Shor factoring uses n + 1 qubits (one reused control qubit).");
        require(result.recovered_order % 2U == 0U && mod_pow(result.winning_base, result.recovered_order, 3233U) == 1U,
                "The recovered order must be an even multiplicative order of the winning base.");

        ShorFactoringOptions tight = options;
        tight.qubit_budget = 5U;
        const ShorFactoringResult refused = run_shor_factoring(3233U, tight);
        require(!refused.executed && !refused.factored,
                "A circuit over the qubit budget must be reported as not executed, not factored.");
    }

    void test_real_shor_ecdlp()
    {
        for (std::uint64_t seed = 1U; seed <= 5U; ++seed)
        {
            const auto sample = educational::generate_toy_ecc_sample();
            ShorEcdlpOptions options;
            options.execution.backend = crypto::quantum::QuantumBackendType::CpuSingleThread;
            options.seed = seed;
            options.qubit_budget = 26U;
            const ShorEcdlpResult result = run_shor_ecdlp(sample.public_instance, options);
            require(result.executed, "ECDLP phase estimation must execute within the budget.");
            require(result.recovered, "Shor ECDLP must recover the discrete logarithm (a real executed attack).");
            require(result.recovered_scalar == sample.ground_truth.private_scalar,
                    "The recovered scalar must equal the withheld private scalar.");
            const educational::ToyEccPoint q{sample.public_instance.public_x, sample.public_instance.public_y, false};
            require(educational::toy_ecc_multiply(result.recovered_scalar, educational::toy_ecc_base_point()) == q,
                    "The recovered scalar must be verified by coordinate arithmetic: k*G == Q.");
            require(result.total_qubits == result.register_qubits + 1U, "ECDLP uses register + 1 control qubit.");
        }
    }

    void test_real_module_lwe_grover()
    {
        const auto sample = educational::generate_toy_lwe_sample();
        QuantumAttackConfig config = test_config(314U);
        const ToyModuleLweGroverAttack attack =
            attack_toy_module_lwe_with_grover(sample.public_instance, config, 314U);
        require(attack.executed && attack.secret_recovered,
                "The custom Module-LWE Grover attack must execute and recover the secret.");
        require(attack.recovered_secret == sample.ground_truth.secret,
                "The recovered Module-LWE secret must equal the withheld secret.");
        require(attack.search_qubits == 13U && attack.candidate_space == educational::ToyModuleSecretCandidateCount,
                "The Module-LWE search covers 3^8 candidates in 13 qubits.");
        require(attack.grover_iterations > 0U, "The custom Grover attack must record its oracle calls.");
    }

    void test_educate_analysis_mode()
    {
        EducateAnalysisConfig config;
        config.primary_execution.backend = crypto::quantum::QuantumBackendType::CpuMultiThread;
        config.primary_execution.cpu_threads = 2U;
        config.seed = 99U;
        config.rsa_modulus_bits = 16U;
        config.measure_gpu = true;

        const EducateAnalysisReport empty = run_educate_analysis(std::string(), config);
        require(empty.plaintext_empty && empty.sets.empty(), "An empty sentence must crack nothing.");

        const std::string sentence = "Meet me at midnight.";
        const EducateAnalysisReport report = run_educate_analysis(sentence, config);
        require(report.sets.size() == 3U, "EducateAnalysis must cover the three toy composites.");
        require(report.sets[0].name == "Toy-AES_Toy-SHA_Toy-ECDSA" &&
                report.sets[1].name == "Toy-AES_Toy-SHA_Toy-RSAPSS" &&
                report.sets[2].name == "Toy-AES_Toy-SHA_Toy-MLDSA",
                "The three composites must be named as requested.");

        const char* expected_last_algorithm[3] = {"Shor (ECDLP)", "Shor (factoring)", "Custom Grover secret search (not Shor)"};
        for (std::size_t index = 0U; index < report.sets.size(); ++index)
        {
            const SetCrack& set = report.sets[index];
            require(set.components.size() == 3U, "Each composite has AES, SHA and a public-key component.");
            require(!set.encryption.empty(), "The encryption of the sentence must be reported.");
            require(set.components[0].algorithm == "Grover" && set.components[1].algorithm == "Grover",
                    "AES and SHA are attacked with Grover.");
            require(set.components[2].algorithm == std::string(expected_last_algorithm[index]),
                    "The public-key component must use the requested algorithm.");
            for (const ComponentCrack& component : set.components)
            {
                require(component.executed, "Every EducateAnalysis attack must actually execute on the simulator.");
                require(component.cracked, "Every component must be really cracked at these toy sizes.");
                require(!component.inputs.empty() && !component.recovered.empty(),
                        "Intermediate input and recovered values must both be reported.");
                // Per-backend timing: single CPU, multithreaded CPU, and a GPU row.
                require(component.timings.size() == 3U, "Three execution methods must be compared.");
                require(component.timings[0].method == "Single CPU" && component.timings[0].executed &&
                        component.timings[1].method == "Multithreaded CPU" && component.timings[1].executed,
                        "Both CPU methods must be timed.");
                const BackendTiming& gpu = component.timings[2];
                require(gpu.method == "GPU parallel", "The third method is GPU parallel.");
                if (!crypto::quantum::cuda_backend::CUDAQuantumBackend::is_available())
                    require(!gpu.executed && contains(gpu.note, "UNAVAILABLE"),
                            "Without a GPU backend, the GPU row must say UNAVAILABLE and must not run on the CPU.");
            }
        }
        // The RSA component must report real factors whose product is the modulus.
        bool rsa_product_ok = false;
        for (const auto& [name, value] : report.sets[1].components[2].recovered)
            if (name == "Product checks out" && value == "YES") rsa_product_ok = true;
        require(rsa_product_ok, "The toy RSA factoring must recover factors whose product is the modulus.");

        // Export to an absolute path regardless of the working directory.
        const std::string directory = "EducateAnalysisTestOutput";
        std::filesystem::remove_all(directory);
        std::string report_path;
        std::string csv_path;
        require(export_educate_analysis_report(report, directory, report_path, csv_path),
                "The EducateAnalysis export failed.");
        require(std::filesystem::path(report_path).is_absolute() && std::filesystem::path(csv_path).is_absolute(),
                "Exported paths must be absolute so the files can be found regardless of the launch directory.");
        require(std::filesystem::exists(report_path) && std::filesystem::file_size(report_path) > 0U &&
                std::filesystem::exists(csv_path) && std::filesystem::file_size(csv_path) > 0U,
                "The EducateAnalysis export files must exist and be non-empty.");
        require(contains(read_file(csv_path), "single_cpu_ms") && contains(read_file(csv_path), "gpu_status"),
                "The crack CSV must carry the per-method columns.");
        std::filesystem::remove_all(directory);
    }

    // ---------------------------------------------------------------------------------
    // Message crack-timing feature: enter a sentence, encrypt it, crack it, time the crack
    // ---------------------------------------------------------------------------------
    void test_message_crack_timing()
    {
        const QuantumAttackConfig config = test_config(9009U);

        // An empty sentence encrypts and cracks nothing.
        const MessageCrackReport empty = run_message_crack_timing(std::string(), config);
        require(empty.plaintext_empty && empty.sets.empty(), "An empty sentence must crack nothing.");
        require(contains(empty.report, "No sentence"), "The empty report must say nothing was cracked.");

        const std::string sentence = "The quick brown fox.";
        const MessageCrackReport report = run_message_crack_timing(sentence, config);
        require(!report.plaintext_empty && report.plaintext == sentence, "The sentence must be preserved.");
        require(report.sets.size() == 3U, "The sentence must be cracked in all three independent toy sets.");
        require(contains(report.report, "CRACK TIME") && contains(report.report, "toy parameters"),
                "The report must present the crack time and stay labeled as a toy.");
        require(contains(report.report, sentence), "The report must echo the entered sentence.");

        for (const MessageCrackSetResult& set : report.sets)
        {
            require(set.unknown_key_bits == educational::ToySetAesUnknownKeyBits &&
                    set.key_space == (std::size_t{1} << educational::ToySetAesUnknownKeyBits),
                    "Each set must encrypt with the 12-bit toy key space.");
            require(set.ciphertext_bytes > 0U, "The sentence must actually be encrypted.");

            // The classical crack recovers the key and decrypts the exact sentence, and its
            // time is a measured value.
            require(set.classical_recovered && set.classical_plaintext_matches &&
                    set.classical_decrypted == sentence,
                    "The classical crack must recover the key and the exact sentence.");
            require(set.classical_crack_ms.kind == MetricKind::Measured &&
                    set.classical_crack_ms.value >= 0.0L,
                    "The classical crack time must be a measured value.");
            require(set.classical_keys_tried.kind == MetricKind::Measured &&
                    set.classical_keys_tried.value > 0.0L, "The classical crack must try keys.");

            // The quantum Grover crack recovers the key; the simulator runtime is measured and
            // the estimated quantum time is an estimate. The two are not the same quantity.
            require(set.quantum_executed && set.quantum_recovered, "The Grover crack must recover the key.");
            require(set.quantum_simulator_ms.kind == MetricKind::Measured,
                    "The Grover simulator runtime must be a measured value.");
            require(set.quantum_estimated_seconds.kind == MetricKind::Estimated,
                    "The estimated quantum attack time must be an estimate, not a measurement.");
            require(set.grover_iterations.has_value() && set.grover_iterations.value > 0.0L,
                    "The Grover crack must record its iterations.");
            require(set.simulated_qubits.value == static_cast<long double>(educational::ToySetAesUnknownKeyBits),
                    "The simulated register must hold the 12 toy key bits.");
        }

        // File export.
        const std::string directory = "MessageCrackTestOutput";
        std::filesystem::remove_all(directory);
        std::string report_path;
        std::string csv_path;
        require(export_message_crack_report(report, directory, report_path, csv_path),
                "The message crack export failed.");
        require(std::filesystem::exists(report_path) && std::filesystem::file_size(report_path) > 0U &&
                std::filesystem::exists(csv_path) && std::filesystem::file_size(csv_path) > 0U,
                "The message crack export files are missing.");
        require(contains(read_file(csv_path), "classical_crack_ms"), "The crack CSV is missing its columns.");
        std::filesystem::remove_all(directory);
    }
}

int main()
{
    try
    {
        test_metric_rules();
        test_resource_models();
        test_backend_resolution();
        test_grover_engine();
        test_phase_estimation_engine();
        test_toy_aes_grover();
        test_toy_sha_preimage();
        test_toy_sha_collision();
        test_toy_ecc_shor_handling();
        test_toy_rsa_shor_handling();
        test_toy_module_lwe_handling();
        test_set_status_logic();
        test_three_independent_sets();
        test_individual_set_entry_points();
        test_real_shor_factoring();
        test_real_shor_ecdlp();
        test_real_module_lwe_grover();
        test_educate_analysis_mode();
        test_message_crack_timing();
        std::cout << "[PASS] Educational quantum attack tests completed successfully.\n";
        return 0;
    }
    catch (const std::exception& exception)
    {
        std::cerr << "[FAIL] " << exception.what() << '\n';
        return 1;
    }
}
