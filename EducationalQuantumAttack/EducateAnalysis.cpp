#include "EducateAnalysis.h"

#include "EducationalQuantumAttack/Attacks/AttackCommon.h"
#include "EducationalQuantumAttack/Attacks/ToyAesGroverAttack.h"
#include "EducationalQuantumAttack/Attacks/ToyModuleLweGroverAttack.h"
#include "EducationalQuantumAttack/Attacks/ToyShaQuantumAttack.h"
#include "EducationalQuantumAttack/Common/QuantumAttackReport.h"
#include "EducationalQuantumAttack/Common/QuantumAttackSupport.h"
#include "EducationalQuantumAttack/Engine/GroverEngine.h"
#include "EducationalQuantumAttack/Engine/ShorEcdlp.h"
#include "EducationalQuantumAttack/Engine/ShorFactoring.h"
#include "CryptoSystem/Standard/AES/AES128GCM.h"
#include "CryptoSystem/Educational/AES/ToyAESKeySearch.h"
#include "CryptoSystem/Educational/ECC/ToyECC.h"
#include "CryptoSystem/Educational/EducationalParameters.h"
#include "CryptoSystem/Educational/ModuleLWE/ToyModuleLWE.h"
#include "CryptoSystem/Educational/RSA/ToyRSA.h"
#include "CryptoSystem/Educational/SHA/ToySha256.h"
#include "QuantumAttack/Backend/CUDA/CUDAMultiGpuQuantumBackend.h"
#include "QuantumAttack/Backend/CUDA/CUDAQuantumBackend.h"

#include <array>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <span>
#include <sstream>

namespace crypto::educational_quantum_attack
{
    namespace
    {
        constexpr const char* kDoubleRule =
            "================================================================================";
        constexpr const char* kRule =
            "--------------------------------------------------------------------------------";

        using Backend = quantum::QuantumBackendType;

        [[nodiscard]] std::string key_hex(const standard::Aes128Key& key)
        {
            return hex_string(std::span<const std::uint8_t>(key.data(), key.size()));
        }

        [[nodiscard]] std::string ms_text(const double value)
        {
            std::ostringstream out;
            out << std::fixed << std::setprecision(3) << value << " ms";
            return out.str();
        }

        [[nodiscard]] std::string lwe_vector_text(const educational::ToyModuleSmallVector& secret)
        {
            std::ostringstream out;
            for (std::size_t module_index = 0; module_index < secret.size(); ++module_index)
            {
                if (module_index != 0U) out << " | ";
                out << "s" << module_index << "=[";
                for (std::size_t coefficient = 0; coefficient < secret[module_index].size(); ++coefficient)
                {
                    if (coefficient != 0U) out << ',';
                    out << static_cast<int>(secret[module_index][coefficient]);
                }
                out << ']';
            }
            return out.str();
        }

        [[nodiscard]] std::string lwe_public_text(const educational::ToyLwePublicInstance& instance)
        {
            std::ostringstream out;
            out << "b=[";
            for (std::size_t row = 0; row < instance.vector.size(); ++row)
            {
                if (row != 0U) out << " | ";
                out << '[';
                for (std::size_t c = 0; c < instance.vector[row].size(); ++c)
                {
                    if (c != 0U) out << ',';
                    out << instance.vector[row][c];
                }
                out << ']';
            }
            out << "]";
            return out.str();
        }

        // Runs one decisive attack circuit on each execution method and times it. `runner`
        // executes one circuit on the given options and returns the simulator wall time in ms.
        // `gpu_request` is the GPU backend the user opted into (CudaGpu or CudaMultiGpu); any
        // CPU value means "GPU timing not requested" and the GPU row is only a detection note.
        [[nodiscard]] std::vector<BackendTiming> measure_backends(
            bool include_gpu, Backend gpu_request,
            const std::function<double(const quantum::QuantumExecutionOptions&)>& runner)
        {
            std::vector<BackendTiming> timings;

            BackendTiming single;
            single.method = "Single CPU";
            single.available = true;
            try
            {
                quantum::QuantumExecutionOptions options;
                options.backend = Backend::CpuSingleThread;
                options.cpu_threads = 1U;
                single.simulator_ms = runner(options);
                single.executed = true;
            }
            catch (const std::exception& exception) { single.note = exception.what(); }
            timings.push_back(std::move(single));

            BackendTiming multi;
            multi.method = "Multithreaded CPU";
            multi.available = true;
            try
            {
                quantum::QuantumExecutionOptions options;
                options.backend = Backend::CpuMultiThread;
                options.cpu_threads = 0U;   // up to the worker-pool default
                multi.simulator_ms = runner(options);
                multi.executed = true;
            }
            catch (const std::exception& exception) { multi.note = exception.what(); }
            timings.push_back(std::move(multi));

            if (include_gpu)
            {
                BackendTiming gpu;
                gpu.method = "GPU parallel";
                const bool user_requested_gpu =
                    gpu_request == Backend::CudaGpu || gpu_request == Backend::CudaMultiGpu;
                if (!user_requested_gpu)
                {
                    // The user did not select a CUDA backend, so the GPU is not exercised. The
                    // project's CUDA paths are unverified on hardware, so GPU timing is strictly
                    // opt-in to keep the default run safe.
                    gpu.available = quantum::cuda_backend::CUDAQuantumBackend::is_available();
                    gpu.note = "not requested (choose a CUDA backend to measure the GPU; CPU is the safe default)";
                    timings.push_back(std::move(gpu));
                    return timings;
                }

                // Resolve the requested GPU backend safely: a multi-GPU request with fewer than
                // two devices falls back to the single-GPU backend, never to a faulting path.
                quantum::QuantumExecutionOptions requested;
                requested.backend = gpu_request;
                const ResolvedBackend resolved = resolve_backend(requested);
                gpu.available = resolved.gpu_available;
                if (resolved.gpu_available)
                {
                    try
                    {
                        gpu.simulator_ms = runner(resolved.options);
                        gpu.executed = true;
                        gpu.note = resolved.gpu_status == "AVAILABLE" ? std::string() : resolved.gpu_status;
                    }
                    catch (const std::exception& exception) { gpu.note = exception.what(); }
                }
                else
                {
                    gpu.note = resolved.gpu_status;
                }
                timings.push_back(std::move(gpu));
            }
            return timings;
        }

        // The real crack always runs on a CPU backend: the CUDA paths are unverified on hardware,
        // so the recovery must never depend on them. A single-thread request stays single-thread;
        // every other choice (including a CUDA selection) recovers on multithreaded CPU.
        [[nodiscard]] quantum::QuantumExecutionOptions primary(const EducateAnalysisConfig& config)
        {
            quantum::QuantumExecutionOptions options;
            if (config.primary_execution.backend == Backend::CpuSingleThread)
            {
                options.backend = Backend::CpuSingleThread;
                options.cpu_threads = 1U;
            }
            else
            {
                options.backend = Backend::CpuMultiThread;
                options.cpu_threads = config.primary_execution.cpu_threads;
            }
            return options;
        }

        // The GPU backend the user opted into for the timing comparison, if any.
        [[nodiscard]] Backend requested_gpu_backend(const EducateAnalysisConfig& config)
        {
            const Backend chosen = config.primary_execution.backend;
            return (chosen == Backend::CudaGpu || chosen == Backend::CudaMultiGpu) ? chosen : Backend::CpuMultiThread;
        }

        // ---- decisive single-circuit runners for the Grover components ------------------

        [[nodiscard]] double time_grover_circuit(
            std::size_t search_qubits, const std::vector<std::size_t>& marked,
            const std::function<bool(std::size_t)>& verifier, double assumed_solutions,
            const quantum::QuantumExecutionOptions& execution, std::uint64_t seed, std::size_t budget)
        {
            GroverSearchRequest request;
            request.search_qubits = search_qubits;
            request.marked_indices = marked;
            request.classical_verifier = verifier;
            request.strategy = GroverStrategy::KnownSolutionCount;
            request.assumed_solution_count = assumed_solutions < 1.0 ? 1.0 : assumed_solutions;
            request.max_attempts = 1U;
            request.fall_back_to_unknown_count = false;
            request.seed = seed;
            request.execution = execution;
            request.simulator_qubit_limit = budget;
            return run_grover_search(request).simulation_wall_ms;
        }
    }

    std::string absolute_output_path(const std::string& path)
    {
        try
        {
            return std::filesystem::weakly_canonical(std::filesystem::absolute(path)).string();
        }
        catch (const std::exception&)
        {
            try { return std::filesystem::absolute(path).string(); }
            catch (const std::exception&) { return path; }
        }
    }

    namespace
    {
        // ---- AES (Grover) --------------------------------------------------------------
        ComponentCrack crack_toy_aes(
            const educational::ToyAesSample& sample, const EducateAnalysisConfig& config, std::uint64_t seed)
        {
            ComponentCrack component;
            component.component = "Toy AES (restricted-key-space AES-128-GCM)";
            component.algorithm = "Grover";
            const auto& instance = sample.public_instance;
            const std::size_t bits = instance.unknown_bits;
            const std::size_t key_space = std::size_t{1} << bits;

            component.inputs.emplace_back("Unknown key bits", std::to_string(bits));
            component.inputs.emplace_back("Key space (2^bits)", std::to_string(key_space));
            component.inputs.emplace_back("Ground-truth AES key", key_hex(sample.ground_truth.key));
            component.inputs.emplace_back("GCM nonce", hex_string(instance.ciphertext.nonce));
            component.inputs.emplace_back("GCM tag", hex_string(instance.ciphertext.tag));
            component.inputs.emplace_back("Ciphertext", hex_string(instance.ciphertext.ciphertext));
            component.inputs.emplace_back("Associated data (Toy SHA digest)", hex_string(instance.associated_data));

            QuantumAttackConfig attack_config;
            attack_config.execution = primary(config);
            attack_config.budget = config.budget;
            attack_config.seed = seed;
            attack_config.run_classical_baselines = false;
            attack_config.run_validation_experiments = false;
            attack_config.include_reference_scenarios = false;

            const Stopwatch crack_timer;
            ToyAesGroverAttack attack = attack_toy_aes_with_grover(instance, attack_config, seed);
            component.real_crack_ms = crack_timer.elapsed_ms();
            component.executed = attack.report.simulator_executed;
            component.cracked = attack.key_recovered;
            component.status = attack.report.execution_note;

            if (attack.key_recovered)
            {
                component.recovered.emplace_back("Recovered AES key", key_hex(attack.recovered_key));
                component.recovered.emplace_back("Decrypted plaintext", printable(attack.recovered_plaintext, 200U));
                component.recovered.emplace_back(
                    "Key matches ground truth",
                    attack.recovered_key == sample.ground_truth.key ? "YES" : "NO");
            }
            component.resources.emplace_back("Search qubits", metric_cell(attack.report.simulated.total_qubits));
            component.resources.emplace_back("Grover iterations (oracle calls)",
                                             metric_cell(attack.report.simulated.oracle_calls));

            if (component.executed)
            {
                std::vector<std::size_t> marked;
                for (std::size_t candidate = 0; candidate < key_space; ++candidate)
                    if (educational::toy_aes_candidate_matches(instance, static_cast<std::uint32_t>(candidate)))
                        marked.push_back(candidate);
                const auto verifier = [&instance](std::size_t candidate)
                { return educational::toy_aes_candidate_matches(instance, static_cast<std::uint32_t>(candidate)); };
                component.timings = measure_backends(config.measure_gpu, requested_gpu_backend(config),
                    [&](const quantum::QuantumExecutionOptions& execution)
                    {
                        return time_grover_circuit(bits, marked, verifier,
                            static_cast<double>(marked.size()), execution, seed, config.budget.max_qubits);
                    });
            }
            return component;
        }

        // ---- SHA preimage (Grover) -----------------------------------------------------
        ComponentCrack crack_toy_sha(
            const std::string& plaintext, const std::string& family, std::size_t sha_bits,
            const EducateAnalysisConfig& config, std::uint64_t seed)
        {
            ComponentCrack component;
            component.component = "Toy SHA preimage (SHA-256 truncated to " + std::to_string(sha_bits) + " bits)";
            component.algorithm = "Grover";
            const std::uint32_t digest = educational::truncated_sha256(plaintext, sha_bits);
            component.inputs.emplace_back("Message", printable(plaintext, 200U));
            component.inputs.emplace_back("Target Toy SHA digest", hex_value(digest, 4U));
            component.inputs.emplace_back("Message family", family + "<counter>");

            QuantumAttackConfig attack_config;
            attack_config.execution = primary(config);
            attack_config.budget = config.budget;
            attack_config.seed = seed;
            attack_config.run_classical_baselines = false;
            attack_config.run_validation_experiments = false;
            attack_config.include_reference_scenarios = false;

            const Stopwatch crack_timer;
            ToyShaPreimageAttack attack =
                attack_toy_sha_preimage_with_grover(digest, sha_bits, family, attack_config, seed);
            component.real_crack_ms = crack_timer.elapsed_ms();
            component.executed = attack.report.simulator_executed;
            component.cracked = attack.preimage_found;
            component.status = attack.report.execution_note;
            if (attack.preimage_found)
            {
                component.recovered.emplace_back("Preimage message", printable(attack.message, 200U));
                component.recovered.emplace_back("Preimage Toy SHA digest",
                    hex_value(educational::truncated_sha256(attack.message, sha_bits), 4U));
            }
            component.resources.emplace_back("Search qubits", metric_cell(attack.report.simulated.total_qubits));
            component.resources.emplace_back("Grover iterations (oracle calls)",
                                             metric_cell(attack.report.simulated.oracle_calls));

            if (component.executed)
            {
                // The preimage attack searches a 2^(b+2) domain. Time one decisive circuit of
                // that size under each backend, with the real predicate as the oracle.
                const std::size_t search_qubits = sha_bits + 2U;
                const std::size_t domain = std::size_t{1} << search_qubits;
                std::vector<std::size_t> marked;
                for (std::size_t counter = 0; counter < domain; ++counter)
                    if (educational::truncated_sha256(educational::toy_sha_family_message(family, counter), sha_bits) == digest)
                        marked.push_back(counter);
                const auto verifier = [&, digest](std::size_t counter)
                {
                    return educational::truncated_sha256(
                        educational::toy_sha_family_message(family, static_cast<std::uint64_t>(counter)), sha_bits) == digest;
                };
                const double assumed = marked.empty() ? 1.0 : static_cast<double>(marked.size());
                component.timings = measure_backends(config.measure_gpu, requested_gpu_backend(config),
                    [&](const quantum::QuantumExecutionOptions& execution)
                    {
                        return time_grover_circuit(search_qubits, marked, verifier, assumed, execution,
                                                   seed, config.budget.max_qubits);
                    });
            }
            return component;
        }

        // ---- ECC (Shor ECDLP) ----------------------------------------------------------
        ComponentCrack crack_toy_ecc(
            const educational::ToyEccSample& sample, const EducateAnalysisConfig& config, std::uint64_t seed)
        {
            ComponentCrack component;
            component.component = "Toy ECC (elliptic-curve discrete logarithm)";
            component.algorithm = "Shor (ECDLP)";

            ShorEcdlpOptions options;
            options.execution = primary(config);
            options.seed = seed;
            options.qubit_budget = config.budget.max_qubits;
            const ShorEcdlpResult shor = run_shor_ecdlp(sample.public_instance, options);

            component.inputs.emplace_back("Curve",
                "y^2 = x^3 + " + std::to_string(shor.coefficient_a) + "x + " + std::to_string(shor.coefficient_b) +
                " over F_" + std::to_string(shor.field_prime));
            component.inputs.emplace_back("Base point G",
                "(" + std::to_string(shor.base_x) + ", " + std::to_string(shor.base_y) + ")");
            component.inputs.emplace_back("Order of G", std::to_string(shor.base_point_order));
            component.inputs.emplace_back("Public point Q",
                "(" + std::to_string(shor.public_x) + ", " + std::to_string(shor.public_y) + ")");
            component.inputs.emplace_back("Ground-truth scalar k",
                std::to_string(sample.ground_truth.private_scalar));

            component.executed = shor.executed;
            component.cracked = shor.recovered;
            component.status = shor.status;
            component.real_crack_ms = shor.total_simulator_ms;
            if (shor.recovered)
            {
                component.recovered.emplace_back("Recovered scalar k", std::to_string(shor.recovered_scalar));
                component.recovered.emplace_back("Verified (k*G == Q)",
                    shor.recovered_scalar != 0U ? "YES" : "NO");
                component.recovered.emplace_back("Matches ground truth",
                    shor.recovered_scalar == sample.ground_truth.private_scalar ? "YES" : "NO");
            }
            component.resources.emplace_back("Register qubits", std::to_string(shor.register_qubits));
            component.resources.emplace_back("Total qubits (with control)", std::to_string(shor.total_qubits));
            component.resources.emplace_back("Phase bits per stage", std::to_string(shor.phase_bits));
            component.resources.emplace_back("Enumerated curve points", std::to_string(shor.point_table_size));
            component.resources.emplace_back("Controlled point additions (measured)",
                                             std::to_string(shor.controlled_point_additions));
            if (!shor.attempts.empty())
            {
                const ShorEcdlpAttempt& last = shor.attempts.back();
                component.resources.emplace_back("Measured phase y_G", std::to_string(last.phase_generator));
                component.resources.emplace_back("Measured phase y_Q", std::to_string(last.phase_public));
                component.resources.emplace_back("Phase-estimation shots", std::to_string(shor.attempts.size()));
            }

            if (shor.executed)
            {
                component.timings = measure_backends(config.measure_gpu, requested_gpu_backend(config),
                    [&](const quantum::QuantumExecutionOptions& execution)
                    {
                        return run_shor_ecdlp_single_circuit(
                            sample.public_instance, execution, seed, config.budget.max_qubits).simulator_ms;
                    });
            }
            return component;
        }

        // ---- RSA (Shor factoring) ------------------------------------------------------
        ComponentCrack crack_toy_rsa(
            const educational::ToyRsaSample& sample, const EducateAnalysisConfig& config, std::uint64_t seed)
        {
            ComponentCrack component;
            component.component = "Toy RSA (integer factoring)";
            component.algorithm = "Shor (factoring)";
            const std::uint64_t modulus = sample.public_instance.modulus;

            ShorFactoringOptions options;
            options.execution = primary(config);
            options.seed = seed;
            options.qubit_budget = config.budget.max_qubits;
            const ShorFactoringResult shor = run_shor_factoring(modulus, options);

            component.inputs.emplace_back("Public modulus N", std::to_string(modulus));
            component.inputs.emplace_back("Modulus bits", std::to_string(shor.modulus_bits));
            component.inputs.emplace_back("Public exponent e", std::to_string(sample.public_instance.public_exponent));
            component.inputs.emplace_back("Ground-truth factors p, q",
                std::to_string(sample.ground_truth.p) + ", " + std::to_string(sample.ground_truth.q));

            component.executed = shor.executed;
            component.cracked = shor.factored;
            component.status = shor.status;
            component.real_crack_ms = shor.total_simulator_ms;
            if (shor.factored)
            {
                component.recovered.emplace_back("Recovered factors",
                    std::to_string(shor.factor_p) + " x " + std::to_string(shor.factor_q));
                component.recovered.emplace_back("Product checks out",
                    shor.factor_p * shor.factor_q == modulus ? "YES" : "NO");
                component.recovered.emplace_back("Winning base a", std::to_string(shor.winning_base));
                component.recovered.emplace_back("Recovered order r", std::to_string(shor.recovered_order));
            }
            component.resources.emplace_back("Work qubits", std::to_string(shor.work_qubits));
            component.resources.emplace_back("Total qubits (with control)", std::to_string(shor.total_qubits));
            component.resources.emplace_back("Phase bits per run", std::to_string(shor.phase_bits));
            component.resources.emplace_back("Phase-estimation runs (attempts)", std::to_string(shor.attempts.size()));
            component.resources.emplace_back("Controlled modular multiplications (measured)",
                                             std::to_string(shor.controlled_modular_multiplications));

            if (shor.executed)
            {
                const std::uint64_t base = shor.winning_base != 0U ? shor.winning_base : 2U;
                component.timings = measure_backends(config.measure_gpu, requested_gpu_backend(config),
                    [&](const quantum::QuantumExecutionOptions& execution)
                    {
                        return run_shor_factoring_single_circuit(
                            modulus, base, execution, seed, config.budget.max_qubits).simulator_ms;
                    });
            }
            return component;
        }

        // ---- Module-LWE (custom Grover) ------------------------------------------------
        ComponentCrack crack_toy_mldsa(
            const educational::ToyLweSample& sample, const EducateAnalysisConfig& config, std::uint64_t seed)
        {
            ComponentCrack component;
            component.component = "Toy ML-DSA / Module-LWE (small-secret recovery)";
            component.algorithm = "Custom Grover secret search (not Shor)";

            QuantumAttackConfig attack_config;
            attack_config.execution = primary(config);
            attack_config.budget = config.budget;
            attack_config.seed = seed;
            const ToyModuleLweGroverAttack attack =
                attack_toy_module_lwe_with_grover(sample.public_instance, attack_config, seed);

            component.inputs.emplace_back("Ring", "Z_" + std::to_string(educational::ToyModuleQ) + "[x]/(x^" +
                std::to_string(educational::ToyModuleDegree) + " + 1)");
            component.inputs.emplace_back("Module rank k", std::to_string(educational::ToyModuleRank));
            component.inputs.emplace_back("Secret coefficients", "{-1, 0, 1}");
            component.inputs.emplace_back("Candidate space (3^(n*k))", std::to_string(attack.candidate_space));
            component.inputs.emplace_back("Ground-truth secret", lwe_vector_text(sample.ground_truth.secret));
            component.inputs.emplace_back("Public vector", lwe_public_text(sample.public_instance));

            component.executed = attack.executed;
            component.cracked = attack.secret_recovered;
            component.status = attack.status;
            component.real_crack_ms = attack.simulator_ms;
            if (attack.secret_recovered)
            {
                component.recovered.emplace_back("Recovered secret", lwe_vector_text(attack.recovered_secret));
                component.recovered.emplace_back("Matches ground truth",
                    attack.recovered_secret == sample.ground_truth.secret ? "YES" : "NO");
                component.recovered.emplace_back("Candidate index", std::to_string(attack.recovered_index));
            }
            component.resources.emplace_back("Search qubits", std::to_string(attack.search_qubits));
            component.resources.emplace_back("Marked candidates", std::to_string(attack.marked_candidates));
            component.resources.emplace_back("Grover iterations (oracle calls)", std::to_string(attack.grover_iterations));
            component.resources.emplace_back("Circuit runs", std::to_string(attack.circuit_runs));

            if (attack.executed)
            {
                component.timings = measure_backends(config.measure_gpu, requested_gpu_backend(config),
                    [&](const quantum::QuantumExecutionOptions& execution)
                    {
                        return run_toy_module_lwe_single_circuit(
                            sample.public_instance, execution, seed, config.budget.max_qubits).simulator_ms;
                    });
            }
            return component;
        }
    }

    EducateAnalysisReport run_educate_analysis(const std::string& plaintext, const EducateAnalysisConfig& config)
    {
        EducateAnalysisReport report;
        report.plaintext = plaintext;
        report.plaintext_empty = plaintext.empty();
        if (report.plaintext_empty)
        {
            report.report = "No sentence was entered. Nothing was encrypted or cracked.\n";
            return report;
        }

        const std::uint64_t root_seed = resolve_seed(config.seed);
        const std::size_t aes_bits = educational::ToySetAesUnknownKeyBits;

        const auto progress = [&](const std::string& message) { if (config.progress) config.progress(message); };
        const auto encrypt_dump = [&](SetCrack& set, const educational::ToyAesSample& aes, std::uint32_t digest)
        {
            set.encryption.emplace_back("Plaintext", printable(plaintext, 200U));
            set.encryption.emplace_back("Plaintext bytes", std::to_string(plaintext.size()));
            set.encryption.emplace_back("Toy SHA digest (" + std::to_string(config.toy_sha_bits) + " bits)",
                                        hex_value(digest, 4U));
            set.encryption.emplace_back("Toy AES unknown key bits", std::to_string(aes_bits));
            set.encryption.emplace_back("Ground-truth AES key", key_hex(aes.ground_truth.key));
            set.encryption.emplace_back("GCM nonce", hex_string(aes.public_instance.ciphertext.nonce));
            set.encryption.emplace_back("GCM tag", hex_string(aes.public_instance.ciphertext.tag));
            set.encryption.emplace_back("Ciphertext", hex_string(aes.public_instance.ciphertext.ciphertext));
        };

        const std::uint32_t digest = educational::truncated_sha256(plaintext, config.toy_sha_bits);

        // ---- Set 1: Toy-AES_Toy-SHA_Toy-ECDSA : Grover + Shor (ECDLP) ----
        {
            progress("Toy-AES_Toy-SHA_Toy-ECDSA: encrypting and cracking (Grover + Shor ECDLP)");
            const Stopwatch wall;
            SetCrack set;
            set.id = EducateSetId::AesShaEcdsa;
            set.name = "Toy-AES_Toy-SHA_Toy-ECDSA";
            set.disclaimer = "Toy elliptic curve over F_97; not real ECDSA or P-256.";
            const auto aes = educational::generate_toy_aes_sample(aes_bits, plaintext);
            const auto ecc = educational::generate_toy_ecc_sample();
            encrypt_dump(set, aes, digest);
            set.components.push_back(crack_toy_aes(aes, config, derive_seed(root_seed, "ecdsa/aes")));
            set.components.push_back(crack_toy_sha(plaintext, "CryptoProject EducateAnalysis ECDSA SHA:",
                                                   config.toy_sha_bits, config, derive_seed(root_seed, "ecdsa/sha")));
            set.components.push_back(crack_toy_ecc(ecc, config, derive_seed(root_seed, "ecdsa/ecc")));
            set.all_cracked = true;
            for (const auto& component : set.components) set.all_cracked = set.all_cracked && component.cracked;
            set.wall_ms = wall.elapsed_ms();
            report.sets.push_back(std::move(set));
        }

        // ---- Set 2: Toy-AES_Toy-SHA_Toy-RSAPSS : Grover + Shor (factoring) ----
        {
            progress("Toy-AES_Toy-SHA_Toy-RSAPSS: encrypting and cracking (Grover + Shor factoring)");
            const Stopwatch wall;
            SetCrack set;
            set.id = EducateSetId::AesShaRsaPss;
            set.name = "Toy-AES_Toy-SHA_Toy-RSAPSS";
            set.disclaimer = "Toy RSA modulus of " + std::to_string(config.rsa_modulus_bits) +
                " bits; not real RSA-PSS or RSA-2048.";
            const auto aes = educational::generate_toy_aes_sample(aes_bits, plaintext);
            const auto rsa = educational::generate_toy_rsa_sample(config.rsa_modulus_bits);
            encrypt_dump(set, aes, digest);
            set.components.push_back(crack_toy_aes(aes, config, derive_seed(root_seed, "rsapss/aes")));
            set.components.push_back(crack_toy_sha(plaintext, "CryptoProject EducateAnalysis RSAPSS SHA:",
                                                   config.toy_sha_bits, config, derive_seed(root_seed, "rsapss/sha")));
            set.components.push_back(crack_toy_rsa(rsa, config, derive_seed(root_seed, "rsapss/rsa")));
            set.all_cracked = true;
            for (const auto& component : set.components) set.all_cracked = set.all_cracked && component.cracked;
            set.wall_ms = wall.elapsed_ms();
            report.sets.push_back(std::move(set));
        }

        // ---- Set 3: Toy-AES_Toy-SHA_Toy-MLDSA : Grover + custom Grover (Module-LWE) ----
        {
            progress("Toy-AES_Toy-SHA_Toy-MLDSA: encrypting and cracking (Grover + custom Module-LWE Grover)");
            const Stopwatch wall;
            SetCrack set;
            set.id = EducateSetId::AesShaMlDsa;
            set.name = "Toy-AES_Toy-SHA_Toy-MLDSA";
            set.disclaimer = "Toy Module-LWE (n=4, k=2, q=257); not real ML-DSA (Dilithium).";
            const auto aes = educational::generate_toy_aes_sample(aes_bits, plaintext);
            const auto lwe = educational::generate_toy_lwe_sample();
            encrypt_dump(set, aes, digest);
            set.components.push_back(crack_toy_aes(aes, config, derive_seed(root_seed, "mldsa/aes")));
            set.components.push_back(crack_toy_sha(plaintext, "CryptoProject EducateAnalysis MLDSA SHA:",
                                                   config.toy_sha_bits, config, derive_seed(root_seed, "mldsa/sha")));
            set.components.push_back(crack_toy_mldsa(lwe, config, derive_seed(root_seed, "mldsa/lwe")));
            set.all_cracked = true;
            for (const auto& component : set.components) set.all_cracked = set.all_cracked && component.cracked;
            set.wall_ms = wall.elapsed_ms();
            report.sets.push_back(std::move(set));
        }

        report.report = format_educate_analysis_report(report);
        return report;
    }

    std::string format_educate_analysis_report(const EducateAnalysisReport& report)
    {
        if (report.plaintext_empty) return "No sentence was entered. Nothing was encrypted or cracked.\n";

        std::ostringstream out;
        out << kDoubleRule << '\n'
            << "EDUCATE ANALYSIS: REAL QUANTUM CRACK OF THE THREE TOY COMPOSITES\n"
            << kDoubleRule << '\n'
            << "Input sentence : " << printable(report.plaintext, 200U) << '\n'
            << "Every attack below is executed on the classical state-vector simulator (not an estimate),\n"
            << "and every recovered value is verified against the real toy instance. Parameters are\n"
            << "deliberately tiny teaching parameters; the crack times apply only to these toys, never to\n"
            << "AES-128, SHA-256, real ECDSA, RSA or ML-DSA.\n"
            << "Crack methods compared per component: Single CPU, Multithreaded CPU, GPU parallel.\n"
            << "(A GPU row shows UNAVAILABLE when no CUDA GPU backend is built; it is never replaced by CPU.)\n";

        for (const SetCrack& set : report.sets)
        {
            out << '\n' << kDoubleRule << '\n' << set.name << '\n' << kDoubleRule << '\n'
                << "Note: " << set.disclaimer << '\n'
                << "Overall: " << (set.all_cracked ? "ALL COMPONENTS CRACKED" : "NOT ALL COMPONENTS CRACKED")
                << "   (set wall time " << ms_text(set.wall_ms) << ")\n\n"
                << "[ENCRYPTION OF THE SENTENCE]\n";
            for (const auto& [name, value] : set.encryption) out << "    " << name << ": " << value << '\n';

            for (const ComponentCrack& component : set.components)
            {
                out << '\n' << kRule << '\n'
                    << "Component : " << component.component << '\n'
                    << "Algorithm : " << component.algorithm << '\n'
                    << "Executed  : " << (component.executed ? "YES (ran on the simulator)" : "NO")
                    << "   Cracked: " << (component.cracked ? "YES" : "NO") << '\n'
                    << "Status    : " << component.status << '\n';
                out << "Inputs (intermediate values):\n";
                for (const auto& [name, value] : component.inputs) out << "    " << name << ": " << value << '\n';
                out << "Recovered values:\n";
                if (component.recovered.empty()) out << "    (nothing recovered)\n";
                for (const auto& [name, value] : component.recovered) out << "    " << name << ": " << value << '\n';
                out << "Quantum circuit resources:\n";
                for (const auto& [name, value] : component.resources) out << "    " << name << ": " << value << '\n';
                out << "Crack time by execution method (state-vector simulation of one decisive circuit):\n";
                out << "    " << std::left << std::setw(22) << "Method" << std::setw(14) << "Available"
                    << "Simulator time\n";
                for (const BackendTiming& timing : component.timings)
                {
                    out << "    " << std::left << std::setw(22) << timing.method
                        << std::setw(14) << (timing.available ? "yes" : "no");
                    if (timing.executed) out << ms_text(timing.simulator_ms);
                    else out << (timing.note.empty() ? std::string("not run") : timing.note);
                    out << '\n';
                }
                out << "Real crack simulation wall time (the executed attack): "
                    << ms_text(component.real_crack_ms) << '\n';
            }
        }
        out << '\n' << kRule << '\n'
            << "The crack time by method is the state-vector SIMULATION time of one decisive circuit on a\n"
            << "classical computer. It is not the time a quantum computer would take. The sets are\n"
            << "independent and are not merged.\n";
        return out.str();
    }

    bool export_educate_analysis_report(
        const EducateAnalysisReport& report, const std::string& directory,
        std::string& report_path, std::string& csv_path)
    {
        try
        {
            std::filesystem::create_directories(directory);
            report_path = absolute_output_path(directory + "/educate_analysis_report.txt");
            csv_path = absolute_output_path(directory + "/educate_analysis_metrics.csv");
            {
                std::ofstream text(report_path, std::ios::out | std::ios::trunc);
                if (!text) return false;
                text << report.report;
                if (!text) return false;
            }
            {
                std::ofstream csv(csv_path, std::ios::out | std::ios::trunc);
                if (!csv) return false;
                csv << "set,component,algorithm,executed,cracked,real_crack_ms,"
                       "single_cpu_ms,multithreaded_cpu_ms,gpu_parallel_ms,gpu_status\n";
                for (const SetCrack& set : report.sets)
                {
                    for (const ComponentCrack& component : set.components)
                    {
                        const auto find = [&](const std::string& method) -> const BackendTiming*
                        {
                            for (const BackendTiming& timing : component.timings)
                                if (timing.method == method) return &timing;
                            return nullptr;
                        };
                        const auto cell = [](const BackendTiming* timing) -> std::string
                        {
                            if (timing == nullptr) return "N/A";
                            if (timing->executed)
                            {
                                std::ostringstream value;
                                value << std::setprecision(12) << timing->simulator_ms;
                                return value.str();
                            }
                            return timing->note.empty() ? "not run" : timing->note;
                        };
                        const BackendTiming* gpu = find("GPU parallel");
                        std::ostringstream real_ms;
                        real_ms << std::setprecision(12) << component.real_crack_ms;
                        csv << csv_field(set.name) << ',' << csv_field(component.component) << ','
                            << csv_field(component.algorithm) << ',' << (component.executed ? "YES" : "NO") << ','
                            << (component.cracked ? "YES" : "NO") << ',' << real_ms.str() << ','
                            << csv_field(cell(find("Single CPU"))) << ','
                            << csv_field(cell(find("Multithreaded CPU"))) << ','
                            << csv_field(gpu != nullptr && gpu->executed ? cell(gpu) : "N/A") << ','
                            << csv_field(gpu != nullptr ? (gpu->executed ? std::string("executed") : gpu->note) : std::string("not measured"))
                            << '\n';
                    }
                }
                if (!csv) return false;
            }
            return true;
        }
        catch (const std::exception&)
        {
            return false;
        }
    }
}
