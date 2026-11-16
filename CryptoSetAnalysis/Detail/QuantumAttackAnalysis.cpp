#include "QuantumAttackAnalysis.h"

#include "QuantumAttack/Standard/Algorithms/QuantumAlgorithms.h"
#include "QuantumAttack/Standard/Models/QuantumResourceModel.h"

#include <cmath>
#include <numbers>
#include <stdexcept>

namespace crypto::set_analysis::detail
{
    void attach_quantum_analysis(SetRunResult& result, const bool enabled)
    {
        // Grover is only demonstrated on a tiny toy search register. The full AES-128
        // estimate below is an ideal query-count model, not a simulated attack.
        result.quantum.grover_ideal_iterations = (std::numbers::pi_v<long double> / 4.0L) * std::ldexp(1.0L, 64);
        result.quantum.grover_time_at_one_microsecond_seconds =
            result.quantum.grover_ideal_iterations * 1.0e-6L;
        result.quantum.sha256_preimage_grover_iterations =
            (std::numbers::pi_v<long double> / 4.0L) * std::ldexp(1.0L, 128);
        result.quantum.sha256_preimage_grover_time_at_one_microsecond_seconds =
            result.quantum.sha256_preimage_grover_iterations * 1.0e-6L;

        if (result.id == SetId::AesShaEcdsa)
        {
            result.quantum.shor_applies_to_public_key_component = true;
            result.quantum.shor_target = "P-256 elliptic-curve discrete logarithm (ECDH and ECDSA)";
            result.quantum.shor_register_qubits =
                quantum::estimate_quantum_resources(quantum::CryptoTarget::ECC, 256U).estimated_register_qubits;
            result.quantum.qualification =
                "Grover estimate concerns only the shared AES-128 key search. Shor applies to the P-256 ECDLP in principle. "
                "The listed 769 qubits are a register-size illustration only; work ancillas, error correction and fault-tolerant overhead are excluded.";
        }
        else if (result.id == SetId::AesShaRsaPss)
        {
            result.quantum.shor_applies_to_public_key_component = true;
            result.quantum.shor_target = "RSA-" + std::to_string(result.public_key_parameter_bits) + " integer factorization (OAEP key transport and PSS signing key)";
            result.quantum.shor_register_qubits =
                quantum::estimate_quantum_resources(quantum::CryptoTarget::RSA, result.public_key_parameter_bits).estimated_register_qubits;
            result.quantum.qualification =
                "Grover estimate concerns only the shared AES-128 key search. Shor applies to RSA factorization in principle. "
                "The listed register count is a coarse register-size illustration, not a complete fault-tolerant circuit estimate.";
        }
        else
        {
            result.quantum.shor_applies_to_public_key_component = false;
            result.quantum.shor_target = "Not directly applicable: ML-KEM-768 is based on Module-LWE, not factoring or discrete logarithms";
            result.quantum.shor_register_qubits = 0U;
            result.quantum.qualification =
                "Grover estimate concerns only the AES-128 symmetric layer. The project's simple Grover model does not quantify attacks on Module-LWE; "
                "Shor's factoring/discrete-log algorithm is not a direct attack on ML-KEM-768. No ML-KEM break is claimed.";
        }

        if (!enabled) return;

        quantum::QuantumExecutionOptions options;
        options.backend = quantum::QuantumBackendType::CpuSingleThread;
        options.cpu_threads = 1U;

        try
        {
            const auto grover = quantum::run_grover_experiment(3U, 5U, 128U, options);
            result.quantum.grover_toy_simulator_ms = grover.elapsed_ms;
        }
        catch (const std::exception& exception)
        {
            result.quantum.qualification += std::string(" Grover toy simulator issue: ") + exception.what();
        }

        if (result.quantum.shor_applies_to_public_key_component)
        {
            try
            {
                const auto shor = quantum::run_shor_toy_experiment(15U, 2U, 128U, options);
                result.quantum.shor_toy_simulator_ms = shor.elapsed_ms;
                result.quantum.shor_toy_demo_passed = shor.factored;
                result.quantum.shor_toy_status = shor.status;
            }
            catch (const std::exception& exception)
            {
                result.quantum.shor_toy_status = std::string("ERROR: ") + exception.what();
            }
        }
        else
        {
            result.quantum.shor_toy_status = "NOT_APPLICABLE_TO_MODULE_LWE";
        }
    }
}
