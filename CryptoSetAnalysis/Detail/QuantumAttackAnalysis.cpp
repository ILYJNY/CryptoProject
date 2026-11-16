#include "QuantumAttackAnalysis.h"
#include "AttackTimeModel.h"

#include "QuantumAttack/Standard/Algorithms/QuantumAlgorithms.h"
#include "QuantumAttack/Standard/Models/QuantumResourceModel.h"

#include <cmath>
#include <numbers>
#include <stdexcept>

namespace crypto::set_analysis::detail
{
    void attach_quantum_analysis(SetRunResult& result, const bool enabled)
    {
        using namespace attack_time_model;

        // Grover estimates use an explicit scenario rate. They are not hardware measurements.
        result.quantum.grover_ideal_iterations =
            (std::numbers::pi_v<long double> / 4.0L) * std::ldexp(1.0L, 64);
        result.quantum.grover_time_at_one_microsecond_seconds =
            result.quantum.grover_ideal_iterations * kSecondsPerGroverOracleIteration;
        result.quantum.sha256_preimage_grover_iterations =
            (std::numbers::pi_v<long double> / 4.0L) * std::ldexp(1.0L, 128);
        result.quantum.sha256_preimage_grover_time_at_one_microsecond_seconds =
            result.quantum.sha256_preimage_grover_iterations * kSecondsPerGroverOracleIteration;

        if (result.id == SetId::AesShaEcdsa)
        {
            result.quantum.shor_applies_to_public_key_component = true;
            result.quantum.shor_target = "P-256 elliptic-curve discrete logarithm (ECDH and ECDSA)";
            result.quantum.shor_register_qubits =
                quantum::estimate_quantum_resources(quantum::CryptoTarget::ECC, 256U).estimated_register_qubits;
            result.quantum.shor_toffoli_gates_estimate = estimate_ecc_shor_toffoli_gates(256U);
            result.quantum.qualification =
                "Shor's P-256 gate estimate uses the Roetteler et al. ECDLP Toffoli-count model. "
                "The attack-time figure serializes the estimated Toffoli gates at the scenario rate; it is not a fault-tolerant hardware forecast.";
        }
        else if (result.id == SetId::AesShaRsaPss)
        {
            result.quantum.shor_applies_to_public_key_component = true;
            result.quantum.shor_target = "RSA-" + std::to_string(result.public_key_parameter_bits) +
                " integer factorization (OAEP key transport and PSS signing key)";
            result.quantum.shor_register_qubits =
                quantum::estimate_quantum_resources(quantum::CryptoTarget::RSA,
                    result.public_key_parameter_bits).estimated_register_qubits;
            result.quantum.shor_toffoli_gates_estimate =
                estimate_rsa_shor_toffoli_gates(result.public_key_parameter_bits);
            result.quantum.qualification =
                "Shor's RSA gate estimate uses an interpolation model for the Toffoli count. "
                "The attack-time figure serializes the estimated Toffoli gates at the scenario rate; it is not a fault-tolerant hardware forecast.";
        }
        else
        {
            result.quantum.shor_applies_to_public_key_component = false;
            result.quantum.shor_target =
                "Not directly applicable: ML-KEM-768 is based on Module-LWE, not factoring or discrete logarithms";
            result.quantum.shor_register_qubits = 0U;
            result.quantum.shor_toffoli_gates_estimate = 0.0L;
            result.quantum.qualification =
                "The Module-LWE attack cost is not modeled by this project. The displayed AES/SHA Grover figures concern only the symmetric/hash components "
                "and cannot be interpreted as the time to break ML-KEM-768 itself.";
        }

        if (result.quantum.shor_applies_to_public_key_component)
        {
            result.quantum.shor_attack_time_at_one_microsecond_per_toffoli_seconds =
                result.quantum.shor_toffoli_gates_estimate * kSecondsPerSerialToffoliGate;
        }

        // Fastest *quantified direct component path*. For ML-KEM this deliberately excludes
        // the Module-LWE core, so it is not a whole-set break-time estimate.
        result.quantum.fastest_quantified_attack = "Grover on AES-128 key";
        result.quantum.fastest_quantified_attack_seconds =
            result.quantum.grover_time_at_one_microsecond_seconds;
        if (result.quantum.shor_applies_to_public_key_component &&
            result.quantum.shor_attack_time_at_one_microsecond_per_toffoli_seconds <
                result.quantum.fastest_quantified_attack_seconds)
        {
            result.quantum.fastest_quantified_attack = "Shor on public-key component";
            result.quantum.fastest_quantified_attack_seconds =
                result.quantum.shor_attack_time_at_one_microsecond_per_toffoli_seconds;
        }
        result.quantum.fastest_quantified_attack_is_complete_for_set =
            result.id != SetId::ShaAesMlKem;
        result.quantum.attack_time_scope = result.id == SetId::ShaAesMlKem
            ? "Component-only estimate; the Module-LWE core attack time is not modeled, so no complete ML-KEM set break time is claimed."
            : "Fastest among the modeled AES-128 Grover and public-key Shor component paths under the stated scenario rates.";

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
