#pragma once

// Theory-only analyses of the public-key components of the educational sets.
//
// IMPORTANT: this release contains NO quantum circuit for these three components. The
// functions below do not run anything on the simulator and do not recover any secret.
// They report the real parameters of the instance, which algorithm corresponds to its
// mathematical problem, whether a circuit exists (it does not), and resource figures
// from published formulas where such formulas exist.
//
//   Toy ECC          - problem: elliptic-curve discrete logarithm. Corresponding algorithm:
//                      Shor (ECDLP). Circuit: NOT IMPLEMENTED. Resources: formula estimate.
//   Toy RSA          - problem: integer factoring. Corresponding algorithm: Shor (order
//                      finding). Circuit for the real modulus: NOT IMPLEMENTED. Resources:
//                      formula estimate. The existing N = 15 experiment is run as a
//                      separate algorithm-validation experiment and is never presented as
//                      an attack on the real modulus.
//   Toy Module-LWE   - problem: Module-LWE. Shor does not apply. No circuit-level model
//                      exists in this project: NOT MODELED, no qubit or time figures.

#include "EducationalQuantumAttack/Common/QuantumAttackTypes.h"

#include "CryptoSystem/Educational/ECC/ToyECC.h"
#include "CryptoSystem/Educational/ModuleLWE/ToyModuleLWE.h"
#include "CryptoSystem/Educational/RSA/ToyRSA.h"

namespace crypto::educational_quantum_attack
{
    [[nodiscard]] AttackResult analyze_toy_ecc_shor_theory(
        const educational::ToyEccPublicInstance& instance,
        const QuantumAttackConfig& config);

    [[nodiscard]] AttackResult analyze_toy_rsa_shor_theory(
        const educational::ToyRsaPublicInstance& instance,
        const QuantumAttackConfig& config);

    [[nodiscard]] AttackResult analyze_toy_module_lwe_not_modeled(
        const educational::ToyLwePublicInstance& instance,
        const QuantumAttackConfig& config);
}
