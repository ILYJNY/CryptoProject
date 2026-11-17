#pragma once

// EducationalQuantumAttack - independent quantum-attack analysis of the three educational
// cryptosystem sets (CryptoProject 2.3.5).
//
// This module is separate from EducationalCryptoSetAnalysis (classical analysis) and from
// the QuantumAttack library. QuantumAttack is the engine: a classical state-vector
// simulator. This module is the analysis system built on top of it: it takes the real toy
// parameters of each set, matches every component with the quantum algorithm that fits its
// mathematical problem, runs the circuits that are implemented, and reports honestly
// which ones are not.
//
//   Component          Problem                    Algorithm            Status in 2.3.5
//   Toy AES            unstructured key search    Grover               circuit simulated
//   Toy SHA preimage   preimage search            Grover               circuit simulated
//   Toy SHA collision  collision search           Brassard-Hoyer-Tapp  circuit simulated
//   Toy ECC            elliptic-curve dlog        Shor (ECDLP)         theory only, circuit not implemented
//   Toy RSA            integer factoring          Shor (factoring)     theory only, circuit not implemented
//   Toy Module-LWE     Module-LWE                 none (never Shor)    NOT MODELED
//
// The three sets stay independent: each has its own instance and its own report.

#include "EducationalQuantumAttack/Common/QuantumAttackReport.h"
#include "EducationalQuantumAttack/Common/QuantumAttackTypes.h"
#include "EducationalQuantumAttack/MessageCrack.h"
#include "EducationalQuantumAttack/EducateAnalysis.h"
#include "EducationalQuantumAttack/Sets/AesShaEcdsaQuantumAttack.h"
#include "EducationalQuantumAttack/Sets/AesShaRsaPssQuantumAttack.h"
#include "EducationalQuantumAttack/Sets/ShaAesMlKemQuantumAttack.h"

#include <string>
#include <string_view>
#include <vector>

namespace crypto::educational_quantum_attack
{
    inline constexpr std::string_view DefaultQuantumAttackMessage = "Educational quantum attack demonstration.";
    inline constexpr std::string_view DefaultQuantumAttackOutputDirectory = "Output/EducationalQuantumAttack";

    // Generates a fresh instance of each set for `plaintext` (the default message when it is
    // empty) and analyzes the three sets one after another, independently.
    [[nodiscard]] std::vector<SetAttackReport> run_all_quantum_attacks(
        const std::string& plaintext, const QuantumAttackConfig& config = {});

    // Convenience wrappers that generate the instance and analyze one set.
    [[nodiscard]] SetAttackReport run_aes_sha_ecdsa_quantum_attack(
        const std::string& plaintext, const QuantumAttackConfig& config = {});
    [[nodiscard]] SetAttackReport run_aes_sha_rsapss_quantum_attack(
        const std::string& plaintext, const QuantumAttackConfig& config = {});
    [[nodiscard]] SetAttackReport run_sha_aes_mlkem_quantum_attack(
        const std::string& plaintext, const QuantumAttackConfig& config = {});
}
