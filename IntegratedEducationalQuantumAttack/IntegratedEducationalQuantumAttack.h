#pragma once

// IntegratedEducationalQuantumAttack - integrated quantum-attack analysis (CryptoProject 2.3.5).
//
// This module runs the three INDEPENDENT quantum-attack analyses of EducationalQuantumAttack
// and gathers their results in one place for comparison. It does not merge the three
// cryptosystems, it is not the classical IntegratedEducationalCryptoAnalysis, and it does
// not turn the separate estimates into one "time to break everything".

#include "IntegratedEducationalQuantumAttack/QuantumAttackComparison.h"

#include "EducationalQuantumAttack/Common/QuantumAttackTypes.h"

#include <string>
#include <string_view>
#include <vector>

namespace crypto::integrated_educational_quantum_attack
{
    inline constexpr std::string_view DefaultIntegratedOutputDirectory = "Output/IntegratedEducationalQuantumAttack";

    struct IntegratedResult
    {
        std::vector<eqa::SetAttackReport> sets;
        Comparison comparison;

        // FAILED as soon as one executed attack of any set failed; ALL SUCCEEDED only when
        // every attack of every set was executed and succeeded; PARTIAL otherwise.
        eqa::SetStatus status = eqa::SetStatus::Partial;
        bool any_failure = false;

        double wall_ms = 0.0;       // wall time of the whole integrated analysis
        std::string report;
    };

    // Generates one instance per set, runs the three independent analyses and integrates them.
    [[nodiscard]] IntegratedResult run(
        const std::string& plaintext, const eqa::QuantumAttackConfig& config = {});

    // Integrates set reports that already exist. No attack is run.
    [[nodiscard]] IntegratedResult integrate(std::vector<eqa::SetAttackReport> sets, double wall_ms = 0.0);

    [[nodiscard]] std::string format_integrated_report(const IntegratedResult& result);
}
