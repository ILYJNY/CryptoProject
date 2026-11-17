#pragma once

// File export of the integrated quantum-attack analysis.

#include "IntegratedEducationalQuantumAttack/IntegratedEducationalQuantumAttack.h"

#include <string>

namespace crypto::integrated_educational_quantum_attack
{
    struct IntegratedExportedFiles
    {
        std::string report;             // integrated_quantum_report.txt
        std::string metrics_csv;        // integrated_quantum_metrics.csv   (aggregates)
        std::string comparison_csv;     // quantum_attack_comparison.csv    (one row per attack)
        std::string metrics_json;       // integrated_quantum_metrics.json  (full per-attack detail)
    };

    // Writes the four files into `directory`. Returns false if any file cannot be written.
    [[nodiscard]] bool export_integrated_result(
        const IntegratedResult& result, const std::string& directory, IntegratedExportedFiles& files);
}
