#pragma once

// Text, CSV and JSON rendering of quantum-attack reports.
//
// Rendering rules:
//   - a value that does not exist is written as NOT MODELED / NOT EXECUTED / N/A / UNKNOWN,
//     never as 0;
//   - the three time categories are printed under separate labels and never summed;
//   - every CSV column name carries its unit, and every numeric column has a companion
//     "_kind" column that says whether the value was measured, computed or estimated.

#include "QuantumAttackTypes.h"

#include <string>
#include <vector>

namespace crypto::educational_quantum_attack
{
    [[nodiscard]] std::string format_attack_report(const AttackResult& attack);
    [[nodiscard]] std::string format_set_report(const SetAttackReport& report);
    // One line per attack: target, algorithm, execution status and outcome.
    [[nodiscard]] std::string format_set_overview(const std::vector<SetAttackReport>& reports);

    [[nodiscard]] std::string metrics_csv_header();
    [[nodiscard]] std::string metrics_csv_row(const SetAttackReport& set, const AttackResult& attack);
    [[nodiscard]] std::string metrics_csv(const std::vector<SetAttackReport>& reports);
    [[nodiscard]] std::string metrics_json(const std::vector<SetAttackReport>& reports);

    // Escapes one CSV field (quotes it when it contains a comma, a quote or a line break).
    [[nodiscard]] std::string csv_field(const std::string& value);
    [[nodiscard]] std::string json_string(const std::string& value);

    struct ExportedFiles
    {
        std::vector<std::string> set_reports;   // one text report per set
        std::string metrics_csv;
        std::string metrics_json;
    };

    // Writes <set>_quantum_report.txt for every set plus quantum_attack_metrics.csv and
    // quantum_attack_metrics.json into `directory`. Returns false if any file fails.
    [[nodiscard]] bool export_quantum_attack_reports(
        const std::vector<SetAttackReport>& reports,
        const std::string& directory,
        ExportedFiles& files);
}
