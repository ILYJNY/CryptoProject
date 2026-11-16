#pragma once

#include "../Standard/Algorithms/QuantumAlgorithms.h"

#include <string>
#include <vector>

namespace crypto::quantum
{
    [[nodiscard]] std::string export_quantum_report(
        const std::vector<ExperimentResult>& experiments,
        const std::string& file_path = "Output/quantum_experiments.csv");
}
