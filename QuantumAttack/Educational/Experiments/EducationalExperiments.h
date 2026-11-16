#pragma once

#include "../../Standard/Algorithms/QuantumAlgorithms.h"

#include <string>
#include <vector>

namespace crypto::quantum::educational
{
    [[nodiscard]] std::vector<ExperimentResult> run_all_experiments(const QuantumExecutionOptions& options = {});
    [[nodiscard]] std::string run_all_experiments_text(const QuantumExecutionOptions& options = {});
}
