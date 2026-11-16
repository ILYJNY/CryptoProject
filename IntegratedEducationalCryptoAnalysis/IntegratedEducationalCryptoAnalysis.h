#pragma once
#include "EducationalCryptoSetAnalysis/EducationalCryptoSetAnalysis.h"
#include <string>
#include <vector>
namespace crypto::integrated_educational {
struct Result { std::vector<educational_set_analysis::SetResult> sets; bool passed=false; double total_attack_ms=0.0; double total_generation_ms=0.0; std::string report; };
[[nodiscard]] Result run();
[[nodiscard]] bool export_result(const Result&, const std::string&, std::string&, std::string&);
}
