#pragma once

#include "ECC/ToyECC.h"
#include "AES/ToyAESKeySearch.h"
#include "ModuleLWE/ToyModuleLWE.h"
#include "RSA/ToyRSA.h"

namespace crypto::analyzer
{
    class EducationalAnalyzer final
    {
    public:
        [[nodiscard]] static educational::ToyRsaAnalysis analyze(
            const educational::ToyRsaPublicInstance& instance);
        [[nodiscard]] static educational::ToyEccAnalysis analyze(
            const educational::ToyEccPublicInstance& instance);
        [[nodiscard]] static educational::ToyAesAnalysis analyze(
            const educational::ToyAesPublicInstance& instance);
        [[nodiscard]] static educational::ToyLweAnalysis analyze(
            const educational::ToyLwePublicInstance& instance);
    };
}
