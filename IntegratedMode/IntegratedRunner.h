#pragma once

#include <string>

namespace crypto::integrated
{
    struct IntegratedRunResult
    {
        bool passed = false;
        std::string report;
    };

    [[nodiscard]] IntegratedRunResult run_educational_integrated_demo();
}
