#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace crypto::quantum::educational
{
    [[nodiscard]] std::string render_probability_bars(
        const std::vector<double>& probabilities,
        std::size_t maximum_rows = 16U,
        std::size_t bar_width = 32U);
}
