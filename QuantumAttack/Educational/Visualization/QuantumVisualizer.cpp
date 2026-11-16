#include "QuantumVisualizer.h"

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <sstream>

namespace crypto::quantum::educational
{
    std::string render_probability_bars(
        const std::vector<double>& probabilities,
        const std::size_t maximum_rows,
        const std::size_t bar_width)
    {
        std::ostringstream output;
        if (probabilities.empty()) return "(empty probability distribution)\n";
        const std::size_t rows = std::min(probabilities.size(), maximum_rows);
        for (std::size_t index = 0; index < rows; ++index)
        {
            const std::size_t width = static_cast<std::size_t>(
                std::llround(std::clamp(probabilities[index], 0.0, 1.0) * static_cast<double>(bar_width)));
            output << '|' << index << "> " << std::string(width, '#')
                   << std::string(bar_width - width, ' ') << ' '
                   << std::fixed << std::setprecision(4) << probabilities[index] << '\n';
        }
        if (probabilities.size() > rows)
            output << "... " << (probabilities.size() - rows) << " additional states omitted\n";
        return output.str();
    }
}
