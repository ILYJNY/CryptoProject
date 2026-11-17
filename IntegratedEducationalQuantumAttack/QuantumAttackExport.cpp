#include "QuantumAttackExport.h"

#include "EducationalQuantumAttack/Common/QuantumAttackReport.h"

#include <filesystem>
#include <fstream>

namespace crypto::integrated_educational_quantum_attack
{
    namespace
    {
        [[nodiscard]] bool write_file(const std::string& path, const std::string& content)
        {
            std::ofstream output(path, std::ios::out | std::ios::trunc);
            if (!output) return false;
            output << content;
            return static_cast<bool>(output);
        }
    }

    bool export_integrated_result(
        const IntegratedResult& result, const std::string& directory, IntegratedExportedFiles& files)
    {
        try
        {
            std::filesystem::create_directories(directory);
            const auto abs = [](const std::string& path)
            {
                try { return std::filesystem::weakly_canonical(std::filesystem::absolute(path)).string(); }
                catch (const std::exception&) { return path; }
            };
            files.report = abs(directory + "/integrated_quantum_report.txt");
            files.metrics_csv = abs(directory + "/integrated_quantum_metrics.csv");
            files.comparison_csv = abs(directory + "/quantum_attack_comparison.csv");
            files.metrics_json = abs(directory + "/integrated_quantum_metrics.json");
            return write_file(files.report, result.report) &&
                   write_file(files.metrics_csv, aggregate_metrics_csv(result.comparison, result.status)) &&
                   write_file(files.comparison_csv, comparison_csv(result.comparison)) &&
                   write_file(files.metrics_json, eqa::metrics_json(result.sets));
        }
        catch (const std::exception&)
        {
            return false;
        }
    }
}
