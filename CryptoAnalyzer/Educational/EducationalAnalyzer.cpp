#include "EducationalAnalyzer.h"

#include "Logger/Logger.h"
#include "PerformanceMonitor/PerformanceMonitor.h"

#include <filesystem>

namespace crypto::analyzer
{
    namespace
    {
        PerformanceMonitor& analyzer_monitor()
        {
            static PerformanceMonitor monitor;
            return monitor;
        }

        void export_performance()
        {
            std::filesystem::create_directories("Output");
            analyzer_monitor().export_csv("Output/educational_analyzer_performance.csv");
            analyzer_monitor().export_summary_csv("Output/educational_analyzer_performance_summary.csv");
        }
    }

    educational::ToyRsaAnalysis EducationalAnalyzer::analyze(
        const educational::ToyRsaPublicInstance& instance)
    {
        educational::ToyRsaAnalysis result;
        analyzer_monitor().measure("Analyzer.Educational.ToyRSA", "CPU", [&]()
        {
            result = educational::analyze_toy_rsa(instance);
        });
        export_performance();
        return result;
    }

    educational::ToyEccAnalysis EducationalAnalyzer::analyze(
        const educational::ToyEccPublicInstance& instance)
    {
        educational::ToyEccAnalysis result;
        analyzer_monitor().measure("Analyzer.Educational.ToyECC", "CPU", [&]()
        {
            result = educational::analyze_toy_ecc(instance);
        });
        export_performance();
        return result;
    }

    educational::ToyAesAnalysis EducationalAnalyzer::analyze(
        const educational::ToyAesPublicInstance& instance)
    {
        educational::ToyAesAnalysis result;
        analyzer_monitor().measure("Analyzer.Educational.ToyAES", "CPU", [&]()
        {
            result = educational::analyze_toy_aes(instance);
        });
        export_performance();
        return result;
    }

    educational::ToyLweAnalysis EducationalAnalyzer::analyze(
        const educational::ToyLwePublicInstance& instance)
    {
        educational::ToyLweAnalysis result;
        analyzer_monitor().measure("Analyzer.Educational.ToyModuleLWE", "CPU", [&]()
        {
            result = educational::analyze_toy_lwe(instance);
        });
        export_performance();
        return result;
    }
}
