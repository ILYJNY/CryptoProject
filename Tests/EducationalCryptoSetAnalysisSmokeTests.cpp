#include "EducationalCryptoSetAnalysis/EducationalCryptoSetAnalysis.h"
#include "IntegratedEducationalCryptoAnalysis/IntegratedEducationalCryptoAnalysis.h"
#include <iostream>
int main(){
    const auto sets=crypto::educational_set_analysis::run_all_toy_sets();
    if(sets.size()!=3U) return 1;
    for(const auto& s:sets) {
        if(!s.passed || s.classical_attack_ms<0.0 || s.candidates==0U) return 2;
        if(s.backend_benchmark.output_bits!=16U ||
           s.backend_benchmark.single_attempts==0U ||
           s.backend_benchmark.multi_attempts==0U ||
           s.backend_benchmark.single_first.empty() ||
           s.backend_benchmark.multi_first.empty() ||
           s.backend_benchmark.single_cpu_ms<=0.0 ||
           s.backend_benchmark.multi_thread_cpu_ms<=0.0 ||
           !s.backend_benchmark.verified) return 5;
        if(s.backend_benchmark.gpu_available && (s.backend_benchmark.gpu_wall_ms<=0.0 || s.backend_benchmark.gpu_first.empty())) return 6;
    }
    const auto message_report=crypto::educational_set_analysis::run_custom_message_simulation("Hello");
    if(message_report.find("Toy SHA-derived ECC challenge:")==std::string::npos ||
       message_report.find("Toy SHA-derived RSA message representative:")==std::string::npos ||
       message_report.find("Toy SHA-derived Module-LWE KDF input:")==std::string::npos ||
       message_report.find("Plaintext recovered exactly: PASS")==std::string::npos ||
       message_report.find("Toy SHA is now consumed by every set:")==std::string::npos) return 8;
    const auto integrated=crypto::integrated_educational::run();
    if(!integrated.passed || integrated.sets.size()!=3U || integrated.total_attack_ms<0.0) return 3;
    if(integrated.report.find("INTEGRATED EDUCATIONAL CRYPTO ANALYSIS")==std::string::npos) return 4;
    if(integrated.report.find("Single CPU:")==std::string::npos ||
       integrated.report.find("Multi-thread CPU") == std::string::npos ||
       integrated.report.find("GPU Parallel:") == std::string::npos) return 7;
    std::cout<<"Educational crypto-set and integrated analysis tests passed.\n";
    return 0;
}
