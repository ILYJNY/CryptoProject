#include "EducationalCryptoSetAnalysis.h"
#include "CryptoSystem/Educational/RSA/ToyRSA.h"
#include "CryptoSystem/Educational/ECC/ToyECC.h"
#include "CryptoSystem/Educational/ModuleLWE/ToyModuleLWE.h"
#include "CryptoSystem/Educational/AES/ToyAESKeySearch.h"
#include "CryptoSystem/Educational/SHA/ToySha256.h"
#include "CryptoSystem/Standard/AES/AES128GCM.h"
#include "CryptoAnalyzer/Educational/EducationalAnalyzer.h"
#include "QuantumAttack/Standard/Algorithms/QuantumAlgorithms.h"
#include "ComputeEngine/ComputeEngine.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_map>

namespace crypto::educational_set_analysis {
namespace {
using Clock=std::chrono::steady_clock;
constexpr std::size_t kToyShaBits=16U;
constexpr std::uint64_t kMaxAttempts=200000U;
constexpr const char* kPrefix="CryptoProject truncated SHA-256 demo:";
template<class F> double timed(F&& f){auto a=Clock::now();f();return std::chrono::duration<double,std::milli>(Clock::now()-a).count();}
std::string input(std::uint32_t n){return std::string(kPrefix)+std::to_string(n);}
std::string duration(double s){std::ostringstream o;o<<std::setprecision(4);if(!std::isfinite(s))return "NOT ESTIMABLE";if(s<1e-6)o<<s*1e9<<" ns";else if(s<1)o<<s*1e3<<" ms";else if(s<3600)o<<s<<" s";else if(s<86400)o<<s/3600<<" h";else o<<s/86400<<" days";return o.str();}
struct Found {bool ok=false;std::uint32_t a=0,b=0,d=0;std::uint64_t attempts=0;};
Found single_search(){std::unordered_map<std::uint32_t,std::uint32_t> seen;seen.reserve(1U<<kToyShaBits);for(std::uint32_t i=0;i<kMaxAttempts;++i){auto d=educational::truncated_sha256(input(i),kToyShaBits);auto [it,inserted]=seen.emplace(d,i);if(!inserted)return {true,it->second,i,d,static_cast<std::uint64_t>(i)+1U};}return {false,0,0,0,kMaxAttempts};}
Found multi_search(std::size_t workers){std::unordered_map<std::uint32_t,std::uint32_t> seen;seen.reserve(1U<<kToyShaBits);std::mutex m;std::atomic<bool> stop{false};std::atomic<std::uint64_t> count{0};Found result;std::vector<std::thread> ts;workers=std::max<std::size_t>(1,workers);for(std::size_t w=0;w<workers;++w)ts.emplace_back([&,w]{for(std::uint64_t i=w;i<kMaxAttempts&&!stop.load(std::memory_order_relaxed);i+=workers){auto d=educational::truncated_sha256(input(static_cast<std::uint32_t>(i)),kToyShaBits);count.fetch_add(1,std::memory_order_relaxed);std::lock_guard<std::mutex> lock(m);auto [it,inserted]=seen.emplace(d,static_cast<std::uint32_t>(i));if(!inserted&&!stop.exchange(true)){result={true,it->second,static_cast<std::uint32_t>(i),d,0};}}});for(auto& t:ts)t.join();result.attempts=count.load();return result;}
BackendBenchmark benchmark_toy_sha(){BackendBenchmark b;b.output_bits=kToyShaBits;b.maximum_attempts=kMaxAttempts;b.cpu_threads=std::max(1U,std::thread::hardware_concurrency());Found s,m;b.single_cpu_ms=timed([&]{s=single_search();});b.multi_thread_cpu_ms=timed([&]{m=multi_search(b.cpu_threads);});b.single_attempts=s.attempts;b.multi_attempts=m.attempts;b.single_digest=s.d;b.multi_digest=m.d;if(s.ok){b.single_first=input(s.a);b.single_second=input(s.b);}if(m.ok){b.multi_first=input(m.a);b.multi_second=input(m.b);}bool valid=s.ok&&m.ok&&educational::truncated_sha256(b.single_first,kToyShaBits)==s.d&&educational::truncated_sha256(b.single_second,kToyShaBits)==s.d&&educational::truncated_sha256(b.multi_first,kToyShaBits)==m.d&&educational::truncated_sha256(b.multi_second,kToyShaBits)==m.d;
 const auto devices=ComputeEngine::discover_gpus();if(devices.empty()){b.gpu_status=ComputeEngine::cuda_compiled()?"UNAVAILABLE (no CUDA-capable GPU detected)":"UNAVAILABLE (project built without CUDA)";b.verified=valid;return b;}
 try{ComputeOptions options;options.backend=ComputeBackend::Gpu;ComputeEngine engine(options);std::unordered_map<std::uint32_t,std::uint32_t> seen;seen.reserve(1U<<kToyShaBits);std::uint64_t next=0;bool found=false;Sha256BatchReport report;b.gpu_wall_ms=timed([&]{while(next<kMaxAttempts&&!found){const std::size_t n=static_cast<std::size_t>(std::min<std::uint64_t>(4096U,kMaxAttempts-next));std::vector<std::string> msgs;msgs.reserve(n);for(std::size_t j=0;j<n;++j)msgs.push_back(input(static_cast<std::uint32_t>(next+j)));auto digests=engine.sha256_short_batch(msgs,&report);if(report.execution.actual_backend!=ComputeBackend::Gpu&&report.execution.actual_backend!=ComputeBackend::MultiGpu)break;for(std::size_t j=0;j<n;++j){const auto& h=digests[j];std::uint32_t top=(static_cast<std::uint32_t>(h[0])<<16U)|(static_cast<std::uint32_t>(h[1])<<8U)|h[2];auto d=top>>(24U-kToyShaBits);auto [it,inserted]=seen.emplace(d,static_cast<std::uint32_t>(next+j));if(!inserted){b.gpu_first=input(it->second);b.gpu_second=input(static_cast<std::uint32_t>(next+j));b.gpu_digest=d;b.gpu_attempts=next+j+1U;found=true;break;}}next+=n;}});b.gpu_available=report.execution.actual_backend==ComputeBackend::Gpu||report.execution.actual_backend==ComputeBackend::MultiGpu;if(b.gpu_available){b.gpu_status="AVAILABLE";b.gpu_device=devices.front().name;b.gpu_kernel_ms=report.execution.gpu_kernel_time_ms;b.gpu_transfer_ms=report.execution.gpu_transfer_time_ms;valid=valid&&found&&educational::truncated_sha256(b.gpu_first,kToyShaBits)==b.gpu_digest&&educational::truncated_sha256(b.gpu_second,kToyShaBits)==b.gpu_digest;}else b.gpu_status="UNAVAILABLE (CUDA execution did not start)";}catch(const std::exception&e){b.gpu_status=std::string("UNAVAILABLE: ")+e.what();}b.verified=valid;return b;}
void add_quantum(SetResult&r){auto g=quantum::run_grover_experiment(4U,7U,512U);r.grover_simulator_ms=g.elapsed_ms;auto s=quantum::run_shor_toy_experiment(15U,2U,512U);r.shor_simulator_ms=s.elapsed_ms;r.estimated_grover_seconds=std::sqrt(std::pow(2.0,128.0))*1e-6;r.estimated_shor_seconds=std::numeric_limits<double>::infinity();}
void add_sha(SetResult&r){r.backend_benchmark=benchmark_toy_sha();r.passed=r.passed&&r.backend_benchmark.verified;}
std::string backend_text(const BackendBenchmark&b){std::ostringstream o;o<<"[TOY SHA-256 TRUNCATED COLLISION SEARCH: "<<b.output_bits<<" bits]\n"<<"Maximum candidates: "<<b.maximum_attempts<<"\n"<<"Single CPU: "<<b.single_cpu_ms<<" ms | attempts="<<b.single_attempts<<" | collision="<<(b.single_first.empty()?"NOT FOUND":b.single_first+" <> "+b.single_second)<<" | digest="<<b.single_digest<<"\n"<<"Multi-thread CPU ("<<b.cpu_threads<<" threads): "<<b.multi_thread_cpu_ms<<" ms | attempts="<<b.multi_attempts<<" | collision="<<(b.multi_first.empty()?"NOT FOUND":b.multi_first+" <> "+b.multi_second)<<" | digest="<<b.multi_digest<<"\n"<<"GPU Parallel: "<<b.gpu_status;if(b.gpu_available)o<<" | device="<<b.gpu_device<<" | wall="<<b.gpu_wall_ms<<" ms | kernel="<<b.gpu_kernel_ms<<" ms | transfer="<<b.gpu_transfer_ms<<" ms | attempts="<<b.gpu_attempts<<" | collision="<<b.gpu_first<<" <> "<<b.gpu_second<<" | digest="<<b.gpu_digest;o<<"\nCollision verification: "<<(b.verified?"PASS":"FAIL")<<"\n";return o.str();}
}
SetResult run_toy_aes_sha_ecdsa(){SetResult r;r.name="Educational AES-SHA-ECDSA";r.key_exchange="Toy elliptic-curve discrete-log analogue";educational::ToyEccSample ec;educational::ToyAesSample aes;r.generation_ms=timed([&]{ec=educational::generate_toy_ecc_sample();aes=educational::generate_toy_aes_sample(12U);});auto t=Clock::now();auto er=analyzer::EducationalAnalyzer::analyze(ec.public_instance);auto ar=analyzer::EducationalAnalyzer::analyze(aes.public_instance);r.classical_attack_ms=std::chrono::duration<double,std::milli>(Clock::now()-t).count();r.candidates=static_cast<std::uint64_t>(er.attempts)+ar.candidates_tested;r.passed=er.success&&er.recovered_scalar==ec.ground_truth.private_scalar&&ar.success&&ar.recovered_key==aes.ground_truth.key;r.estimated_classical_seconds=r.classical_attack_ms/1000.;r.attack_note="Toy ECC scalar search and 12-bit restricted AES keyspace; not ECDSA/P-256 or AES-128 security.";add_quantum(r);add_sha(r);return r;}
SetResult run_toy_aes_sha_rsapss(){SetResult r;r.name="Educational AES-SHA-RSAPSS";r.key_exchange="Toy RSA factorization / key recovery";educational::ToyRsaSample rsa;educational::ToyAesSample aes;r.generation_ms=timed([&]{rsa=educational::generate_toy_rsa_sample(24U);aes=educational::generate_toy_aes_sample(12U);});auto t=Clock::now();auto rr=analyzer::EducationalAnalyzer::analyze(rsa.public_instance);auto ar=analyzer::EducationalAnalyzer::analyze(aes.public_instance);r.classical_attack_ms=std::chrono::duration<double,std::milli>(Clock::now()-t).count();r.candidates=rr.trial_divisions+ar.candidates_tested;r.passed=rr.success&&rr.recovered_plaintext==rsa.ground_truth.plaintext&&ar.success&&ar.recovered_key==aes.ground_truth.key;r.estimated_classical_seconds=r.classical_attack_ms/1000.;r.attack_note="Toy RSA modulus (24-bit) factorization and 12-bit restricted AES keyspace; not RSA-PSS/RSA-2048 security.";add_quantum(r);add_sha(r);return r;}
SetResult run_toy_sha_aes_mlkem(){SetResult r;r.name="Educational SHA-AES-MLKEM";r.key_exchange="Toy Module-LWE secret recovery";educational::ToyLweSample lwe;educational::ToyAesSample aes;r.generation_ms=timed([&]{lwe=educational::generate_toy_lwe_sample();aes=educational::generate_toy_aes_sample(12U);});auto t=Clock::now();auto lr=analyzer::EducationalAnalyzer::analyze(lwe.public_instance);auto ar=analyzer::EducationalAnalyzer::analyze(aes.public_instance);r.classical_attack_ms=std::chrono::duration<double,std::milli>(Clock::now()-t).count();r.candidates=lr.candidates_tested+ar.candidates_tested;r.passed=lr.success&&lr.recovered_secret==lwe.ground_truth.secret&&ar.success&&ar.recovered_key==aes.ground_truth.key;r.estimated_classical_seconds=r.classical_attack_ms/1000.;r.attack_note="Toy Module-LWE (n=4,k=2,q=257) and 12-bit restricted AES keyspace; not ML-KEM-768. No validated Module-LWE quantum attack-time model is included.";add_quantum(r);add_sha(r);return r;}
std::vector<SetResult> run_all_toy_sets(){return {run_toy_aes_sha_ecdsa(),run_toy_aes_sha_rsapss(),run_toy_sha_aes_mlkem()};}

namespace {
std::uint64_t toy_mod_pow(std::uint64_t base, std::uint64_t exponent, const std::uint64_t modulus)
{
    std::uint64_t result = 1U;
    base %= modulus;
    while (exponent > 0U) {
        if ((exponent & 1U) != 0U) result = (result * base) % modulus;
        exponent >>= 1U;
        base = (base * base) % modulus;
    }
    return result;
}
std::string toy_lwe_secret_material(const educational::ToyModuleSmallVector& secret)
{
    std::string material;
    for (const auto& polynomial : secret)
        for (const auto coefficient : polynomial)
            material += std::to_string(static_cast<int>(coefficient)) + ",";
    return material;
}
}

std::string run_custom_message_simulation(const std::string& plaintext)
{
    if (plaintext.empty()) return "No message entered. Simulation cancelled.\n";
    std::ostringstream out;
    out << "EDUCATIONAL CUSTOM-MESSAGE ENCRYPTION / ATTACK SIMULATION\n"
        << "Input is treated as UTF-8 bytes; no newline is appended.\n"
        << "Plaintext: " << plaintext << "\n"
        << "Plaintext bytes: " << plaintext.size() << "\n";
    const auto toy_digest = educational::truncated_sha256(plaintext, kToyShaBits);
    out << "Toy SHA-256 (first " << kToyShaBits << " bits): 0x"
        << std::hex << std::uppercase << toy_digest << std::dec << "\n"
        << "Note: Toy SHA retains SHA-256 computation and truncates its output.\n"
        << "The Toy SHA digest is supplied to AES-GCM as associated authenticated data (AAD).\n"
        << "Toy AES uses AES-128-GCM with only 12 unknown key bits; this is an educational keyspace reduction.\n\n";

    const auto run_aes_record = [&](const char* title, const auto& run_key_attack)
    {
        out << "--- " << title << " ---\n";
        educational::ToyAesSample aes;
        const double encryption_ms = timed([&] { aes = educational::generate_toy_aes_sample(12U, plaintext); });
        const auto attack_start = Clock::now();
        const auto recovered = analyzer::EducationalAnalyzer::analyze(aes.public_instance);
        const double attack_ms = std::chrono::duration<double, std::milli>(Clock::now() - attack_start).count();
        bool decrypted_match = false;
        if (recovered.success)
        {
            try
            {
                const auto bytes = standard::AES128GCM::decrypt(recovered.recovered_key, aes.public_instance.ciphertext, aes.public_instance.associated_data);
                const std::string recovered_text(bytes.begin(), bytes.end());
                decrypted_match = recovered_text == plaintext;
                out << "Recovered plaintext: " << recovered_text << "\n";
            }
            catch (const std::exception& e) { out << "Decrypt error: " << e.what() << "\n"; }
        }
        out << "Toy AES encryption/key setup: " << encryption_ms << " ms\n"
            << "Toy AES key-search attack: " << attack_ms << " ms\n"
            << "Key candidates tested: " << recovered.candidates_tested << "\n"
            << "AES key recovered: " << (recovered.success ? "YES" : "NO") << "\n"
            << "Plaintext recovered exactly: " << (decrypted_match ? "PASS" : "FAIL") << "\n"
            << "Ciphertext bytes: " << aes.public_instance.ciphertext.ciphertext.size() << "\n"
            << "Toy SHA digest: 0x" << std::hex << std::uppercase << toy_digest << std::dec << "\n";
        const bool component_ok = run_key_attack(out);
        out << "Composite educational demonstration: " << ((recovered.success && decrypted_match && component_ok) ? "PASS" : "FAIL") << "\n\n";
    };

    run_aes_record("1) Toy AES-SHA-ECDSA analogue", [&](std::ostringstream& report)
    {
        const auto sample = educational::generate_toy_ecc_sample();
        const auto attack = analyzer::EducationalAnalyzer::analyze(sample.public_instance);
        const std::uint32_t challenge = (toy_digest % 49U) + 1U;
        const std::uint32_t expected_response = (challenge * sample.ground_truth.private_scalar) % 97U;
        const std::uint32_t recovered_response = attack.success ? (challenge * attack.recovered_scalar) % 97U : 0U;
        const bool challenge_ok = attack.success && recovered_response == expected_response;
        report << "Toy SHA-derived ECC challenge: " << challenge << " (digest mod 49 + 1)\n";
        report << "Toy ECC scalar recovery + digest-bound challenge verification: " << (challenge_ok ? "PASS" : "FAIL")
               << " | candidates=" << attack.attempts << " | response=" << recovered_response << "\n";
        report << "Important: this is a message-bound ECC teaching analogue, not a standards-compliant ECDSA signature.\n";
        return challenge_ok;
    });
    run_aes_record("2) Toy AES-SHA-RSAPSS analogue", [&](std::ostringstream& report)
    {
        const auto sample = educational::generate_toy_rsa_sample(24U);
        const auto attack = analyzer::EducationalAnalyzer::analyze(sample.public_instance);
        const std::uint64_t message_representative = (static_cast<std::uint64_t>(toy_digest) % (sample.public_instance.modulus - 1U)) + 1U;
        const std::uint64_t digest_ciphertext = toy_mod_pow(message_representative, sample.public_instance.public_exponent, sample.public_instance.modulus);
        const std::uint64_t recovered_representative = attack.success
            ? toy_mod_pow(digest_ciphertext, attack.recovered_private_exponent, sample.public_instance.modulus) : 0U;
        const bool digest_message_ok = attack.success && recovered_representative == message_representative;
        report << "Toy SHA-derived RSA message representative: " << message_representative << "\n";
        report << "Toy RSA factorization + digest-message recovery: " << (digest_message_ok ? "PASS" : "FAIL")
               << " | trial divisions=" << attack.trial_divisions << " | recovered=" << recovered_representative << "\n";
        report << "Important: this is a tiny RSA message-recovery analogue, not RSA-PSS or secure RSA encryption.\n";
        return digest_message_ok;
    });
    run_aes_record("3) Toy SHA-AES-MLKEM analogue", [&](std::ostringstream& report)
    {
        const auto sample = educational::generate_toy_lwe_sample();
        const auto attack = analyzer::EducationalAnalyzer::analyze(sample.public_instance);
        const std::string sender_material = plaintext + ":" + std::to_string(toy_digest) + ":" + toy_lwe_secret_material(sample.ground_truth.secret);
        const std::string recovered_material = plaintext + ":" + std::to_string(toy_digest) + ":" + toy_lwe_secret_material(attack.recovered_secret);
        const std::uint32_t sender_shared = educational::truncated_sha256(sender_material, kToyShaBits);
        const std::uint32_t recovered_shared = attack.success
            ? educational::truncated_sha256(recovered_material, kToyShaBits) : 0U;
        const bool shared_secret_ok = attack.success && attack.recovered_secret == sample.ground_truth.secret && sender_shared == recovered_shared;
        report << "Toy SHA-derived Module-LWE KDF input: plaintext digest + recovered secret coefficients\n";
        report << "Sender toy shared key: 0x" << std::hex << std::uppercase << sender_shared
               << " | Receiver toy shared key: 0x" << recovered_shared << std::dec << "\n";
        report << "Toy Module-LWE recovery + SHA-derived shared-key agreement: " << (shared_secret_ok ? "PASS" : "FAIL")
               << " | candidate vectors=" << attack.candidates_tested << "\n";
        report << "Important: this is a tiny Module-LWE/KDF teaching analogue, not standardized ML-KEM.\n";
        return shared_secret_ok;
    });
    out << "All timings are local educational measurements, not real-world cracking estimates.\n"
        << "Toy SHA is now consumed by every set: AES-GCM AAD in all sets; a digest-derived ECC challenge in set 1; a digest-derived RSA message representative in set 2; and a digest/secret-derived toy KDF in set 3.\n"
        << "Collision search remains a separate experiment from this message-bound composite simulation.\n";
    return out.str();
}
std::string format_set(const SetResult&r){std::ostringstream o;o<<"==================================================\n"<<r.name<<"\nResult: "<<(r.passed?"PASS":"FAIL")<<"\nKey exchange model: "<<r.key_exchange<<"\nGeneration time: "<<r.generation_ms<<" ms\nClassical toy attack runtime (measured): "<<r.classical_attack_ms<<" ms\nCandidates tested: "<<r.candidates<<"\nGrover toy simulator runtime (measured): "<<r.grover_simulator_ms<<" ms\nShor N=15 toy simulator runtime (measured): "<<r.shor_simulator_ms<<" ms\n[ILLUSTRATIVE FULL-SIZE SCENARIO, NOT A REAL CRACKING PREDICTION]\nAES-128 Grover idealized time at 1us/oracle iteration: "<<duration(r.estimated_grover_seconds)<<"\nShor full-size runtime estimate: NOT ESTIMABLE\nWhole-set compromise time: NOT ESTIMABLE\n\n"<<backend_text(r.backend_benchmark)<<"\nLimitations: "<<r.attack_note<<"\n";return o.str();}
std::string format_comparison(const std::vector<SetResult>&v){std::ostringstream o;o<<"EDUCATIONAL CRYPTO SET COMPARISON (TOY PARAMETERS)\n"<<std::left<<std::setw(36)<<"Set"<<std::setw(9)<<"Result"<<std::setw(16)<<"Attack ms"<<"Candidates\n";for(const auto&r:v)o<<std::left<<std::setw(36)<<r.name<<std::setw(9)<<(r.passed?"PASS":"FAIL")<<std::setw(16)<<r.classical_attack_ms<<r.candidates<<"\n";o<<"\nToy SHA collision search is included in every set using the same truncated SHA-256 primitive.\nMeasured toy attack runtimes are not full-size compromise times.\n";for(const auto&r:v)o<<"\n"<<format_set(r);return o.str();}
bool export_results(const std::vector<SetResult>&rs,const std::string&dir,std::string&rp,std::string&cp){try{std::filesystem::create_directories(dir);rp=dir+"/educational_sets_report.txt";cp=dir+"/educational_sets_metrics.csv";std::ofstream t(rp),c(cp);if(!t||!c)return false;t<<format_comparison(rs);c<<"set,result,generation_ms,classical_attack_ms,candidates,toy_sha_bits,single_cpu_ms,single_attempts,single_collision_first,single_collision_second,single_digest,multi_cpu_ms,multi_attempts,multi_collision_first,multi_collision_second,multi_digest,gpu_status,gpu_wall_ms,gpu_kernel_ms,gpu_transfer_ms,gpu_attempts,gpu_collision_first,gpu_collision_second,gpu_digest,collision_verified,grover_simulator_ms,shor_simulator_ms,attack_note\n";for(const auto&r:rs){const auto&b=r.backend_benchmark;c<<'"'<<r.name<<"\","<<(r.passed?"PASS":"FAIL")<<','<<r.generation_ms<<','<<r.classical_attack_ms<<','<<r.candidates<<','<<b.output_bits<<','<<b.single_cpu_ms<<','<<b.single_attempts<<",\""<<b.single_first<<"\",\""<<b.single_second<<"\","<<b.single_digest<<','<<b.multi_thread_cpu_ms<<','<<b.multi_attempts<<",\""<<b.multi_first<<"\",\""<<b.multi_second<<"\","<<b.multi_digest<<",\""<<b.gpu_status<<"\","<<b.gpu_wall_ms<<','<<b.gpu_kernel_ms<<','<<b.gpu_transfer_ms<<','<<b.gpu_attempts<<",\""<<b.gpu_first<<"\",\""<<b.gpu_second<<"\","<<b.gpu_digest<<','<<(b.verified?"PASS":"FAIL")<<','<<r.grover_simulator_ms<<','<<r.shor_simulator_ms<<",\""<<r.attack_note<<"\"\n";}return true;}catch(...){return false;}}
}
