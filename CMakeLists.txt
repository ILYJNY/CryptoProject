cmake_minimum_required(VERSION 3.27)

project(CryptoProject VERSION 2.3.4 DESCRIPTION "Educational cryptography system and analyzer" LANGUAGES CXX)

option(CRYPTO_ENABLE_CUDA "Enable CUDA when a compatible toolkit is found" ON)
option(CRYPTO_REQUIRE_CUDA "Fail if CUDA is unavailable" OFF)
option(CRYPTO_BUILD_TESTS "Build the test targets" ON)
option(CRYPTO_BUILD_BENCHMARKS "Build benchmark targets when available" ON)

set(CRYPTO_DEFAULT_BACKEND "AUTO" CACHE STRING "Default compute backend: AUTO, CPU, GPU, or MULTI-GPU")
set_property(CACHE CRYPTO_DEFAULT_BACKEND PROPERTY STRINGS AUTO CPU GPU MULTI-GPU)
if(NOT CRYPTO_DEFAULT_BACKEND MATCHES "^(AUTO|CPU|GPU|MULTI-GPU)$")
    message(FATAL_ERROR "CRYPTO_DEFAULT_BACKEND must be AUTO, CPU, GPU, or MULTI-GPU.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
include(cmake/CompilerOptions.cmake)

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()
set(Boost_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/boost_1_90_0")
include_directories("${Boost_INCLUDE_DIR}")
find_package(Threads REQUIRED)

add_library(crypto_compute_cpu INTERFACE)
set(CRYPTO_CUDA_AVAILABLE OFF)
if(CRYPTO_ENABLE_CUDA)
    include(CheckLanguage)
    check_language(CUDA)
    if(CMAKE_CUDA_COMPILER)
        enable_language(CUDA)
        find_package(CUDAToolkit QUIET)
        if(CUDAToolkit_FOUND)
            set(CRYPTO_CUDA_AVAILABLE ON)
            add_library(crypto_compute_cuda INTERFACE)
            target_link_libraries(crypto_compute_cuda INTERFACE CUDA::cudart)
            message(STATUS "CUDA enabled: ${CUDAToolkit_VERSION}")
        else()
            message(WARNING "CUDA Toolkit package was not found. CPU support will be used.")
        endif()
    else()
        message(WARNING "CUDA compiler was not found. CPU support will be used.")
    endif()
endif()
if(CRYPTO_REQUIRE_CUDA AND NOT CRYPTO_CUDA_AVAILABLE)
    message(FATAL_ERROR "CRYPTO_REQUIRE_CUDA is ON, but a usable CUDA compiler/toolkit was not found.")
endif()

add_library(crypto_compute INTERFACE)
target_link_libraries(crypto_compute INTERFACE crypto_compute_cpu)
if(CRYPTO_CUDA_AVAILABLE)
    target_link_libraries(crypto_compute INTERFACE crypto_compute_cuda)
    target_compile_definitions(crypto_compute INTERFACE CRYPTO_HAS_CUDA=1)
else()
    target_compile_definitions(crypto_compute INTERFACE CRYPTO_HAS_CUDA=0)
endif()

add_library(crypto_common STATIC
        Common/BigInteger/BigInteger.cpp
        Common/Encoding/Encoding.cpp
        Common/Logger/Logger.cpp
        Common/PerformanceMonitor/PerformanceMonitor.cpp
        Common/Random/SecureRandom.cpp
)
target_include_directories(crypto_common PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/Common")
if(TARGET Boost::headers)
    target_link_libraries(crypto_common PUBLIC Boost::headers)
elseif(TARGET Boost::boost)
    target_link_libraries(crypto_common PUBLIC Boost::boost)
else()
    target_include_directories(crypto_common SYSTEM PUBLIC ${Boost_INCLUDE_DIRS})
endif()
target_link_libraries(crypto_common PUBLIC Threads::Threads crypto_compute)
if(WIN32)
    target_link_libraries(crypto_common PUBLIC bcrypt)
endif()
crypto_apply_compiler_options(crypto_common)

# Compute engine implementation
set(COMPUTE_ENGINE_SOURCES
        ComputeEngine/ComputeEngine.cpp
)

if(CRYPTO_CUDA_AVAILABLE)
    list(APPEND COMPUTE_ENGINE_SOURCES
            ComputeEngine/CUDA/CudaVectorAdd.cu
            ComputeEngine/CUDA/CudaQuantumKernels.cu
            ComputeEngine/CUDA/CudaCrypto.cu
    )
endif()

add_library(crypto_compute_engine STATIC ${COMPUTE_ENGINE_SOURCES})
target_include_directories(crypto_compute_engine PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/ComputeEngine"
        "${CMAKE_CURRENT_SOURCE_DIR}"
)
target_link_libraries(crypto_compute_engine PUBLIC
        crypto_common
        crypto_compute
)
if(CRYPTO_CUDA_AVAILABLE)
    target_compile_definitions(crypto_compute_engine PUBLIC CRYPTO_HAS_CUDA=1)
    set_target_properties(crypto_compute_engine PROPERTIES
            CUDA_STANDARD 17
            CUDA_STANDARD_REQUIRED ON
            CUDA_SEPARABLE_COMPILATION ON
    )
else()
    target_compile_definitions(crypto_compute_engine PUBLIC CRYPTO_HAS_CUDA=0)
endif()
crypto_apply_compiler_options(crypto_compute_engine)

# Standard cryptographic algorithms
add_library(crypto_system_standard STATIC
        CryptoSystem/Standard/SHA/SHA256.cpp
        CryptoSystem/Standard/AES/AES128GCM.cpp
        CryptoSystem/Standard/RSA/RSA.cpp
        CryptoSystem/Standard/ECC/P256.cpp
        CryptoSystem/Standard/ModuleLWE/MLKEM768.cpp
        CryptoSystem/Standard/StandardCrypto.cpp
)
target_include_directories(crypto_system_standard PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/CryptoSystem/Standard")
target_link_libraries(crypto_system_standard PUBLIC crypto_common)
crypto_apply_compiler_options(crypto_system_standard)
target_link_libraries(crypto_compute_engine PUBLIC crypto_system_standard)

# ML-KEM-768 is implemented in-tree in portable C++; Windows CNG ML-KEM APIs are not used.

# Educational cryptography: tiny, intentionally insecure test instances only.
add_library(crypto_system_educational STATIC
        CryptoSystem/Educational/RSA/ToyRSA.cpp
        CryptoSystem/Educational/ECC/ToyECC.cpp
        CryptoSystem/Educational/ModuleLWE/ToyModuleLWE.cpp
        CryptoSystem/Educational/AES/ToyAESKeySearch.cpp
        CryptoSystem/Educational/SHA/ToySha256.cpp
)
target_include_directories(crypto_system_educational PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/CryptoSystem/Educational")
target_link_libraries(crypto_system_educational PUBLIC crypto_common crypto_system_standard)
crypto_apply_compiler_options(crypto_system_educational)

add_library(crypto_analyzer_standard STATIC
        CryptoAnalyzer/Standard/StandardAnalyzer.cpp)
target_include_directories(crypto_analyzer_standard PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(crypto_analyzer_standard PUBLIC
        crypto_common crypto_system_standard)
crypto_apply_compiler_options(crypto_analyzer_standard)

add_library(crypto_analyzer_educational STATIC
        CryptoAnalyzer/Educational/EducationalAnalyzer.cpp)
target_include_directories(crypto_analyzer_educational PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(crypto_analyzer_educational PUBLIC
        crypto_common crypto_system_educational)
crypto_apply_compiler_options(crypto_analyzer_educational)

add_library(crypto_integrated STATIC
        IntegratedMode/IntegratedRunner.cpp)
target_include_directories(crypto_integrated PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(crypto_integrated PUBLIC
        crypto_common crypto_system_educational crypto_analyzer_educational)
crypto_apply_compiler_options(crypto_integrated)

# Classical state-vector quantum simulator, CPU/CUDA backends, and benchmarks.
set(QUANTUM_ATTACK_SOURCES
        QuantumAttack/Backend/CPU/QuantumThreadPool.cpp
        QuantumAttack/Backend/CPU/CPUQuantumBackend.cpp
        QuantumAttack/Standard/Core/QuantumSimulator.cpp
        QuantumAttack/Standard/Algorithms/QuantumAlgorithms.cpp
        QuantumAttack/Standard/Models/QuantumResourceModel.cpp
        QuantumAttack/Educational/Experiments/EducationalExperiments.cpp
        QuantumAttack/Educational/Visualization/QuantumVisualizer.cpp
        QuantumAttack/Reports/QuantumReport.cpp
        QuantumAttack/Benchmark/QftBenchmark.cpp
        QuantumAttack/Benchmark/AlgorithmBenchmark.cpp
)

if(CRYPTO_CUDA_AVAILABLE)
    list(APPEND QUANTUM_ATTACK_SOURCES
            QuantumAttack/Backend/CUDA/CUDAQuantumBackend.cu
            QuantumAttack/Backend/CUDA/CUDAMultiGpuQuantumBackend.cu
    )
else()
    list(APPEND QUANTUM_ATTACK_SOURCES
            QuantumAttack/Backend/CUDA/CUDAQuantumBackendStub.cpp
            QuantumAttack/Backend/CUDA/CUDAMultiGpuQuantumBackendStub.cpp
    )
endif()

add_library(crypto_quantum STATIC ${QUANTUM_ATTACK_SOURCES})
target_include_directories(crypto_quantum PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/QuantumAttack"
        "${CMAKE_CURRENT_SOURCE_DIR}/ComputeEngine"
        "${CMAKE_CURRENT_SOURCE_DIR}"
)
target_link_libraries(crypto_quantum PUBLIC crypto_common crypto_compute_engine)
target_compile_definitions(crypto_quantum PUBLIC CRYPTO_HAS_CUDA=$<BOOL:${CRYPTO_CUDA_AVAILABLE}>)

if(CRYPTO_CUDA_AVAILABLE)
    set_target_properties(crypto_quantum PROPERTIES
            CUDA_STANDARD 17
            CUDA_STANDARD_REQUIRED ON
            CUDA_SEPARABLE_COMPILATION ON
    )
endif()

crypto_apply_compiler_options(crypto_quantum)
target_link_libraries(crypto_integrated PUBLIC crypto_quantum)

# Three independently evaluated cryptosystem sets plus quantum-attack resource analysis.
add_library(crypto_set_analysis STATIC
        CryptoSetAnalysis/CryptoSetAnalysis.cpp
        CryptoSetAnalysis/Detail/QuantumAttackAnalysis.cpp
        CryptoSetAnalysis/Sets/AesShaEcdsa.cpp
        CryptoSetAnalysis/Sets/AesShaRsaPss.cpp
        CryptoSetAnalysis/Sets/ShaAesMlKem.cpp
)
target_include_directories(crypto_set_analysis PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/CryptoSystem/Standard"
        "${CMAKE_CURRENT_SOURCE_DIR}/QuantumAttack"
)
target_link_libraries(crypto_set_analysis PUBLIC
        crypto_common crypto_system_standard crypto_quantum)
crypto_apply_compiler_options(crypto_set_analysis)

# Batch analysis runs all three independent sets and aggregates their metrics.
add_library(crypto_integrated_crypto_analysis STATIC
        IntegratedCryptoAnalysis/IntegratedCryptoAnalysis.cpp
)
target_include_directories(crypto_integrated_crypto_analysis PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(crypto_integrated_crypto_analysis PUBLIC crypto_set_analysis)
crypto_apply_compiler_options(crypto_integrated_crypto_analysis)

# Educational analogues of the three independent cryptosystem sets and their batch analysis.
add_library(crypto_educational_set_analysis STATIC
        EducationalCryptoSetAnalysis/EducationalCryptoSetAnalysis.cpp)
target_include_directories(crypto_educational_set_analysis PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(crypto_educational_set_analysis PUBLIC
        crypto_system_educational crypto_analyzer_educational crypto_quantum crypto_compute_engine)
crypto_apply_compiler_options(crypto_educational_set_analysis)

add_library(crypto_integrated_educational_analysis STATIC
        IntegratedEducationalCryptoAnalysis/IntegratedEducationalCryptoAnalysis.cpp)
target_include_directories(crypto_integrated_educational_analysis PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(crypto_integrated_educational_analysis PUBLIC crypto_educational_set_analysis)
crypto_apply_compiler_options(crypto_integrated_educational_analysis)

add_library(crypto_benchmark STATIC
        Benchmark/BenchmarkRunner.cpp)
target_include_directories(crypto_benchmark PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/Benchmark")
target_link_libraries(crypto_benchmark PUBLIC
        crypto_common crypto_system_standard)
crypto_apply_compiler_options(crypto_benchmark)

add_executable(CryptoProject main.cpp)
target_link_libraries(CryptoProject PRIVATE
        crypto_common
        crypto_compute_engine
        crypto_system_standard
        crypto_system_educational
        crypto_analyzer_standard
        crypto_analyzer_educational
        crypto_integrated
        crypto_quantum
        crypto_set_analysis
        crypto_integrated_crypto_analysis
        crypto_educational_set_analysis
        crypto_integrated_educational_analysis
        crypto_benchmark
)
crypto_apply_compiler_options(CryptoProject)

if(CRYPTO_BUILD_TESTS)
    enable_testing()
    add_subdirectory(Tests)
endif()
if(CRYPTO_BUILD_BENCHMARKS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/Benchmark/CMakeLists.txt")
    add_subdirectory(Benchmark)
endif()

message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Default compute backend: ${CRYPTO_DEFAULT_BACKEND}")
message(STATUS "CUDA available: ${CRYPTO_CUDA_AVAILABLE}")
message(STATUS "Boost version: ${Boost_VERSION}")
