cmake_minimum_required(VERSION 3.25)
project(QuantumAttack LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(QUANTUM_ENABLE_CUDA "Build the NVIDIA CUDA quantum backend when a CUDA compiler is available" ON)
option(QUANTUM_BUILD_DEMO "Build the QuantumAttack command-line demo" ON)
option(QUANTUM_BUILD_TESTS "Build the QuantumAttack smoke tests" ON)

set(QUANTUM_CUDA_AVAILABLE OFF)
if(QUANTUM_ENABLE_CUDA)
    include(CheckLanguage)
    check_language(CUDA)
    if(CMAKE_CUDA_COMPILER)
        enable_language(CUDA)
        set(QUANTUM_CUDA_AVAILABLE ON)
        message(STATUS "QuantumAttack CUDA backend: ON (${CMAKE_CUDA_COMPILER})")
    else()
        message(STATUS "QuantumAttack CUDA backend: OFF (CUDA compiler not found); CPU backend remains available")
    endif()
else()
    message(STATUS "QuantumAttack CUDA backend: OFF (disabled by option)")
endif()

set(QUANTUM_ATTACK_SOURCES
    Backend/CPU/QuantumThreadPool.cpp
    Backend/CPU/CPUQuantumBackend.cpp
    Standard/Core/QuantumSimulator.cpp
    Standard/Algorithms/QuantumAlgorithms.cpp
    Standard/Models/QuantumResourceModel.cpp
    Educational/Experiments/EducationalExperiments.cpp
    Educational/Visualization/QuantumVisualizer.cpp
    Reports/QuantumReport.cpp
    Benchmark/QftBenchmark.cpp
    Benchmark/AlgorithmBenchmark.cpp
)

if(QUANTUM_CUDA_AVAILABLE)
    list(APPEND QUANTUM_ATTACK_SOURCES
        Backend/CUDA/CUDAQuantumBackend.cu
        Backend/CUDA/CUDAMultiGpuQuantumBackend.cu
    )
else()
    list(APPEND QUANTUM_ATTACK_SOURCES
        Backend/CUDA/CUDAQuantumBackendStub.cpp
        Backend/CUDA/CUDAMultiGpuQuantumBackendStub.cpp
    )
endif()

add_library(quantum_attack STATIC ${QUANTUM_ATTACK_SOURCES})
target_include_directories(quantum_attack PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(quantum_attack PUBLIC CRYPTO_HAS_CUDA=$<BOOL:${QUANTUM_CUDA_AVAILABLE}>)
target_compile_features(quantum_attack PUBLIC cxx_std_20)

if(MSVC)
    target_compile_options(quantum_attack PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:/W4>
        $<$<COMPILE_LANGUAGE:CXX>:/permissive->
        $<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>
        $<$<COMPILE_LANGUAGE:CXX>:/utf-8>
        $<$<COMPILE_LANGUAGE:CXX>:/bigobj>
    )
else()
    target_compile_options(quantum_attack PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:-Wall>
        $<$<COMPILE_LANGUAGE:CXX>:-Wextra>
        $<$<COMPILE_LANGUAGE:CXX>:-Wpedantic>
    )
endif()

if(QUANTUM_CUDA_AVAILABLE)
    set_target_properties(quantum_attack PROPERTIES
        CUDA_STANDARD 17
        CUDA_STANDARD_REQUIRED ON
        CUDA_SEPARABLE_COMPILATION ON
    )
endif()

if(QUANTUM_BUILD_DEMO)
    add_executable(QuantumAttackDemo Examples/QuantumAttackDemo.cpp)
    target_link_libraries(QuantumAttackDemo PRIVATE quantum_attack)
endif()

add_executable(QuantumAttackBenchmark Examples/QuantumAttackBenchmark.cpp)
target_link_libraries(QuantumAttackBenchmark PRIVATE quantum_attack)

add_executable(QuantumAttackAlgorithmBenchmark Examples/QuantumAttackAlgorithmBenchmark.cpp)
target_link_libraries(QuantumAttackAlgorithmBenchmark PRIVATE quantum_attack)

if(QUANTUM_BUILD_TESTS)
    enable_testing()
    add_executable(QuantumAttackSmokeTests Tests/QuantumAttackSmokeTests.cpp)
    target_link_libraries(QuantumAttackSmokeTests PRIVATE quantum_attack)
    add_test(NAME QuantumAttackSmokeTests COMMAND QuantumAttackSmokeTests)
endif()
