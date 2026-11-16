# Replace the existing crypto_quantum source-list block in the root CryptoProject CMakeLists.txt.
# CRYPTO_CUDA_AVAILABLE is expected to have been determined by the root project already.

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
# Keep the existing target_link_libraries(crypto_integrated PUBLIC crypto_quantum) line.
