cmake_minimum_required(VERSION 3.16)
project(SamuLibreGPUEngine VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include_directories(include)

set(CORE_SOURCES
    src/core/gpu_detector.cpp
    src/core/compute_engine.cpp
    src/backends/cuda_backend.cpp
    src/backends/cpu_backend.cpp
    src/scanner/signature_scanner.cpp
    src/ml/elf_feature_extractor.cpp
    src/ml/ml_classifier.cpp
)

add_library(samulibre_gpu SHARED ${CORE_SOURCES})
target_link_libraries(samulibre_gpu PRIVATE ${CMAKE_DL_LIBS} pthread)

# Test executables
enable_testing()

add_executable(test_gpu_detector tests/test_gpu_detector.cpp ${CORE_SOURCES})
target_link_libraries(test_gpu_detector PRIVATE ${CMAKE_DL_LIBS} pthread)
add_test(NAME TestGPUDetector COMMAND test_gpu_detector)

add_executable(test_compute_engine tests/test_compute_engine.cpp ${CORE_SOURCES})
target_link_libraries(test_compute_engine PRIVATE ${CMAKE_DL_LIBS} pthread)
add_test(NAME TestComputeEngine COMMAND test_compute_engine)

add_executable(test_pattern_scanner tests/test_pattern_scanner.cpp ${CORE_SOURCES})
target_link_libraries(test_pattern_scanner PRIVATE ${CMAKE_DL_LIBS} pthread)
add_test(NAME TestPatternScanner COMMAND test_pattern_scanner)

add_executable(test_ml_classifier tests/test_ml_classifier.cpp ${CORE_SOURCES})
target_link_libraries(test_ml_classifier PRIVATE ${CMAKE_DL_LIBS} pthread)
add_test(NAME TestMLClassifier COMMAND test_ml_classifier)
