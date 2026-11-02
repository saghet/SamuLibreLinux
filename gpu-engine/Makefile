CXX = g++
CXXFLAGS = -std=c++17 -O3 -Wall -Wextra -fPIC -Iinclude
LDFLAGS = -ldl -lpthread

SRCS_CORE = src/core/gpu_detector.cpp \
            src/core/compute_engine.cpp \
            src/backends/cuda_backend.cpp \
            src/backends/cpu_backend.cpp \
            src/scanner/signature_scanner.cpp

OBJS_CORE = $(SRCS_CORE:.cpp=.o)

LIB_TARGET = libsamulibre_gpu.so
TEST_DETECTOR = bin/test_gpu_detector
TEST_COMPUTE = bin/test_compute_engine
TEST_SCANNER = bin/test_pattern_scanner

all: $(LIB_TARGET) $(TEST_DETECTOR) $(TEST_COMPUTE) $(TEST_SCANNER)

$(LIB_TARGET): $(OBJS_CORE)
	@mkdir -p lib
	$(CXX) -shared -o lib/$@ $^ $(LDFLAGS)
	@echo "✓ Biblioteca dinámica lib/$@ generada con éxito."

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(TEST_DETECTOR): tests/test_gpu_detector.cpp $(OBJS_CORE)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "✓ Binario de prueba $@ compilado."

$(TEST_COMPUTE): tests/test_compute_engine.cpp $(OBJS_CORE)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "✓ Binario de prueba $@ compilado."

$(TEST_SCANNER): tests/test_pattern_scanner.cpp $(OBJS_CORE)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "✓ Binario de prueba $@ compilado."

test: all
	@echo "=== Ejecutando Test 1: Detector de Hardware GPU ==="
	./$(TEST_DETECTOR)
	@echo ""
	@echo "=== Ejecutando Test 2: Motor de Cómputo y Transferencias de Memoria ==="
	./$(TEST_COMPUTE)
	@echo ""
	@echo "=== Ejecutando Test 3: Escáner de Firmas y Cálculo de Entropía ==="
	./$(TEST_SCANNER)
	@echo "✓ Todos los tests del motor GPU pasaron al 100%."

clean:
	rm -f src/core/*.o src/backends/*.o src/scanner/*.o bin/* lib/*

.PHONY: all test clean
