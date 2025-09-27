# Simple Makefile for quick building (alternative to CMake)

CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -O3 -march=native -DNDEBUG
DEBUG_FLAGS = -std=c++20 -Wall -Wextra -g -O0 -fsanitize=address,undefined

INCLUDE_DIR = include
SRC_DIR = src
BUILD_DIR = build
EXAMPLES_DIR = examples
TESTS_DIR = tests

SOURCES = $(wildcard $(SRC_DIR)/*.cpp)
OBJECTS = $(SOURCES:$(SRC_DIR)/%.cpp=$(BUILD_DIR)/%.o)
LIBRARY = $(BUILD_DIR)/librlwe_crypto.a

# Platform-specific flags
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    LDFLAGS += -framework Security
endif

.PHONY: all clean test examples debug

all: $(LIBRARY) examples

debug: CXXFLAGS = $(DEBUG_FLAGS)
debug: all

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

$(LIBRARY): $(OBJECTS)
	ar rcs $@ $^

examples: $(LIBRARY)
	$(CXX) $(CXXFLAGS) -I$(INCLUDE_DIR) $(EXAMPLES_DIR)/basic_example.cpp $(LIBRARY) $(LDFLAGS) -o $(BUILD_DIR)/basic_example
	$(CXX) $(CXXFLAGS) -I$(INCLUDE_DIR) $(EXAMPLES_DIR)/benchmark.cpp $(LIBRARY) $(LDFLAGS) -o $(BUILD_DIR)/benchmark
	$(CXX) $(CXXFLAGS) -I$(INCLUDE_DIR) $(EXAMPLES_DIR)/advanced_example.cpp $(LIBRARY) $(LDFLAGS) -o $(BUILD_DIR)/advanced_example

test: $(LIBRARY)
	$(CXX) $(CXXFLAGS) -I$(INCLUDE_DIR) $(TESTS_DIR)/test_rlwe.cpp $(LIBRARY) $(LDFLAGS) -o $(BUILD_DIR)/test_rlwe
	$(BUILD_DIR)/test_rlwe

clean:
	rm -rf $(BUILD_DIR)

install: $(LIBRARY)
	cp -r $(INCLUDE_DIR)/rlwe /usr/local/include/
	cp $(LIBRARY) /usr/local/lib/

help:
	@echo "Available targets:"
	@echo "  all      - Build library and examples (optimized)"
	@echo "  debug    - Build with debug flags"
	@echo "  examples - Build example programs"
	@echo "  test     - Build and run tests"
	@echo "  clean    - Remove build directory"
	@echo "  install  - Install library system-wide"
	@echo "  help     - Show this help"
