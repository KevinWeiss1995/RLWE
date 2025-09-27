#pragma once

#include <vector>
#include <string>
#include <functional>
#include <memory>
#include <chrono>
#include <random>

namespace rlwe {
namespace testing {

/**
 * @brief Enterprise-grade testing framework for cryptographic systems
 */

/**
 * @brief Test result status
 */
enum class TestResult {
    PASS,
    FAIL,
    SKIP,
    TIMEOUT
};

/**
 * @brief Individual test case
 */
struct TestCase {
    std::string name;
    std::string category;
    std::function<void()> test_function;
    std::chrono::milliseconds timeout{30000}; // 30 second default timeout
    bool is_security_critical = false;
    
    TestCase(const std::string& test_name, 
            const std::string& test_category,
            std::function<void()> func,
            std::chrono::milliseconds test_timeout = std::chrono::milliseconds(30000),
            bool security_critical = false)
        : name(test_name), category(test_category), test_function(func), 
          timeout(test_timeout), is_security_critical(security_critical) {}
};

/**
 * @brief Test execution result
 */
struct TestExecution {
    TestCase test_case;
    TestResult result;
    std::chrono::milliseconds execution_time;
    std::string error_message;
    std::string stack_trace;
    
    TestExecution(const TestCase& tc) : test_case(tc), result(TestResult::SKIP) {}
};

/**
 * @brief Test suite for organizing related tests
 */
class TestSuite {
public:
    explicit TestSuite(const std::string& suite_name) : name_(suite_name) {}
    
    /**
     * @brief Add a test case to the suite
     */
    void add_test(const TestCase& test_case);
    
    /**
     * @brief Add a test with simplified syntax
     */
    void add_test(const std::string& name, const std::string& category,
                 std::function<void()> func, bool security_critical = false);
    
    /**
     * @brief Run all tests in the suite
     */
    std::vector<TestExecution> run_all_tests();
    
    /**
     * @brief Run tests in a specific category
     */
    std::vector<TestExecution> run_category(const std::string& category);
    
    /**
     * @brief Run only security-critical tests
     */
    std::vector<TestExecution> run_security_tests();
    
    /**
     * @brief Get suite statistics
     */
    struct Statistics {
        size_t total_tests;
        size_t passed;
        size_t failed;
        size_t skipped;
        size_t timeouts;
        std::chrono::milliseconds total_time;
        std::chrono::milliseconds average_time;
    };
    
    Statistics get_statistics(const std::vector<TestExecution>& results) const;
    
    const std::string& get_name() const { return name_; }
    const std::vector<TestCase>& get_tests() const { return tests_; }
    
private:
    std::string name_;
    std::vector<TestCase> tests_;
    
    TestExecution run_single_test(const TestCase& test_case);
};

/**
 * @brief Cryptographic test utilities
 */
class CryptoTestUtils {
public:
    /**
     * @brief Generate random test data
     */
    static std::vector<uint8_t> generate_random_bytes(size_t length, uint32_t seed = 0);
    
    /**
     * @brief Generate deterministic test polynomials
     */
    static std::vector<uint64_t> generate_test_polynomial(size_t degree, uint64_t modulus, uint32_t seed = 0);
    
    /**
     * @brief Verify encryption/decryption round trip
     */
    static bool verify_encryption_round_trip(const std::vector<uint8_t>& original_data);
    
    /**
     * @brief Test homomorphic operation correctness
     */
    static bool verify_homomorphic_addition(bool bit1, bool bit2);
    
    /**
     * @brief Measure operation timing for performance tests
     */
    template<typename Func>
    static std::chrono::nanoseconds measure_timing(Func&& func, size_t iterations = 1000) {
        auto start = std::chrono::high_resolution_clock::now();
        for (size_t i = 0; i < iterations; ++i) {
            func();
        }
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start) / iterations;
    }
    
    /**
     * @brief Statistical randomness tests
     */
    static bool test_randomness_quality(const std::vector<uint8_t>& data);
    
    /**
     * @brief Memory corruption detection
     */
    static bool detect_memory_corruption(void* data, size_t size, uint32_t expected_checksum);
};

/**
 * @brief Fuzzing test framework
 */
class FuzzTester {
public:
    /**
     * @brief Fuzz test configuration
     */
    struct FuzzConfig {
        size_t max_iterations = 10000;
        size_t max_input_size = 1024;
        uint32_t seed = std::random_device{}();
        std::chrono::milliseconds timeout_per_iteration{100};
        bool crash_on_failure = false;
    };
    
    /**
     * @brief Fuzz test a function with random inputs
     */
    template<typename InputGenerator, typename TestFunction>
    static size_t fuzz_test(const std::string& test_name,
                           InputGenerator input_gen,
                           TestFunction test_func,
                           const FuzzConfig& config = FuzzConfig{}) {
        size_t failures = 0;
        std::mt19937 rng(config.seed);
        
        for (size_t i = 0; i < config.max_iterations; ++i) {
            try {
                auto input = input_gen(rng, config.max_input_size);
                
                auto start = std::chrono::high_resolution_clock::now();
                test_func(input);
                auto end = std::chrono::high_resolution_clock::now();
                
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                if (duration > config.timeout_per_iteration) {
                    ++failures;
                    if (config.crash_on_failure) {
                        throw std::runtime_error("Fuzz test timeout on iteration " + std::to_string(i));
                    }
                }
                
            } catch (const std::exception& e) {
                ++failures;
                if (config.crash_on_failure) {
                    throw std::runtime_error("Fuzz test failure on iteration " + std::to_string(i) + ": " + e.what());
                }
            }
        }
        
        return failures;
    }
    
    /**
     * @brief Generate random polynomial coefficients for fuzzing
     */
    static std::vector<uint64_t> generate_random_polynomial(std::mt19937& rng, size_t max_degree, uint64_t modulus);
    
    /**
     * @brief Generate random serialized data for deserialization fuzzing
     */
    static std::vector<uint8_t> generate_random_serialized_data(std::mt19937& rng, size_t max_size);
};

/**
 * @brief Security test framework
 */
class SecurityTester {
public:
    /**
     * @brief Test for timing side-channel vulnerabilities
     */
    static bool test_constant_time_operations();
    
    /**
     * @brief Test memory safety and secure deletion
     */
    static bool test_memory_security();
    
    /**
     * @brief Test input validation robustness
     */
    static bool test_input_validation();
    
    /**
     * @brief Test fault injection resistance
     */
    static bool test_fault_injection_resistance();
    
    /**
     * @brief Test cryptographic correctness
     */
    static bool test_cryptographic_properties();
    
    /**
     * @brief Run comprehensive security test suite
     */
    static std::vector<TestExecution> run_security_test_suite();
    
private:
    static TestExecution create_security_test(const std::string& name, std::function<bool()> test_func);
};

/**
 * @brief Performance benchmark framework
 */
class BenchmarkSuite {
public:
    struct BenchmarkResult {
        std::string operation_name;
        size_t iterations;
        std::chrono::nanoseconds total_time;
        std::chrono::nanoseconds average_time;
        std::chrono::nanoseconds min_time;
        std::chrono::nanoseconds max_time;
        double operations_per_second;
        size_t memory_usage_bytes;
    };
    
    /**
     * @brief Benchmark a cryptographic operation
     */
    template<typename Func>
    static BenchmarkResult benchmark_operation(const std::string& name, Func&& func, size_t iterations = 1000) {
        std::vector<std::chrono::nanoseconds> timings;
        timings.reserve(iterations);
        
        // Warm up
        for (size_t i = 0; i < 10; ++i) {
            func();
        }
        
        // Actual benchmark
        auto start_total = std::chrono::high_resolution_clock::now();
        for (size_t i = 0; i < iterations; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            func();
            auto end = std::chrono::high_resolution_clock::now();
            timings.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(end - start));
        }
        auto end_total = std::chrono::high_resolution_clock::now();
        
        auto total_time = std::chrono::duration_cast<std::chrono::nanoseconds>(end_total - start_total);
        auto average_time = total_time / iterations;
        auto min_time = *std::min_element(timings.begin(), timings.end());
        auto max_time = *std::max_element(timings.begin(), timings.end());
        
        double ops_per_second = 1e9 / average_time.count();
        
        return BenchmarkResult{
            name,
            iterations,
            total_time,
            average_time,
            min_time,
            max_time,
            ops_per_second,
            0 // Memory usage would need platform-specific implementation
        };
    }
    
    /**
     * @brief Run comprehensive performance benchmarks
     */
    static std::vector<BenchmarkResult> run_comprehensive_benchmarks();
    
    /**
     * @brief Compare benchmark results
     */
    static void compare_benchmarks(const std::vector<BenchmarkResult>& baseline,
                                  const std::vector<BenchmarkResult>& current);
};

/**
 * @brief Test assertion macros for better error reporting
 */
#define RLWE_TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            throw std::runtime_error("Assertion failed: " + std::string(message) + \
                                   " at " + __FILE__ + ":" + std::to_string(__LINE__)); \
        } \
    } while (0)

#define RLWE_TEST_ASSERT_EQ(expected, actual, message) \
    do { \
        if ((expected) != (actual)) { \
            throw std::runtime_error("Assertion failed: " + std::string(message) + \
                                   " (expected: " + std::to_string(expected) + \
                                   ", actual: " + std::to_string(actual) + ")" + \
                                   " at " + __FILE__ + ":" + std::to_string(__LINE__)); \
        } \
    } while (0)

#define RLWE_TEST_ASSERT_THROWS(statement, exception_type, message) \
    do { \
        bool threw = false; \
        try { \
            statement; \
        } catch (const exception_type&) { \
            threw = true; \
        } catch (...) { \
            throw std::runtime_error("Assertion failed: " + std::string(message) + \
                                   " (wrong exception type)" + \
                                   " at " + __FILE__ + ":" + std::to_string(__LINE__)); \
        } \
        if (!threw) { \
            throw std::runtime_error("Assertion failed: " + std::string(message) + \
                                   " (no exception thrown)" + \
                                   " at " + __FILE__ + ":" + std::to_string(__LINE__)); \
        } \
    } while (0)

} // namespace testing
} // namespace rlwe
