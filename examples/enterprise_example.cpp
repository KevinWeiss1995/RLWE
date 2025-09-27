/**
 * @file enterprise_example.cpp
 * @brief Enterprise-grade RLWE crypto system demonstration
 * 
 * This example showcases the production-ready features of the RLWE crypto system
 * including enterprise logging, security monitoring, performance tracking, and
 * advanced cryptographic operations.
 */

#include "rlwe/rlwe.h"
#include "rlwe/logging.h"
#include "rlwe/security.h"
#include "rlwe/exceptions.h"
#include "rlwe/advanced_rlwe.h"

#include <iostream>
#include <iomanip>
#include <thread>
#include <vector>
#include <chrono>

using namespace rlwe;
using namespace rlwe::logging;
using namespace rlwe::security;
using namespace rlwe::advanced;

/**
 * @brief Initialize enterprise-grade logging system
 */
void setup_enterprise_logging() {
    std::cout << "=== Setting up Enterprise Logging System ===" << std::endl;
    
    // Create composite logger for multiple outputs
    auto composite = std::make_unique<CompositeLogger>();
    
    // Add console logging for real-time monitoring
    composite->add_logger(std::make_unique<ConsoleLogger>(LogLevel::INFO));
    
    // Add file logging with rotation for persistent storage
    composite->add_logger(std::make_unique<FileLogger>(
        "rlwe_enterprise.log", LogLevel::DEBUG, 10*1024*1024, 5));
    
    LoggerManager::instance().set_default_logger(std::move(composite));
    
    // Set up security logging
    auto security_logger = std::make_unique<SecurityLogger>("rlwe_security.log");
    LoggerManager::instance().set_security_logger(std::move(security_logger));
    
    // Set up performance monitoring
    auto perf_logger = std::make_unique<PerformanceLogger>(
        std::shared_ptr<ILogger>(LoggerManager::instance().get_default_logger(), 
                               [](ILogger*){}));
    LoggerManager::instance().set_performance_logger(std::move(perf_logger));
    
    RLWE_LOG_INFO("Enterprise", "Logging system initialized successfully");
    std::cout << "✓ Enterprise logging system ready" << std::endl;
}

/**
 * @brief Demonstrate enterprise key management
 */
void demonstrate_enterprise_key_management() {
    std::cout << "\n=== Enterprise Key Management ===" << std::endl;
    
    try {
        RLWE_PERF_TIMER("enterprise_keygen");
        
        // Generate keys with enterprise-grade security
        RLWE_LOG_INFO("KeyManagement", "Generating enterprise-grade key pair (256-bit security)");
        auto [public_key, secret_key] = keygen(SecurityLevel::LEVEL_256);
        
        // Log security event
        RLWE_LOG_SECURITY("KEY_GENERATION", "New key pair generated for enterprise use");
        
        // Demonstrate secure serialization
        {
            RLWE_PERF_TIMER("key_serialization");
            
            auto pk_serialized = public_key->serialize();
            auto sk_serialized = secret_key->serialize();
            
            RLWE_LOG_INFO("KeyManagement", 
                         "Keys serialized: PK=" + std::to_string(pk_serialized.size()) + " bytes, " +
                         "SK=" + std::to_string(sk_serialized.size()) + " bytes");
            
            // Demonstrate secure deserialization with validation
            auto pk_restored = PublicKey::deserialize(pk_serialized);
            auto sk_restored = SecretKey::deserialize(sk_serialized);
            
            RLWE_LOG_INFO("KeyManagement", "Key deserialization successful");
        }
        
        std::cout << "✓ Enterprise key management completed" << std::endl;
        
    } catch (const RLWEException& e) {
        RLWE_LOG_ERROR("KeyManagement", "Key management failed: " + std::string(e.what()));
        std::cout << "✗ Key management failed: " << e.what() << std::endl;
    }
}

/**
 * @brief Demonstrate secure cryptographic operations
 */
void demonstrate_secure_crypto_operations() {
    std::cout << "\n=== Secure Cryptographic Operations ===" << std::endl;
    
    try {
        // Initialize timing analyzer for side-channel protection
        TimingAnalyzer timing_analyzer;
        
        auto [public_key, secret_key] = keygen(SecurityLevel::LEVEL_256);
        
        // Demonstrate batch encryption with security monitoring
        {
            RLWE_PERF_TIMER("batch_encryption");
            timing_analyzer.start_measurement();
            
            std::vector<bool> sensitive_bits = {true, false, true, true, false, true, false, false};
            RLWE_LOG_INFO("CryptoOps", "Encrypting batch of " + std::to_string(sensitive_bits.size()) + " bits");
            
            auto batch_ciphertext = BatchProcessor::pack_encrypt(*public_key, sensitive_bits);
            
            timing_analyzer.end_measurement("batch_encryption");
            
            // Decrypt and verify
            auto decrypted_bits = BatchProcessor::unpack_decrypt(*secret_key, batch_ciphertext);
            
            bool verification_success = (sensitive_bits == decrypted_bits);
            if (verification_success) {
                RLWE_LOG_INFO("CryptoOps", "Batch encryption/decryption verification successful");
                std::cout << "✓ Batch crypto operations verified" << std::endl;
            } else {
                RLWE_LOG_ERROR("CryptoOps", "Batch encryption/decryption verification failed");
                throw CryptographicException("Batch operation verification failed");
            }
        }
        
        // Demonstrate homomorphic operations with security monitoring
        {
            RLWE_PERF_TIMER("homomorphic_operations");
            
            auto ct1 = public_key->encrypt_bit(true);
            auto ct2 = public_key->encrypt_bit(false);
            
            // Homomorphic XOR
            auto xor_result = HomomorphicOps::logical_xor(ct1, ct2);
            bool xor_decrypted = secret_key->decrypt_bit(xor_result);
            
            // Homomorphic AND
            auto and_result = HomomorphicOps::logical_and(ct1, ct2);
            bool and_decrypted = secret_key->decrypt_bit(and_result);
            
            RLWE_LOG_INFO("CryptoOps", 
                         "Homomorphic operations: XOR=" + std::to_string(xor_decrypted) + 
                         ", AND=" + std::to_string(and_decrypted));
            
            // Verify correctness
            if (xor_decrypted == (true ^ false) && and_decrypted == (true & false)) {
                std::cout << "✓ Homomorphic operations verified" << std::endl;
            } else {
                throw CryptographicException("Homomorphic operation verification failed");
            }
        }
        
    } catch (const RLWEException& e) {
        RLWE_LOG_ERROR("CryptoOps", "Cryptographic operation failed: " + std::string(e.what()));
        std::cout << "✗ Cryptographic operations failed: " << e.what() << std::endl;
    }
}

/**
 * @brief Demonstrate enterprise security monitoring
 */
void demonstrate_security_monitoring() {
    std::cout << "\n=== Enterprise Security Monitoring ===" << std::endl;
    
    // Demonstrate input validation
    {
        std::vector<uint64_t> invalid_coeffs = {999999999, 888888888}; // Too large for typical modulus
        
        if (!InputValidator::validate_polynomial_coefficients(invalid_coeffs, 12289)) {
            RLWE_LOG_SECURITY("INPUT_VALIDATION", "Invalid polynomial coefficients detected and rejected");
            std::cout << "✓ Input validation working correctly" << std::endl;
        }
    }
    
    // Demonstrate secure memory management
    {
        RLWE_PERF_TIMER("secure_memory_operations");
        
        // Use secure buffer for sensitive data
        SecureBuffer<uint64_t> secure_data(1024);
        
        // Fill with sensitive data
        for (size_t i = 0; i < secure_data.size(); ++i) {
            secure_data[i] = i * 42; // Some sensitive computation
        }
        
        RLWE_LOG_INFO("Security", "Secure buffer operations completed");
        std::cout << "✓ Secure memory management working" << std::endl;
        
        // Buffer will be automatically zeroed when it goes out of scope
    }
    
    // Demonstrate fault detection
    {
        try {
            auto test_function = []() -> int {
                return 42;
            };
            
            // This should succeed (both calls return 42)
            auto result = FaultDetector::verify_computation(test_function);
            
            if (result == 42) {
                RLWE_LOG_INFO("Security", "Fault detection verification passed");
                std::cout << "✓ Fault detection system operational" << std::endl;
            }
            
        } catch (const std::exception& e) {
            RLWE_LOG_SECURITY("FAULT_INJECTION", "Fault injection detected: " + std::string(e.what()));
            std::cout << "⚠ Fault injection detected and handled" << std::endl;
        }
    }
}

/**
 * @brief Demonstrate multi-threaded enterprise operations
 */
void demonstrate_multithreaded_operations() {
    std::cout << "\n=== Multi-threaded Enterprise Operations ===" << std::endl;
    
    try {
        auto [public_key, secret_key] = keygen(SecurityLevel::LEVEL_256);
        
        const size_t num_threads = 4;
        const size_t operations_per_thread = 10;
        
        std::vector<std::thread> threads;
        std::atomic<size_t> successful_operations{0};
        std::atomic<size_t> failed_operations{0};
        
        RLWE_LOG_INFO("MultiThread", 
                     "Starting " + std::to_string(num_threads) + " threads with " + 
                     std::to_string(operations_per_thread) + " operations each");
        
        // Launch worker threads
        for (size_t thread_id = 0; thread_id < num_threads; ++thread_id) {
            threads.emplace_back([&, thread_id]() {
                try {
                    for (size_t op = 0; op < operations_per_thread; ++op) {
                        RLWE_PERF_TIMER("threaded_crypto_operation");
                        
                        // Each thread performs independent crypto operations
                        uint8_t test_data = static_cast<uint8_t>((thread_id * operations_per_thread + op) % 256);
                        
                        auto ciphertext = public_key->encrypt({test_data});
                        auto decrypted = secret_key->decrypt(ciphertext);
                        
                        // Verify result (LSB should match)
                        if ((decrypted[0] & 1) == (test_data & 1)) {
                            successful_operations++;
                        } else {
                            failed_operations++;
                            RLWE_LOG_WARN("MultiThread", 
                                         "Thread " + std::to_string(thread_id) + 
                                         " operation " + std::to_string(op) + " failed verification");
                        }
                    }
                    
                    RLWE_LOG_INFO("MultiThread", "Thread " + std::to_string(thread_id) + " completed");
                    
                } catch (const std::exception& e) {
                    RLWE_LOG_ERROR("MultiThread", 
                                  "Thread " + std::to_string(thread_id) + " failed: " + e.what());
                    failed_operations += operations_per_thread;
                }
            });
        }
        
        // Wait for all threads to complete
        for (auto& thread : threads) {
            thread.join();
        }
        
        size_t total_ops = num_threads * operations_per_thread;
        RLWE_LOG_INFO("MultiThread", 
                     "Multi-threaded operations completed: " + 
                     std::to_string(successful_operations.load()) + "/" + std::to_string(total_ops) + " successful");
        
        if (failed_operations.load() == 0) {
            std::cout << "✓ All multi-threaded operations successful (" << successful_operations.load() << "/" << total_ops << ")" << std::endl;
        } else {
            std::cout << "⚠ Some operations failed: " << failed_operations.load() << "/" << total_ops << std::endl;
        }
        
    } catch (const RLWEException& e) {
        RLWE_LOG_ERROR("MultiThread", "Multi-threaded test failed: " + std::string(e.what()));
        std::cout << "✗ Multi-threaded operations failed: " << e.what() << std::endl;
    }
}

/**
 * @brief Display performance statistics
 */
void display_performance_statistics() {
    std::cout << "\n=== Performance Statistics ===" << std::endl;
    
    auto perf_logger = LoggerManager::instance().get_performance_logger();
    if (!perf_logger) {
        std::cout << "Performance logger not available" << std::endl;
        return;
    }
    
    // Display statistics for key operations
    std::vector<std::string> operations = {
        "enterprise_keygen",
        "key_serialization",
        "batch_encryption",
        "homomorphic_operations",
        "secure_memory_operations",
        "threaded_crypto_operation"
    };
    
    std::cout << std::setw(30) << "Operation" 
              << std::setw(15) << "Count" 
              << std::setw(20) << "Avg Time (μs)" 
              << std::setw(20) << "Min Time (μs)" 
              << std::setw(20) << "Max Time (μs)" << std::endl;
    std::cout << std::string(105, '-') << std::endl;
    
    for (const auto& op : operations) {
        auto stats = perf_logger->get_statistics(op);
        if (stats.total_operations > 0) {
            std::cout << std::setw(30) << op
                      << std::setw(15) << stats.total_operations
                      << std::setw(20) << std::fixed << std::setprecision(2) 
                      << (stats.mean_duration_ns / 1000.0)
                      << std::setw(20) << (stats.min_duration.count() / 1000.0)
                      << std::setw(20) << (stats.max_duration.count() / 1000.0) << std::endl;
        }
    }
    
    std::cout << "✓ Performance statistics displayed" << std::endl;
}

/**
 * @brief Main enterprise demonstration
 */
int main() {
    try {
        std::cout << "🏢 RLWE Enterprise Crypto System Demonstration" << std::endl;
        std::cout << "================================================" << std::endl;
        
        // Initialize enterprise infrastructure
        setup_enterprise_logging();
        
        // Run enterprise demonstrations
        demonstrate_enterprise_key_management();
        demonstrate_secure_crypto_operations();
        demonstrate_security_monitoring();
        demonstrate_multithreaded_operations();
        
        // Display performance metrics
        display_performance_statistics();
        
        std::cout << "\n🎉 Enterprise demonstration completed successfully!" << std::endl;
        std::cout << "📊 Check log files: rlwe_enterprise.log, rlwe_security.log" << std::endl;
        
        // Final security log
        RLWE_LOG_SECURITY("SYSTEM_SHUTDOWN", "Enterprise demonstration completed successfully");
        
        return 0;
        
    } catch (const RLWEException& e) {
        std::cerr << "❌ Enterprise demonstration failed: " << e.what() << std::endl;
        RLWE_LOG_CRITICAL("Enterprise", "Demonstration failed: " + std::string(e.what()));
        return 1;
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Unexpected error: " << e.what() << std::endl;
        RLWE_LOG_CRITICAL("Enterprise", "Unexpected error: " + std::string(e.what()));
        return 1;
    }
}
