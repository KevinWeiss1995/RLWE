#pragma once

#include "rlwe.h"
#include <vector>
#include <functional>
#include <future>

namespace rlwe {

// Advanced RLWE features - our unique innovations
namespace advanced {

// Custom parameter sets beyond standard security levels
struct CustomParameters {
    size_t n;
    uint64_t q;
    double noise_stddev;
    size_t hamming_weight;  // For sparse secrets
    std::string description;
    
    // Custom security estimation
    double estimated_security_bits() const;
    bool is_ntt_friendly() const;
};

// Advanced key management
class KeyManager {
public:
    // Key rotation and refresh
    struct RotationKeys {
        std::vector<PublicKey> rotation_keys;
        std::vector<int> rotation_steps;
    };
    
    static RotationKeys generate_rotation_keys(const SecretKey& sk, const std::vector<int>& steps);
    static Ciphertext rotate(const Ciphertext& ct, int steps, const RotationKeys& rk);
    
    // Key switching
    struct SwitchingKeys {
        std::vector<PublicKey> switching_keys;
    };
    
    static SwitchingKeys generate_switching_keys(const SecretKey& old_sk, const SecretKey& new_sk);
    static Ciphertext key_switch(const Ciphertext& ct, const SwitchingKeys& sk);
    
    // Bootstrapping keys for noise refresh
    struct BootstrappingKeys {
        std::vector<PublicKey> bootstrap_keys;
        PublicKey refresh_key;
    };
    
    static BootstrappingKeys generate_bootstrapping_keys(const SecretKey& sk);
    static Ciphertext bootstrap(const Ciphertext& noisy_ct, const BootstrappingKeys& bk);
};

// Batch operations for efficiency
class BatchProcessor {
public:
    // Encrypt multiple plaintexts efficiently
    static std::vector<Ciphertext> batch_encrypt(
        const PublicKey& pk, 
        const std::vector<std::vector<uint8_t>>& messages
    );
    
    // Decrypt multiple ciphertexts efficiently
    static std::vector<std::vector<uint8_t>> batch_decrypt(
        const SecretKey& sk,
        const std::vector<Ciphertext>& ciphertexts
    );
    
    // Parallel processing
    static std::vector<std::future<Ciphertext>> async_encrypt(
        const PublicKey& pk,
        const std::vector<std::vector<uint8_t>>& messages
    );
    
    // SIMD-style packing (multiple values in one ciphertext)
    static Ciphertext pack_encrypt(const PublicKey& pk, const std::vector<bool>& bits);
    static std::vector<bool> unpack_decrypt(const SecretKey& sk, const Ciphertext& packed_ct);
};

// Streaming encryption for large data
class StreamCipher {
public:
    StreamCipher(const PublicKey& pk, size_t buffer_size = 4096);
    
    // Stream interface
    void write(const uint8_t* data, size_t length);
    std::vector<Ciphertext> read_encrypted_chunks();
    void finalize();
    
    // File encryption
    static std::vector<Ciphertext> encrypt_file(const PublicKey& pk, const std::string& filename);
    static void decrypt_file(const SecretKey& sk, const std::vector<Ciphertext>& encrypted_chunks, const std::string& output_filename);
    
private:
    const PublicKey& pk_;
    std::vector<uint8_t> buffer_;
    size_t buffer_size_;
    std::vector<Ciphertext> encrypted_chunks_;
};

// Advanced homomorphic operations
class HomomorphicOps {
public:
    // Arithmetic beyond addition
    static Ciphertext multiply(const Ciphertext& a, const Ciphertext& b);  // Requires relinearization
    static Ciphertext square(const Ciphertext& a);
    static Ciphertext negate(const Ciphertext& a);
    
    // Logical operations
    static Ciphertext logical_and(const Ciphertext& a, const Ciphertext& b);
    static Ciphertext logical_or(const Ciphertext& a, const Ciphertext& b);
    static Ciphertext logical_xor(const Ciphertext& a, const Ciphertext& b);
    static Ciphertext logical_not(const Ciphertext& a);
    
    // Comparison operations (returns encrypted boolean)
    static Ciphertext compare_equal(const Ciphertext& a, const Ciphertext& b);
    static Ciphertext compare_greater(const Ciphertext& a, const Ciphertext& b);
    
    // Polynomial evaluation
    static Ciphertext evaluate_polynomial(const Ciphertext& x, const std::vector<int64_t>& coefficients);
    
    // Statistical operations on encrypted data
    static Ciphertext encrypted_sum(const std::vector<Ciphertext>& values);
    static Ciphertext encrypted_average(const std::vector<Ciphertext>& values);
    
    // Conditional operations
    static Ciphertext conditional_select(const Ciphertext& condition, const Ciphertext& true_val, const Ciphertext& false_val);
};

// Noise management and analysis
class NoiseAnalyzer {
public:
    // Estimate noise in ciphertext
    static double estimate_noise_budget(const Ciphertext& ct, const SecretKey& sk);
    
    // Predict noise growth
    static double predict_noise_after_addition(const Ciphertext& a, const Ciphertext& b);
    static double predict_noise_after_multiplication(const Ciphertext& a, const Ciphertext& b);
    
    // Automatic noise management
    static bool needs_bootstrapping(const Ciphertext& ct, const SecretKey& sk);
    static Ciphertext auto_bootstrap_if_needed(const Ciphertext& ct, const KeyManager::BootstrappingKeys& bk);
};

// Protocol implementations
namespace protocols {

// Private Set Intersection
class PSI {
public:
    static std::vector<Ciphertext> compute_intersection(
        const std::vector<uint64_t>& set_a,
        const std::vector<Ciphertext>& encrypted_set_b
    );
};

// Secure Multi-Party Computation primitives
class SMPC {
public:
    // Secret sharing
    static std::vector<Ciphertext> share_secret(const PublicKey& pk, uint64_t secret, size_t num_parties);
    static Ciphertext reconstruct_secret(const std::vector<Ciphertext>& shares);
    
    // Secure comparison
    static Ciphertext secure_max(const std::vector<Ciphertext>& values);
    static Ciphertext secure_min(const std::vector<Ciphertext>& values);
};

// Privacy-preserving machine learning
class PPML {
public:
    // Linear regression on encrypted data
    static std::vector<double> encrypted_linear_regression(
        const std::vector<std::vector<Ciphertext>>& encrypted_features,
        const std::vector<Ciphertext>& encrypted_labels
    );
    
    // Neural network inference
    static std::vector<Ciphertext> encrypted_neural_network_inference(
        const std::vector<Ciphertext>& encrypted_input,
        const std::vector<std::vector<double>>& weights,
        const std::vector<double>& biases
    );
};

} // namespace protocols

// Performance profiler
class Profiler {
public:
    struct PerformanceMetrics {
        double key_generation_time_ms;
        double encryption_time_ms;
        double decryption_time_ms;
        double homomorphic_add_time_ms;
        double homomorphic_mult_time_ms;
        size_t memory_usage_bytes;
        std::string ntt_backend_used;
    };
    
    static PerformanceMetrics benchmark_system(SecurityLevel level, int iterations = 100);
    static void profile_operation(const std::string& op_name, std::function<void()> operation);
    static std::string generate_performance_report();
};

} // namespace advanced
} // namespace rlwe
