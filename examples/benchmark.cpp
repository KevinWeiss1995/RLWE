#include "rlwe/rlwe.h"
#include <iostream>
#include <chrono>
#include <vector>
#include <iomanip>

using namespace rlwe;
using namespace std::chrono;

class Timer {
public:
    Timer() : start_(high_resolution_clock::now()) {}
    
    double elapsed_ms() const {
        auto end = high_resolution_clock::now();
        return duration_cast<microseconds>(end - start_).count() / 1000.0;
    }
    
    void reset() {
        start_ = high_resolution_clock::now();
    }
    
private:
    high_resolution_clock::time_point start_;
};

void benchmark_security_level(SecurityLevel level, int iterations = 100) {
    std::cout << "\n=== Security Level " << static_cast<int>(level) << " ===" << std::endl;
    
    initialize_rlwe(level);
    std::cout << "Parameters: n=" << get_n() << ", q=" << get_q() << std::endl;
    
    Timer timer;
    
    // Benchmark key generation
    timer.reset();
    std::vector<std::pair<std::unique_ptr<PublicKey>, std::unique_ptr<SecretKey>>> keys;
    keys.reserve(iterations);
    
    for (int i = 0; i < iterations; ++i) {
        keys.push_back(keygen(level));
    }
    
    double keygen_time = timer.elapsed_ms();
    std::cout << "Key generation: " << std::fixed << std::setprecision(2) 
              << keygen_time / iterations << " ms/keygen" << std::endl;
    
    // Use the first key pair for encryption/decryption benchmarks
    auto& [pk, sk] = keys[0];
    
    // Benchmark encryption
    timer.reset();
    std::vector<Ciphertext> ciphertexts;
    ciphertexts.reserve(iterations);
    
    for (int i = 0; i < iterations; ++i) {
        ciphertexts.push_back(pk->encrypt_bit(i & 1));
    }
    
    double encrypt_time = timer.elapsed_ms();
    std::cout << "Encryption:     " << std::fixed << std::setprecision(2)
              << encrypt_time / iterations << " ms/encrypt" << std::endl;
    
    // Benchmark decryption
    timer.reset();
    for (int i = 0; i < iterations; ++i) {
        volatile bool result = sk->decrypt_bit(ciphertexts[i]);
        (void)result; // Suppress unused variable warning
    }
    
    double decrypt_time = timer.elapsed_ms();
    std::cout << "Decryption:     " << std::fixed << std::setprecision(2)
              << decrypt_time / iterations << " ms/decrypt" << std::endl;
    
    // Benchmark homomorphic addition
    if (ciphertexts.size() >= 2) {
        timer.reset();
        for (int i = 0; i < iterations / 2; ++i) {
            volatile auto result = ciphertexts[2*i] + ciphertexts[2*i + 1];
            (void)result;
        }
        
        double add_time = timer.elapsed_ms();
        std::cout << "Homomorphic add:" << std::fixed << std::setprecision(2)
                  << add_time / (iterations / 2) << " ms/addition" << std::endl;
    }
    
    // Benchmark serialization
    timer.reset();
    for (int i = 0; i < iterations; ++i) {
        volatile auto data = pk->serialize();
        (void)data;
    }
    
    double serialize_pk_time = timer.elapsed_ms();
    std::cout << "PK Serialization:" << std::fixed << std::setprecision(2)
              << serialize_pk_time / iterations << " ms/serialize" << std::endl;
    
    // Benchmark deserialization
    auto pk_data = pk->serialize();
    timer.reset();
    for (int i = 0; i < iterations; ++i) {
        volatile auto deserialized = PublicKey::deserialize(pk_data);
        (void)deserialized;
    }
    
    double deserialize_pk_time = timer.elapsed_ms();
    std::cout << "PK Deserialize: " << std::fixed << std::setprecision(2)
              << deserialize_pk_time / iterations << " ms/deserialize" << std::endl;
    
    // Memory usage estimation
    size_t pk_size = pk->serialize().size();
    size_t sk_size = sk->serialize().size();
    size_t ct_size = ciphertexts[0].serialize().size();
    
    std::cout << "\nMemory usage:" << std::endl;
    std::cout << "  Public key:  " << pk_size << " bytes" << std::endl;
    std::cout << "  Secret key:  " << sk_size << " bytes" << std::endl;
    std::cout << "  Ciphertext:  " << ct_size << " bytes" << std::endl;
}

int main() {
    try {
        std::cout << "=== RLWE Crypto System Benchmark ===" << std::endl;
        
        const int iterations = 100;
        std::cout << "Running " << iterations << " iterations per test..." << std::endl;
        
        // Benchmark all security levels
        benchmark_security_level(SecurityLevel::LEVEL_128, iterations);
        benchmark_security_level(SecurityLevel::LEVEL_192, iterations);
        benchmark_security_level(SecurityLevel::LEVEL_256, iterations);
        
        // Polynomial multiplication benchmark
        std::cout << "\n=== Polynomial Multiplication Benchmark ===" << std::endl;
        std::cout << "Note: Currently using naive multiplication (O(n²))" << std::endl;
        std::cout << "NTT infrastructure ready for future optimization" << std::endl;
        
        for (auto level : {SecurityLevel::LEVEL_128, SecurityLevel::LEVEL_192, SecurityLevel::LEVEL_256}) {
            initialize_rlwe(level);
            
            Timer timer;
            
            // Current multiplication (naive)
            timer.reset();
            for (int i = 0; i < iterations; ++i) {
                auto a = Polynomial::sample_uniform();
                auto b = Polynomial::sample_uniform();
                volatile auto result = a.multiply(b);
                (void)result;
            }
            double current_time = timer.elapsed_ms();
            
            std::cout << "Level " << static_cast<int>(level) << " (n=" << get_n() << "):" << std::endl;
            std::cout << "  Polynomial multiply: " << std::fixed << std::setprecision(2)
                      << current_time / iterations << " ms" << std::endl;
            std::cout << "  Theoretical NTT speedup: ~" << static_cast<int>(get_n() * std::log2(get_n()) / (get_n() * get_n() / 1000)) << "x" << std::endl;
        }
        
        std::cout << "\n=== Benchmark Complete ===" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
