#include "rlwe/rlwe.h"
#include <iostream>
#include <cassert>
#include <vector>
#include <random>

using namespace rlwe;

#define ASSERT_TRUE(condition) \
    do { \
        if (!(condition)) { \
            std::cerr << "ASSERTION FAILED: " << #condition \
                      << " at line " << __LINE__ << std::endl; \
            return false; \
        } \
    } while(0)

#define ASSERT_EQ(a, b) \
    do { \
        if ((a) != (b)) { \
            std::cerr << "ASSERTION FAILED: " << #a << " != " << #b \
                      << " at line " << __LINE__ << std::endl; \
            return false; \
        } \
    } while(0)

bool test_parameters() {
    std::cout << "Testing parameter initialization..." << std::endl;
    
    // Test all security levels
    for (auto level : {SecurityLevel::LEVEL_128, SecurityLevel::LEVEL_192, SecurityLevel::LEVEL_256}) {
        initialize_rlwe(level);
        ASSERT_TRUE(is_initialized());
        ASSERT_EQ(get_current_security_level(), level);
        ASSERT_TRUE(get_n() > 0);
        ASSERT_TRUE(get_q() > 0);
    }
    
    return true;
}

bool test_polynomial_operations() {
    std::cout << "Testing polynomial operations..." << std::endl;
    
    initialize_rlwe(SecurityLevel::LEVEL_128);
    
    // Test construction
    Polynomial p1;
    ASSERT_EQ(p1.size(), get_n());
    
    Polynomial p2({1, 2, 3, 4});
    ASSERT_TRUE(p2.size() >= 4);
    ASSERT_EQ(p2[0], 1);
    ASSERT_EQ(p2[1], 2);
    
    // Test addition
    Polynomial p3({5, 6, 7, 8});
    Polynomial sum = p2 + p3;
    ASSERT_EQ(sum[0], mod_q(1 + 5));
    ASSERT_EQ(sum[1], mod_q(2 + 6));
    
    // Test scalar multiplication
    Polynomial scaled = p2 * 3;
    ASSERT_EQ(scaled[0], mod_q(1 * 3));
    ASSERT_EQ(scaled[1], mod_q(2 * 3));
    
    // Test sampling
    auto uniform = Polynomial::sample_uniform();
    ASSERT_EQ(uniform.size(), get_n());
    
    auto small = Polynomial::sample_small();
    ASSERT_EQ(small.size(), get_n());
    
    // Test serialization
    auto data = p2.serialize();
    auto deserialized = Polynomial::deserialize(data);
    ASSERT_EQ(deserialized.size(), p2.size());
    for (size_t i = 0; i < 4; ++i) {
        ASSERT_EQ(deserialized[i], p2[i]);
    }
    
    return true;
}

bool test_polynomial_multiplication() {
    std::cout << "Testing polynomial multiplication..." << std::endl;
    
    initialize_rlwe(SecurityLevel::LEVEL_128);
    
    // Test small polynomials
    Polynomial a({1, 2, 0, 0});
    Polynomial b({3, 4, 0, 0});
    
    auto result_ntt = a.multiply(b);
    auto result_naive = a.multiply_naive(b);
    
    // Results should be the same
    for (size_t i = 0; i < std::min(result_ntt.size(), result_naive.size()); ++i) {
        ASSERT_EQ(result_ntt[i], result_naive[i]);
    }
    
    // Test with random polynomials
    for (int trial = 0; trial < 10; ++trial) {
        auto p1 = Polynomial::sample_small();
        auto p2 = Polynomial::sample_small();
        
        auto r1 = p1.multiply(p2);
        auto r2 = p1.multiply_naive(p2);
        
        for (size_t i = 0; i < r1.size(); ++i) {
            ASSERT_EQ(r1[i], r2[i]);
        }
    }
    
    return true;
}

bool test_key_generation() {
    std::cout << "Testing key generation..." << std::endl;
    
    for (auto level : {SecurityLevel::LEVEL_128, SecurityLevel::LEVEL_192}) {
        auto [pk, sk] = keygen(level);
        
        ASSERT_TRUE(pk != nullptr);
        ASSERT_TRUE(sk != nullptr);
        
        ASSERT_EQ(pk->get_a().size(), get_n());
        ASSERT_EQ(pk->get_b().size(), get_n());
        ASSERT_EQ(sk->get_s().size(), get_n());
    }
    
    return true;
}

bool test_encryption_decryption() {
    std::cout << "Testing encryption and decryption..." << std::endl;
    
    initialize_rlwe(SecurityLevel::LEVEL_128);
    auto [pk, sk] = keygen();
    
    // Test bit encryption
    for (bool bit : {false, true}) {
        auto ct = pk->encrypt_bit(bit);
        bool decrypted = sk->decrypt_bit(ct);
        ASSERT_EQ(bit, decrypted);
    }
    
    // Test message encryption (single byte)
    std::vector<uint8_t> message = {0x55}; // 01010101
    auto ct = pk->encrypt(message);
    auto decrypted = sk->decrypt(ct);
    
    // Should preserve the least significant bit
    ASSERT_EQ(message[0] & 1, decrypted[0] & 1);
    
    // Test multiple encryptions of the same bit
    const int trials = 50;
    int correct_decryptions = 0;
    
    for (int i = 0; i < trials; ++i) {
        auto ct = pk->encrypt_bit(true);
        if (sk->decrypt_bit(ct)) {
            correct_decryptions++;
        }
    }
    
    // Should have high success rate (>90%)
    ASSERT_TRUE(correct_decryptions > trials * 0.9);
    
    return true;
}

bool test_homomorphic_operations() {
    std::cout << "Testing homomorphic operations..." << std::endl;
    
    initialize_rlwe(SecurityLevel::LEVEL_128);
    auto [pk, sk] = keygen();
    
    // Test homomorphic addition
    auto ct_0 = pk->encrypt_bit(false);
    auto ct_1 = pk->encrypt_bit(true);
    
    auto ct_sum = ct_0 + ct_1;
    bool sum_result = sk->decrypt_bit(ct_sum);
    
    // 0 + 1 should equal 1 (XOR in binary field)
    ASSERT_EQ(sum_result, true);
    
    // Test multiple additions
    auto ct_sum2 = ct_1 + ct_1; // 1 + 1 = 0 in GF(2)
    bool sum2_result = sk->decrypt_bit(ct_sum2);
    ASSERT_EQ(sum2_result, false);
    
    return true;
}

bool test_serialization() {
    std::cout << "Testing serialization..." << std::endl;
    
    initialize_rlwe(SecurityLevel::LEVEL_128);
    auto [pk, sk] = keygen();
    
    // Test public key serialization
    auto pk_data = pk->serialize();
    auto pk2 = PublicKey::deserialize(pk_data);
    
    ASSERT_EQ(pk->get_a().size(), pk2->get_a().size());
    ASSERT_EQ(pk->get_b().size(), pk2->get_b().size());
    
    // Test secret key serialization
    auto sk_data = sk->serialize();
    auto sk2 = SecretKey::deserialize(sk_data);
    
    ASSERT_EQ(sk->get_s().size(), sk2->get_s().size());
    
    // Test ciphertext serialization
    auto ct = pk->encrypt_bit(true);
    auto ct_data = ct.serialize();
    auto ct2 = Ciphertext::deserialize(ct_data);
    
    // Verify functionality after deserialization
    bool original_result = sk->decrypt_bit(ct);
    bool deserialized_result = sk2->decrypt_bit(*ct2);
    ASSERT_EQ(original_result, deserialized_result);
    
    return true;
}

bool test_error_handling() {
    std::cout << "Testing error handling..." << std::endl;
    
    // Test uninitialized system
    try {
        // This should work fine - it auto-initializes
        auto [pk, sk] = keygen();
        (void)pk; (void)sk; // Suppress unused warnings
    } catch (const std::exception& e) {
        // Should not throw
        ASSERT_TRUE(false);
    }
    
    // Test invalid serialization data
    try {
        std::vector<uint8_t> bad_data = {1, 2, 3};
        auto pk = PublicKey::deserialize(bad_data);
        ASSERT_TRUE(false); // Should have thrown
    } catch (const std::exception& e) {
        // Expected
    }
    
    return true;
}

int main() {
    std::cout << "=== RLWE Crypto System Tests ===" << std::endl;
    
    std::vector<std::pair<std::string, bool(*)()>> tests = {
        {"Parameters", test_parameters},
        {"Polynomial Operations", test_polynomial_operations},
        {"Polynomial Multiplication", test_polynomial_multiplication},
        {"Key Generation", test_key_generation},
        {"Encryption/Decryption", test_encryption_decryption},
        {"Homomorphic Operations", test_homomorphic_operations},
        {"Serialization", test_serialization},
        {"Error Handling", test_error_handling}
    };
    
    int passed = 0;
    int total = tests.size();
    
    for (auto& [name, test_func] : tests) {
        std::cout << "\n--- " << name << " ---" << std::endl;
        try {
            if (test_func()) {
                std::cout << "✓ PASSED" << std::endl;
                passed++;
            } else {
                std::cout << "✗ FAILED" << std::endl;
            }
        } catch (const std::exception& e) {
            std::cout << "✗ FAILED with exception: " << e.what() << std::endl;
        }
    }
    
    std::cout << "\n=== Test Summary ===" << std::endl;
    std::cout << "Passed: " << passed << "/" << total << std::endl;
    
    if (passed == total) {
        std::cout << "🎉 All tests passed!" << std::endl;
        return 0;
    } else {
        std::cout << "❌ Some tests failed!" << std::endl;
        return 1;
    }
}
