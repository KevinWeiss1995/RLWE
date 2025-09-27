#pragma once

#include "polynomial.h"
#include "parameters.h"
#include <vector>
#include <memory>

namespace rlwe {

// Forward declarations
class PublicKey;
class SecretKey;
class Ciphertext;

// Key pair generation
std::pair<std::unique_ptr<PublicKey>, std::unique_ptr<SecretKey>> 
keygen(SecurityLevel level = SecurityLevel::LEVEL_128);

// Public Key
class PublicKey {
public:
    PublicKey(const Polynomial& a, const Polynomial& b);
    
    // Encryption
    Ciphertext encrypt(const std::vector<uint8_t>& message) const;
    Ciphertext encrypt_bit(bool bit) const;
    Ciphertext encrypt_polynomial(const Polynomial& message) const;
    
    // Serialization
    std::vector<uint8_t> serialize() const;
    static std::unique_ptr<PublicKey> deserialize(const std::vector<uint8_t>& data);
    
    // Access (for advanced users)
    const Polynomial& get_a() const { return a_; }
    const Polynomial& get_b() const { return b_; }
    
private:
    Polynomial a_;
    Polynomial b_;
    SecurityLevel level_;
};

// Secret Key
class SecretKey {
public:
    explicit SecretKey(const Polynomial& s);
    
    // Decryption
    std::vector<uint8_t> decrypt(const Ciphertext& ciphertext) const;
    bool decrypt_bit(const Ciphertext& ciphertext) const;
    Polynomial decrypt_polynomial(const Ciphertext& ciphertext) const;
    
    // Serialization
    std::vector<uint8_t> serialize() const;
    static std::unique_ptr<SecretKey> deserialize(const std::vector<uint8_t>& data);
    
    // Access (for advanced users)
    const Polynomial& get_s() const { return s_; }
    
private:
    Polynomial s_;
    SecurityLevel level_;
};

// Ciphertext
class Ciphertext {
public:
    Ciphertext(const Polynomial& u, const Polynomial& v);
    
    // Homomorphic operations
    Ciphertext operator+(const Ciphertext& other) const;
    Ciphertext& operator+=(const Ciphertext& other);
    
    // Serialization
    std::vector<uint8_t> serialize() const;
    static std::unique_ptr<Ciphertext> deserialize(const std::vector<uint8_t>& data);
    
    // Access (for advanced users)
    const Polynomial& get_u() const { return u_; }
    const Polynomial& get_v() const { return v_; }
    
private:
    Polynomial u_;
    Polynomial v_;
    SecurityLevel level_;
    
    friend class PublicKey;
    friend class SecretKey;
};

// Utility functions
void initialize_rlwe(SecurityLevel level = SecurityLevel::LEVEL_128);
bool is_initialized();
SecurityLevel get_current_security_level();

// Error handling - see exceptions.h for comprehensive exception hierarchy

} // namespace rlwe
