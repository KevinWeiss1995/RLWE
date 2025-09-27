#include "rlwe/rlwe.h"
#include "rlwe/ntt.h"
#include "rlwe/rng.h"
#include <cstring>
#include <sstream>

namespace rlwe {

static SecurityLevel current_security_level_ = SecurityLevel::LEVEL_128;
static bool system_initialized_ = false;

// Utility functions
void initialize_rlwe(SecurityLevel level) {
    set_parameters(level);
    NTT::initialize();
    current_security_level_ = level;
    system_initialized_ = true;
}

bool is_initialized() {
    return system_initialized_;
}

SecurityLevel get_current_security_level() {
    return current_security_level_;
}

// Key generation
std::pair<std::unique_ptr<PublicKey>, std::unique_ptr<SecretKey>> 
keygen(SecurityLevel level) {
    if (!is_initialized() || get_current_security_level() != level) {
        initialize_rlwe(level);
    }
    
    // Sample polynomials
    Polynomial a = Polynomial::sample_uniform();
    Polynomial s = Polynomial::sample_small();
    Polynomial e = Polynomial::sample_small();
    
    // Compute b = a*s + e
    Polynomial b = a.multiply(s) + e;
    
    auto pk = std::make_unique<PublicKey>(a, b);
    auto sk = std::make_unique<SecretKey>(s);
    
    return {std::move(pk), std::move(sk)};
}

// PublicKey implementation
PublicKey::PublicKey(const Polynomial& a, const Polynomial& b) 
    : a_(a), b_(b), level_(get_current_security_level()) {}

Ciphertext PublicKey::encrypt(const std::vector<uint8_t>& message) const {
    if (message.empty()) {
        throw std::invalid_argument("Message cannot be empty");
    }
    
    // For now, encrypt one bit at a time and return the first bit
    // In a full implementation, you'd pack multiple bits efficiently
    bool bit = (message[0] & 1) != 0;
    return encrypt_bit(bit);
}

Ciphertext PublicKey::encrypt_bit(bool bit) const {
    Polynomial m(get_n());
    m[0] = bit ? 1 : 0;
    return encrypt_polynomial(m);
}

Ciphertext PublicKey::encrypt_polynomial(const Polynomial& message) const {
    // Sample random polynomials
    Polynomial r = Polynomial::sample_small();
    Polynomial e1 = Polynomial::sample_small();
    Polynomial e2 = Polynomial::sample_small();
    
    // Compute ciphertext components
    Polynomial u = a_.multiply(r) + e1;
    Polynomial v = b_.multiply(r) + e2;
    
    // Encode message (scale by q/2)
    uint64_t q = get_q();
    uint64_t half_q = q / 2;
    
    for (size_t i = 0; i < message.size() && i < v.size(); ++i) {
        int64_t scaled_msg = (message[i] != 0) ? static_cast<int64_t>(half_q) : 0;
        v[i] = mod_q(v[i] + scaled_msg);
    }
    
    return Ciphertext(u, v);
}

std::vector<uint8_t> PublicKey::serialize() const {
    auto a_data = a_.serialize();
    auto b_data = b_.serialize();
    
    std::vector<uint8_t> result;
    result.reserve(sizeof(SecurityLevel) + sizeof(size_t) + a_data.size() + b_data.size());
    
    // Write security level
    result.insert(result.end(), 
                  reinterpret_cast<const uint8_t*>(&level_),
                  reinterpret_cast<const uint8_t*>(&level_) + sizeof(SecurityLevel));
    
    // Write size of a_data
    size_t a_size = a_data.size();
    result.insert(result.end(),
                  reinterpret_cast<const uint8_t*>(&a_size),
                  reinterpret_cast<const uint8_t*>(&a_size) + sizeof(size_t));
    
    // Write a_data and b_data
    result.insert(result.end(), a_data.begin(), a_data.end());
    result.insert(result.end(), b_data.begin(), b_data.end());
    
    return result;
}

std::unique_ptr<PublicKey> PublicKey::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < sizeof(SecurityLevel) + sizeof(size_t)) {
        throw std::invalid_argument("Invalid serialized public key data");
    }
    
    size_t offset = 0;
    
    // Read security level
    SecurityLevel level;
    std::memcpy(&level, data.data() + offset, sizeof(SecurityLevel));
    offset += sizeof(SecurityLevel);
    
    // Read size of a_data
    size_t a_size;
    std::memcpy(&a_size, data.data() + offset, sizeof(size_t));
    offset += sizeof(size_t);
    
    if (offset + a_size >= data.size()) {
        throw std::invalid_argument("Invalid serialized public key data");
    }
    
    // Read a_data
    std::vector<uint8_t> a_data(data.begin() + offset, data.begin() + offset + a_size);
    offset += a_size;
    
    // Read b_data
    std::vector<uint8_t> b_data(data.begin() + offset, data.end());
    
    // Deserialize polynomials
    Polynomial a = Polynomial::deserialize(a_data);
    Polynomial b = Polynomial::deserialize(b_data);
    
    // Initialize with correct security level
    if (!is_initialized() || get_current_security_level() != level) {
        initialize_rlwe(level);
    }
    
    return std::make_unique<PublicKey>(a, b);
}

// SecretKey implementation
SecretKey::SecretKey(const Polynomial& s) 
    : s_(s), level_(get_current_security_level()) {}

std::vector<uint8_t> SecretKey::decrypt(const Ciphertext& ciphertext) const {
    bool bit = decrypt_bit(ciphertext);
    return {static_cast<uint8_t>(bit ? 1 : 0)};
}

bool SecretKey::decrypt_bit(const Ciphertext& ciphertext) const {
    Polynomial m = decrypt_polynomial(ciphertext);
    return m[0] != 0;
}

Polynomial SecretKey::decrypt_polynomial(const Ciphertext& ciphertext) const {
    // Compute v - u*s
    Polynomial us = ciphertext.u_.multiply(s_);
    Polynomial diff = ciphertext.v_ - us;
    
    // Decode message by threshold decoding
    int64_t q = static_cast<int64_t>(get_q());
    int64_t quarter_q = q / 4;
    int64_t three_quarter_q = 3 * q / 4;
    
    Polynomial result(diff.size());
    for (size_t i = 0; i < diff.size(); ++i) {
        int64_t coeff = diff[i];
        // Handle negative coefficients properly
        if (coeff < 0) coeff += q;
        
        if (coeff > quarter_q && coeff < three_quarter_q) {
            result[i] = 1;
        } else {
            result[i] = 0;
        }
    }
    
    return result;
}

std::vector<uint8_t> SecretKey::serialize() const {
    auto s_data = s_.serialize();
    
    std::vector<uint8_t> result;
    result.reserve(sizeof(SecurityLevel) + s_data.size());
    
    // Write security level
    result.insert(result.end(),
                  reinterpret_cast<const uint8_t*>(&level_),
                  reinterpret_cast<const uint8_t*>(&level_) + sizeof(SecurityLevel));
    
    // Write s_data
    result.insert(result.end(), s_data.begin(), s_data.end());
    
    return result;
}

std::unique_ptr<SecretKey> SecretKey::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < sizeof(SecurityLevel)) {
        throw std::invalid_argument("Invalid serialized secret key data");
    }
    
    // Read security level
    SecurityLevel level;
    std::memcpy(&level, data.data(), sizeof(SecurityLevel));
    
    // Read s_data
    std::vector<uint8_t> s_data(data.begin() + sizeof(SecurityLevel), data.end());
    
    // Deserialize polynomial
    Polynomial s = Polynomial::deserialize(s_data);
    
    // Initialize with correct security level
    if (!is_initialized() || get_current_security_level() != level) {
        initialize_rlwe(level);
    }
    
    return std::make_unique<SecretKey>(s);
}

// Ciphertext implementation
Ciphertext::Ciphertext(const Polynomial& u, const Polynomial& v)
    : u_(u), v_(v), level_(get_current_security_level()) {}

Ciphertext Ciphertext::operator+(const Ciphertext& other) const {
    if (level_ != other.level_) {
        throw std::invalid_argument("Cannot add ciphertexts with different security levels");
    }
    
    return Ciphertext(u_ + other.u_, v_ + other.v_);
}

Ciphertext& Ciphertext::operator+=(const Ciphertext& other) {
    if (level_ != other.level_) {
        throw std::invalid_argument("Cannot add ciphertexts with different security levels");
    }
    
    u_ += other.u_;
    v_ += other.v_;
    return *this;
}

std::vector<uint8_t> Ciphertext::serialize() const {
    auto u_data = u_.serialize();
    auto v_data = v_.serialize();
    
    std::vector<uint8_t> result;
    result.reserve(sizeof(SecurityLevel) + sizeof(size_t) + u_data.size() + v_data.size());
    
    // Write security level
    result.insert(result.end(),
                  reinterpret_cast<const uint8_t*>(&level_),
                  reinterpret_cast<const uint8_t*>(&level_) + sizeof(SecurityLevel));
    
    // Write size of u_data
    size_t u_size = u_data.size();
    result.insert(result.end(),
                  reinterpret_cast<const uint8_t*>(&u_size),
                  reinterpret_cast<const uint8_t*>(&u_size) + sizeof(size_t));
    
    // Write u_data and v_data
    result.insert(result.end(), u_data.begin(), u_data.end());
    result.insert(result.end(), v_data.begin(), v_data.end());
    
    return result;
}

std::unique_ptr<Ciphertext> Ciphertext::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < sizeof(SecurityLevel) + sizeof(size_t)) {
        throw std::invalid_argument("Invalid serialized ciphertext data");
    }
    
    size_t offset = 0;
    
    // Read security level
    SecurityLevel level;
    std::memcpy(&level, data.data() + offset, sizeof(SecurityLevel));
    offset += sizeof(SecurityLevel);
    
    // Read size of u_data
    size_t u_size;
    std::memcpy(&u_size, data.data() + offset, sizeof(size_t));
    offset += sizeof(size_t);
    
    if (offset + u_size >= data.size()) {
        throw std::invalid_argument("Invalid serialized ciphertext data");
    }
    
    // Read u_data
    std::vector<uint8_t> u_data(data.begin() + offset, data.begin() + offset + u_size);
    offset += u_size;
    
    // Read v_data
    std::vector<uint8_t> v_data(data.begin() + offset, data.end());
    
    // Deserialize polynomials
    Polynomial u = Polynomial::deserialize(u_data);
    Polynomial v = Polynomial::deserialize(v_data);
    
    // Initialize with correct security level
    if (!is_initialized() || get_current_security_level() != level) {
        initialize_rlwe(level);
    }
    
    return std::make_unique<Ciphertext>(u, v);
}

} // namespace rlwe
