#pragma once

#include <vector>
#include <cstdint>
#include <iosfwd>

namespace rlwe {

class Polynomial {
public:
    using coeff_t = int64_t;
    
    // Constructors
    Polynomial();
    explicit Polynomial(size_t size);
    Polynomial(std::initializer_list<coeff_t> coeffs);
    
    // Access
    coeff_t& operator[](size_t i) { return coeffs_[i]; }
    const coeff_t& operator[](size_t i) const { return coeffs_[i]; }
    
    size_t size() const { return coeffs_.size(); }
    void resize(size_t new_size);
    
    // Arithmetic operations
    Polynomial& operator+=(const Polynomial& other);
    Polynomial& operator-=(const Polynomial& other);
    Polynomial& operator*=(coeff_t scalar);
    
    Polynomial operator+(const Polynomial& other) const;
    Polynomial operator-(const Polynomial& other) const;
    Polynomial operator*(coeff_t scalar) const;
    
    // Polynomial multiplication (uses NTT)
    Polynomial multiply(const Polynomial& other) const;
    Polynomial multiply_naive(const Polynomial& other) const;
    
    // Modular reduction
    void reduce_mod_q();
    
    // Serialization
    std::vector<uint8_t> serialize() const;
    static Polynomial deserialize(const std::vector<uint8_t>& data);
    
    // Utility
    void zero();
    bool is_zero() const;
    
    // Random sampling
    static Polynomial sample_uniform();
    static Polynomial sample_small(size_t k = 0); // Uses current params if k=0
    static Polynomial sample_gaussian(double sigma = 0.0); // Uses current params if sigma=0
    
    // I/O
    friend std::ostream& operator<<(std::ostream& os, const Polynomial& p);
    
private:
    std::vector<coeff_t> coeffs_;
    
    friend class NTT;
};

// Utility functions
int64_t mod_q(int64_t x);
uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t mod);
uint64_t mod_inverse(uint64_t a, uint64_t mod);

} // namespace rlwe
