#include "rlwe/polynomial.h"
#include "rlwe/parameters.h"
#include "rlwe/rng.h"
#include "rlwe/ntt.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <cmath>

namespace rlwe {

// Constructors
Polynomial::Polynomial() {
    if (current_params) {
        coeffs_.resize(current_params->n, 0);
    }
}

Polynomial::Polynomial(size_t size) : coeffs_(size, 0) {}

Polynomial::Polynomial(std::initializer_list<coeff_t> coeffs) : coeffs_(coeffs) {
    if (current_params && coeffs_.size() != current_params->n) {
        coeffs_.resize(current_params->n, 0);
    }
}

void Polynomial::resize(size_t new_size) {
    coeffs_.resize(new_size, 0);
}

// Arithmetic operations
Polynomial& Polynomial::operator+=(const Polynomial& other) {
    if (coeffs_.size() != other.coeffs_.size()) {
        throw std::invalid_argument("Polynomial size mismatch");
    }
    
    for (size_t i = 0; i < coeffs_.size(); ++i) {
        coeffs_[i] = mod_q(coeffs_[i] + other.coeffs_[i]);
    }
    return *this;
}

Polynomial& Polynomial::operator-=(const Polynomial& other) {
    if (coeffs_.size() != other.coeffs_.size()) {
        throw std::invalid_argument("Polynomial size mismatch");
    }
    
    for (size_t i = 0; i < coeffs_.size(); ++i) {
        coeffs_[i] = mod_q(coeffs_[i] - other.coeffs_[i]);
    }
    return *this;
}

Polynomial& Polynomial::operator*=(coeff_t scalar) {
    for (auto& coeff : coeffs_) {
        coeff = mod_q(coeff * scalar);
    }
    return *this;
}

Polynomial Polynomial::operator+(const Polynomial& other) const {
    Polynomial result = *this;
    result += other;
    return result;
}

Polynomial Polynomial::operator-(const Polynomial& other) const {
    Polynomial result = *this;
    result -= other;
    return result;
}

Polynomial Polynomial::operator*(coeff_t scalar) const {
    Polynomial result = *this;
    result *= scalar;
    return result;
}

Polynomial Polynomial::multiply(const Polynomial& other) const {
    if (coeffs_.size() != other.coeffs_.size()) {
        throw std::invalid_argument("Polynomial size mismatch");
    }
    
    // For now, always use naive multiplication
    // NTT implementation needs proper negacyclic convolution handling
    return multiply_naive(other);
}

Polynomial Polynomial::multiply_naive(const Polynomial& other) const {
    size_t n = coeffs_.size();
    std::vector<int64_t> tmp(2 * n, 0);
    
    // Standard polynomial multiplication
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < n; ++j) {
            tmp[i + j] += coeffs_[i] * other.coeffs_[j];
        }
    }
    
    // Reduce modulo (x^n + 1) - negacyclic
    Polynomial result(n);
    for (size_t k = 0; k < 2 * n; ++k) {
        if (k < n) {
            result.coeffs_[k] += tmp[k];
        } else {
            result.coeffs_[k - n] -= tmp[k]; // x^n = -1
        }
    }
    
    result.reduce_mod_q();
    return result;
}

void Polynomial::reduce_mod_q() {
    for (auto& coeff : coeffs_) {
        coeff = mod_q(coeff);
    }
}

void Polynomial::zero() {
    std::fill(coeffs_.begin(), coeffs_.end(), 0);
}

bool Polynomial::is_zero() const {
    return std::all_of(coeffs_.begin(), coeffs_.end(), 
                      [](coeff_t c) { return c == 0; });
}

// Random sampling
Polynomial Polynomial::sample_uniform() {
    if (!current_params) {
        throw std::runtime_error("Parameters not initialized");
    }
    
    Polynomial result(current_params->n);
    auto& rng = get_rng();
    
    for (size_t i = 0; i < current_params->n; ++i) {
        result.coeffs_[i] = rng.uniform_uint64(current_params->q);
    }
    
    return result;
}

Polynomial Polynomial::sample_small(size_t k) {
    if (!current_params) {
        throw std::runtime_error("Parameters not initialized");
    }
    
    if (k == 0) k = current_params->k;
    
    Polynomial result(current_params->n);
    auto& rng = get_rng();
    
    for (size_t i = 0; i < current_params->n; ++i) {
        result.coeffs_[i] = rng.binomial(k);
    }
    
    return result;
}

Polynomial Polynomial::sample_gaussian(double sigma) {
    if (!current_params) {
        throw std::runtime_error("Parameters not initialized");
    }
    
    if (sigma == 0.0) sigma = current_params->sigma;
    
    Polynomial result(current_params->n);
    auto& rng = get_rng();
    
    for (size_t i = 0; i < current_params->n; ++i) {
        double sample = rng.gaussian(0.0, sigma);
        result.coeffs_[i] = static_cast<int64_t>(std::round(sample));
    }
    
    result.reduce_mod_q();
    return result;
}

// Serialization
std::vector<uint8_t> Polynomial::serialize() const {
    size_t coeff_bytes = sizeof(coeff_t);
    std::vector<uint8_t> data(sizeof(size_t) + coeffs_.size() * coeff_bytes);
    
    // Write size
    size_t size = coeffs_.size();
    std::memcpy(data.data(), &size, sizeof(size_t));
    
    // Write coefficients
    std::memcpy(data.data() + sizeof(size_t), coeffs_.data(), 
                coeffs_.size() * coeff_bytes);
    
    return data;
}

Polynomial Polynomial::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < sizeof(size_t)) {
        throw std::invalid_argument("Invalid serialized data");
    }
    
    size_t size;
    std::memcpy(&size, data.data(), sizeof(size_t));
    
    size_t expected_size = sizeof(size_t) + size * sizeof(coeff_t);
    if (data.size() != expected_size) {
        throw std::invalid_argument("Invalid serialized data size");
    }
    
    Polynomial result(size);
    std::memcpy(result.coeffs_.data(), data.data() + sizeof(size_t),
                size * sizeof(coeff_t));
    
    return result;
}

// I/O
std::ostream& operator<<(std::ostream& os, const Polynomial& p) {
    os << "[";
    for (size_t i = 0; i < p.coeffs_.size(); ++i) {
        os << p.coeffs_[i];
        if (i + 1 < p.coeffs_.size()) os << ", ";
    }
    os << "]";
    return os;
}

} // namespace rlwe
