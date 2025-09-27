#include "rlwe/ntt.h"
#include "rlwe/parameters.h"
#include <algorithm>
#include <stdexcept>

namespace {
// Helper function for modular exponentiation
uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t mod) {
    if (mod == 1) return 0;
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) {
            result = (static_cast<__uint128_t>(result) * base) % mod;
        }
        exp >>= 1;
        base = (static_cast<__uint128_t>(base) * base) % mod;
    }
    return result;
}
}

namespace rlwe {

std::vector<uint64_t> NTT::powers_of_psi_;
std::vector<uint64_t> NTT::powers_of_psi_inv_;
bool NTT::initialized_ = false;

void NTT::initialize() {
    if (!current_params) {
        throw std::runtime_error("Parameters not initialized");
    }
    
    size_t n = current_params->n;
    uint64_t q = current_params->q;
    uint64_t psi = current_params->psi;
    uint64_t psi_inv = current_params->psi_inv;
    
    // Precompute powers of psi and psi_inv for negacyclic NTT
    powers_of_psi_.resize(n);
    powers_of_psi_inv_.resize(n);
    
    // For negacyclic NTT, we need twiddle factors
    // Store powers of psi for the NTT butterfly operations
    size_t log_n = 0;
    size_t temp = n;
    while (temp > 1) {
        temp >>= 1;
        log_n++;
    }
    
    for (size_t i = 0; i < n; ++i) {
        size_t rev_i = reverse_bits(i, log_n);
        powers_of_psi_[i] = mod_pow(psi, rev_i, q);
        powers_of_psi_inv_[i] = mod_pow(psi_inv, rev_i, q);
    }
    
    initialized_ = true;
}

bool NTT::is_initialized() {
    return initialized_;
}

void NTT::forward(Polynomial& poly) {
    if (!initialized_) {
        throw std::runtime_error("NTT not initialized");
    }
    
    std::vector<uint64_t> coeffs(poly.size());
    for (size_t i = 0; i < poly.size(); ++i) {
        coeffs[i] = static_cast<uint64_t>(poly[i]);
    }
    
    coeffs = forward(coeffs);
    
    for (size_t i = 0; i < poly.size(); ++i) {
        poly[i] = static_cast<int64_t>(coeffs[i]);
    }
}

std::vector<uint64_t> NTT::forward(const std::vector<uint64_t>& coeffs) {
    if (!initialized_) {
        throw std::runtime_error("NTT not initialized");
    }
    
    size_t n = coeffs.size();
    uint64_t q = current_params->q;
    uint64_t psi = current_params->psi;
    
    std::vector<uint64_t> result = coeffs;
    
    // Apply input twisting for negacyclic NTT
    // Multiply by psi^i where psi^(2n) = 1
    for (size_t i = 0; i < n; ++i) {
        uint64_t twist = mod_pow(psi, i, q);
        result[i] = (static_cast<__uint128_t>(result[i]) * twist) % q;
    }
    
    // Standard NTT
    ntt_forward(result);
    
    return result;
}

void NTT::inverse(Polynomial& poly) {
    if (!initialized_) {
        throw std::runtime_error("NTT not initialized");
    }
    
    std::vector<uint64_t> coeffs(poly.size());
    for (size_t i = 0; i < poly.size(); ++i) {
        coeffs[i] = static_cast<uint64_t>(poly[i]);
    }
    
    coeffs = inverse(coeffs);
    
    for (size_t i = 0; i < poly.size(); ++i) {
        poly[i] = static_cast<int64_t>(coeffs[i]);
    }
}

std::vector<uint64_t> NTT::inverse(const std::vector<uint64_t>& coeffs) {
    if (!initialized_) {
        throw std::runtime_error("NTT not initialized");
    }
    
    size_t n = coeffs.size();
    uint64_t q = current_params->q;
    uint64_t psi_inv = current_params->psi_inv;
    uint64_t n_inv = current_params->n_inv;
    
    std::vector<uint64_t> result = coeffs;
    
    // Standard inverse NTT
    ntt_inverse(result);
    
    // Apply output twisting and scaling for negacyclic NTT
    for (size_t i = 0; i < n; ++i) {
        uint64_t twist = mod_pow(psi_inv, i, q);
        result[i] = (static_cast<__uint128_t>(result[i]) * twist) % q;
        result[i] = (static_cast<__uint128_t>(result[i]) * n_inv) % q;
    }
    
    return result;
}

void NTT::pointwise_multiply(Polynomial& result, const Polynomial& a, const Polynomial& b) {
    if (a.size() != b.size() || result.size() != a.size()) {
        throw std::invalid_argument("Polynomial size mismatch");
    }
    
    uint64_t q = current_params->q;
    for (size_t i = 0; i < a.size(); ++i) {
        uint64_t prod = (static_cast<__uint128_t>(a[i]) * static_cast<uint64_t>(b[i])) % q;
        result[i] = static_cast<int64_t>(prod);
    }
}

void NTT::bit_reverse(std::vector<uint64_t>& coeffs) {
    size_t n = coeffs.size();
    size_t log_n = 0;
    size_t temp = n;
    while (temp > 1) {
        temp >>= 1;
        log_n++;
    }
    
    for (size_t i = 0; i < n; ++i) {
        size_t j = reverse_bits(i, log_n);
        if (i < j) {
            std::swap(coeffs[i], coeffs[j]);
        }
    }
}

size_t NTT::reverse_bits(size_t x, size_t log_n) {
    size_t result = 0;
    for (size_t i = 0; i < log_n; ++i) {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    return result;
}

void NTT::ntt_forward(std::vector<uint64_t>& coeffs) {
    size_t n = coeffs.size();
    uint64_t q = current_params->q;
    uint64_t psi = current_params->psi;
    
    // Bit-reverse the input
    bit_reverse(coeffs);
    
    // Cooley-Tukey NTT
    for (size_t len = 2; len <= n; len <<= 1) {
        uint64_t w_len = mod_pow(psi, n / len, q);
        for (size_t i = 0; i < n; i += len) {
            uint64_t w = 1;
            for (size_t j = 0; j < len / 2; ++j) {
                uint64_t u = coeffs[i + j];
                uint64_t v = (static_cast<__uint128_t>(coeffs[i + j + len/2]) * w) % q;
                
                coeffs[i + j] = (u + v) % q;
                coeffs[i + j + len/2] = (u + q - v) % q;
                
                w = (static_cast<__uint128_t>(w) * w_len) % q;
            }
        }
    }
}

void NTT::ntt_inverse(std::vector<uint64_t>& coeffs) {
    size_t n = coeffs.size();
    uint64_t q = current_params->q;
    uint64_t psi_inv = current_params->psi_inv;
    
    // Cooley-Tukey inverse NTT
    for (size_t len = n; len >= 2; len >>= 1) {
        uint64_t w_len = mod_pow(psi_inv, n / len, q);
        for (size_t i = 0; i < n; i += len) {
            uint64_t w = 1;
            for (size_t j = 0; j < len / 2; ++j) {
                uint64_t u = coeffs[i + j];
                uint64_t v = coeffs[i + j + len/2];
                
                coeffs[i + j] = (u + v) % q;
                coeffs[i + j + len/2] = (static_cast<__uint128_t>(u + q - v) * w) % q;
                
                w = (static_cast<__uint128_t>(w) * w_len) % q;
            }
        }
    }
    
    // Bit-reverse the output
    bit_reverse(coeffs);
}

} // namespace rlwe
