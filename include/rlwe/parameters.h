#pragma once

#include <cstdint>
#include <array>

namespace rlwe {

// Security levels
enum class SecurityLevel {
    LEVEL_128 = 128,
    LEVEL_192 = 192,
    LEVEL_256 = 256
};

// Parameter sets for different security levels
struct Parameters {
    size_t n;           // Ring dimension
    uint64_t q;         // Modulus
    double sigma;       // Gaussian parameter
    size_t k;           // Binomial parameter
    
    // NTT parameters
    uint64_t psi;       // 2n-th root of unity
    uint64_t psi_inv;   // Inverse of psi
    uint64_t n_inv;     // Inverse of n mod q
    
    static Parameters get(SecurityLevel level);
    
private:
    Parameters(size_t n_, uint64_t q_, double sigma_, size_t k_, 
               uint64_t psi_, uint64_t psi_inv_, uint64_t n_inv_)
        : n(n_), q(q_), sigma(sigma_), k(k_), 
          psi(psi_), psi_inv(psi_inv_), n_inv(n_inv_) {}
};

// Global parameter access
extern const Parameters* current_params;
void set_parameters(SecurityLevel level);

// Convenience accessors
inline size_t get_n() { return current_params->n; }
inline uint64_t get_q() { return current_params->q; }
inline double get_sigma() { return current_params->sigma; }
inline size_t get_k() { return current_params->k; }

} // namespace rlwe
