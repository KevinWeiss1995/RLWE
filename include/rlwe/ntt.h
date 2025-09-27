#pragma once

#include "polynomial.h"
#include <vector>

namespace rlwe {

// Number Theoretic Transform for efficient polynomial multiplication
class NTT {
public:
    // Initialize NTT with current parameters
    static void initialize();
    
    // Forward NTT: time domain -> frequency domain
    static void forward(Polynomial& poly);
    static std::vector<uint64_t> forward(const std::vector<uint64_t>& coeffs);
    
    // Inverse NTT: frequency domain -> time domain  
    static void inverse(Polynomial& poly);
    static std::vector<uint64_t> inverse(const std::vector<uint64_t>& coeffs);
    
    // Point-wise multiplication in NTT domain
    static void pointwise_multiply(Polynomial& result, 
                                  const Polynomial& a, 
                                  const Polynomial& b);
    
    // Check if NTT is initialized
    static bool is_initialized();
    
private:
    static std::vector<uint64_t> powers_of_psi_;
    static std::vector<uint64_t> powers_of_psi_inv_;
    static bool initialized_;
    
    // Bit-reverse permutation
    static void bit_reverse(std::vector<uint64_t>& coeffs);
    static size_t reverse_bits(size_t x, size_t log_n);
    
    // Core NTT operations
    static void ntt_forward(std::vector<uint64_t>& coeffs);
    static void ntt_inverse(std::vector<uint64_t>& coeffs);
};

} // namespace rlwe
