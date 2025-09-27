#include "rlwe/polynomial.h"
#include "rlwe/parameters.h"
#include <algorithm>

namespace rlwe {

int64_t mod_q(int64_t x) {
    if (!current_params) {
        throw std::runtime_error("Parameters not initialized");
    }
    
    int64_t q = static_cast<int64_t>(current_params->q);
    x %= q;
    if (x < 0) x += q;
    return x;
}

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

uint64_t mod_inverse(uint64_t a, uint64_t mod) {
    // Extended Euclidean algorithm
    int64_t old_r = static_cast<int64_t>(mod);
    int64_t r = static_cast<int64_t>(a);
    int64_t old_s = 0;
    int64_t s = 1;
    
    while (r != 0) {
        int64_t quotient = old_r / r;
        
        int64_t temp = r;
        r = old_r - quotient * r;
        old_r = temp;
        
        temp = s;
        s = old_s - quotient * s;
        old_s = temp;
    }
    
    if (old_r != 1) {
        throw std::runtime_error("Modular inverse does not exist");
    }
    
    if (old_s < 0) {
        old_s += static_cast<int64_t>(mod);
    }
    
    return static_cast<uint64_t>(old_s);
}

} // namespace rlwe
