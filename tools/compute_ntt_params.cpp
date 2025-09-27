#include <iostream>
#include <cstdint>
#include <vector>
#include <cmath>

// Compute a^b mod m
uint64_t mod_pow(uint64_t a, uint64_t b, uint64_t m) {
    if (m == 1) return 0;
    uint64_t result = 1;
    a %= m;
    while (b > 0) {
        if (b & 1) {
            result = (static_cast<__uint128_t>(result) * a) % m;
        }
        b >>= 1;
        a = (static_cast<__uint128_t>(a) * a) % m;
    }
    return result;
}

// Extended Euclidean algorithm to find modular inverse
uint64_t mod_inverse(uint64_t a, uint64_t m) {
    int64_t old_r = static_cast<int64_t>(m);
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
        old_s += static_cast<int64_t>(m);
    }
    
    return static_cast<uint64_t>(old_s);
}

// Find a primitive 2n-th root of unity modulo q
uint64_t find_primitive_root(uint64_t q, uint64_t n) {
    uint64_t order = 2 * n;
    
    // Check if q-1 is divisible by order
    if ((q - 1) % order != 0) {
        std::cout << "q-1 = " << (q-1) << " is not divisible by 2n = " << order << std::endl;
        return 0;
    }
    
    // Try different generators
    for (uint64_t g = 2; g < q; ++g) {
        // Check if g^((q-1)/order) is a primitive order-th root of unity
        uint64_t candidate = mod_pow(g, (q - 1) / order, q);
        
        // Verify it's primitive (order of candidate should be exactly 'order')
        if (mod_pow(candidate, order, q) == 1) {
            // Check that no smaller power gives 1
            bool is_primitive = true;
            for (uint64_t d = 1; d < order; ++d) {
                if (order % d == 0 && mod_pow(candidate, d, q) == 1) {
                    is_primitive = false;
                    break;
                }
            }
            
            if (is_primitive) {
                return candidate;
            }
        }
    }
    
    return 0;
}

int main() {
    std::cout << "Computing NTT parameters for RLWE..." << std::endl;
    
    struct ParamSet {
        uint64_t q;
        uint64_t n;
        const char* name;
    };
    
    std::vector<ParamSet> params = {
        {12289, 1024, "Level 128 (n=1024)"},
        {12289, 2048, "Level 192 (n=2048)"},
        {40961, 4096, "Level 256 (n=4096)"}
    };
    
    for (const auto& param : params) {
        std::cout << "\n=== " << param.name << " ===" << std::endl;
        std::cout << "q = " << param.q << ", n = " << param.n << std::endl;
        std::cout << "Looking for primitive " << (2 * param.n) << "-th root of unity mod " << param.q << std::endl;
        
        // Check if NTT is possible
        if ((param.q - 1) % (2 * param.n) != 0) {
            std::cout << "❌ NTT not possible: q-1 = " << (param.q - 1) 
                      << " is not divisible by 2n = " << (2 * param.n) << std::endl;
            continue;
        }
        
        uint64_t psi = find_primitive_root(param.q, param.n);
        if (psi == 0) {
            std::cout << "❌ Could not find primitive root" << std::endl;
            continue;
        }
        
        uint64_t psi_inv = mod_inverse(psi, param.q);
        uint64_t n_inv = mod_inverse(param.n, param.q);
        
        std::cout << "✅ Found parameters:" << std::endl;
        std::cout << "  psi = " << psi << " (primitive " << (2 * param.n) << "-th root of unity)" << std::endl;
        std::cout << "  psi_inv = " << psi_inv << std::endl;
        std::cout << "  n_inv = " << n_inv << std::endl;
        
        // Verify
        std::cout << "Verification:" << std::endl;
        std::cout << "  psi^(2n) mod q = " << mod_pow(psi, 2 * param.n, param.q) << " (should be 1)" << std::endl;
        uint64_t psi_check = (static_cast<__uint128_t>(psi) * psi_inv) % param.q;
        uint64_t n_check = (static_cast<__uint128_t>(param.n) * n_inv) % param.q;
        std::cout << "  (psi * psi_inv) mod q = " << psi_check << " (should be 1)" << std::endl;
        std::cout << "  (n * n_inv) mod q = " << n_check << " (should be 1)" << std::endl;
    }
    
    return 0;
}
