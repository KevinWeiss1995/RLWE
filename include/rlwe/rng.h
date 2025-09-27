#pragma once

#include <cstdint>
#include <random>
#include <memory>

namespace rlwe {

// Cryptographically secure random number generator
class CSPRNG {
public:
    using result_type = uint64_t;
    
    static constexpr result_type min() noexcept { return 0; }
    static constexpr result_type max() noexcept { return UINT64_MAX; }
    
    // Get singleton instance
    static CSPRNG& instance();
    
    // Generate random values
    result_type operator()();
    void generate_bytes(uint8_t* buffer, size_t length);
    
    // Uniform distributions
    uint64_t uniform_uint64();
    uint64_t uniform_uint64(uint64_t max); // [0, max)
    double uniform_double(); // [0, 1)
    
    // Gaussian sampling (Box-Muller transform)
    double gaussian(double mean = 0.0, double stddev = 1.0);
    
    // Binomial sampling
    int32_t binomial(size_t k);
    
private:
    CSPRNG() = default;
    
    // Platform-specific implementations
    void seed_from_os();
    result_type get_os_random();
    
    // Gaussian state for Box-Muller
    bool has_spare_gaussian_ = false;
    double spare_gaussian_ = 0.0;
};

// Global convenience functions
inline CSPRNG& get_rng() { return CSPRNG::instance(); }

} // namespace rlwe
