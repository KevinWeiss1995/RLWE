#include "rlwe/rng.h"
#include <stdexcept>
#include <cmath>

#ifdef __APPLE__
#include <Security/Security.h>
#elif defined(__linux__)
#include <sys/random.h>
#elif defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
#endif

namespace rlwe {

CSPRNG& CSPRNG::instance() {
    static CSPRNG instance;
    return instance;
}

CSPRNG::result_type CSPRNG::operator()() {
    return get_os_random();
}

void CSPRNG::generate_bytes(uint8_t* buffer, size_t length) {
    if (length == 0) return;
    
#ifdef __APPLE__
    if (SecRandomCopyBytes(kSecRandomDefault, length, buffer) != errSecSuccess) {
        throw std::runtime_error("Failed to generate random bytes");
    }
#elif defined(__linux__)
    ssize_t result = getrandom(buffer, length, 0);
    if (result < 0 || static_cast<size_t>(result) != length) {
        throw std::runtime_error("Failed to generate random bytes");
    }
#elif defined(_WIN32)
    HCRYPTPROV hProv;
    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        throw std::runtime_error("Failed to acquire crypto context");
    }
    if (!CryptGenRandom(hProv, length, buffer)) {
        CryptReleaseContext(hProv, 0);
        throw std::runtime_error("Failed to generate random bytes");
    }
    CryptReleaseContext(hProv, 0);
#else
    // Fallback to std::random_device (not cryptographically secure)
    static std::random_device rd;
    for (size_t i = 0; i < length; ++i) {
        buffer[i] = static_cast<uint8_t>(rd());
    }
#endif
}

CSPRNG::result_type CSPRNG::get_os_random() {
    result_type value;
    generate_bytes(reinterpret_cast<uint8_t*>(&value), sizeof(value));
    return value;
}

uint64_t CSPRNG::uniform_uint64() {
    return operator()();
}

uint64_t CSPRNG::uniform_uint64(uint64_t max) {
    if (max == 0) return 0;
    
    // Avoid modulo bias using rejection sampling
    uint64_t limit = UINT64_MAX - (UINT64_MAX % max);
    uint64_t value;
    
    do {
        value = uniform_uint64();
    } while (value >= limit);
    
    return value % max;
}

double CSPRNG::uniform_double() {
    // Generate a random 64-bit integer and convert to [0,1)
    uint64_t value = uniform_uint64();
    return static_cast<double>(value) / static_cast<double>(UINT64_MAX);
}

double CSPRNG::gaussian(double mean, double stddev) {
    if (has_spare_gaussian_) {
        has_spare_gaussian_ = false;
        return spare_gaussian_ * stddev + mean;
    }
    
    // Box-Muller transform
    double u1, u2;
    do {
        u1 = uniform_double();
    } while (u1 == 0.0); // Ensure u1 != 0
    
    u2 = uniform_double();
    
    double mag = stddev * std::sqrt(-2.0 * std::log(u1));
    double z0 = mag * std::cos(2.0 * M_PI * u2) + mean;
    double z1 = mag * std::sin(2.0 * M_PI * u2) + mean;
    
    spare_gaussian_ = z1;
    has_spare_gaussian_ = true;
    
    return z0;
}

int32_t CSPRNG::binomial(size_t k) {
    int32_t result = 0;
    for (size_t i = 0; i < k; ++i) {
        result += (uniform_uint64(2) == 1) ? 1 : -1;
    }
    return result;
}

} // namespace rlwe
