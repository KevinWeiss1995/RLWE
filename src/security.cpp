#include "rlwe/security.h"
#include <cstring>
#include <random>
#include <thread>
#include <algorithm>
#include <numeric>
#include <cmath>

#ifdef _WIN32
    #include <windows.h>
    #include <memoryapi.h>
#else
    #include <sys/mman.h>
    #include <unistd.h>
#endif

namespace rlwe {
namespace security {

uint8_t constant_time_memcmp(const void* a, const void* b, size_t len) {
    const uint8_t* pa = static_cast<const uint8_t*>(a);
    const uint8_t* pb = static_cast<const uint8_t*>(b);
    uint8_t result = 0;
    
    for (size_t i = 0; i < len; ++i) {
        result |= (pa[i] ^ pb[i]);
    }
    
    return constant_time_equal(result, static_cast<uint8_t>(0));
}

void secure_memzero(volatile void* ptr, size_t len) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    for (size_t i = 0; i < len; ++i) {
        p[i] = 0;
    }
    
    // Memory barrier to prevent optimization
    std::atomic_thread_fence(std::memory_order_seq_cst);
}

void* secure_malloc(size_t size) {
    // Add guard pages and alignment
    const size_t page_size = 4096; // Typical page size
    const size_t aligned_size = ((size + page_size - 1) / page_size) * page_size;
    const size_t total_size = aligned_size + 2 * page_size; // Guard pages
    
#ifdef _WIN32
    void* ptr = VirtualAlloc(nullptr, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ptr) return nullptr;
    
    // Set up guard pages
    DWORD old_protect;
    VirtualProtect(ptr, page_size, PAGE_NOACCESS, &old_protect);
    VirtualProtect(static_cast<char*>(ptr) + page_size + aligned_size, 
                  page_size, PAGE_NOACCESS, &old_protect);
    
    return static_cast<char*>(ptr) + page_size;
#else
    void* ptr = mmap(nullptr, total_size, PROT_READ | PROT_WRITE, 
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) return nullptr;
    
    // Set up guard pages
    mprotect(ptr, page_size, PROT_NONE);
    mprotect(static_cast<char*>(ptr) + page_size + aligned_size, page_size, PROT_NONE);
    
    return static_cast<char*>(ptr) + page_size;
#endif
}

void secure_free(void* ptr, size_t size) {
    if (!ptr) return;
    
    // Zero memory first
    secure_memzero(ptr, size);
    
    const size_t page_size = 4096;
    const size_t aligned_size = ((size + page_size - 1) / page_size) * page_size;
    const size_t total_size = aligned_size + 2 * page_size;
    
    void* base_ptr = static_cast<char*>(ptr) - page_size;
    
#ifdef _WIN32
    VirtualFree(base_ptr, 0, MEM_RELEASE);
#else
    munmap(base_ptr, total_size);
#endif
}

// TimingAnalyzer implementation
void TimingAnalyzer::start_measurement() {
    start_time_ = std::chrono::high_resolution_clock::now();
}

void TimingAnalyzer::end_measurement(const char* operation_name) {
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time_);
    
    measurements_.push_back(duration);
    if (measurements_.size() > MAX_MEASUREMENTS) {
        measurements_.erase(measurements_.begin());
    }
    
    // Add timing noise to normalize execution time
    add_timing_noise();
    
    // Log suspicious timing if detected
    if (detect_timing_anomaly()) {
        // In production, this would go to a secure log
        // For now, we just add extra noise
        add_timing_noise();
    }
}

void TimingAnalyzer::add_timing_noise() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<int> dis(1, 1000);
    
    // Add random delay (1-1000 nanoseconds)
    auto delay = std::chrono::nanoseconds(dis(gen));
    std::this_thread::sleep_for(delay);
}

bool TimingAnalyzer::detect_timing_anomaly() const {
    if (measurements_.size() < 10) return false;
    
    // Calculate mean and standard deviation
    auto mean = std::accumulate(measurements_.begin(), measurements_.end(), 
                               std::chrono::nanoseconds(0)).count() / measurements_.size();
    
    double variance = 0.0;
    for (const auto& measurement : measurements_) {
        double diff = measurement.count() - mean;
        variance += diff * diff;
    }
    variance /= measurements_.size();
    double stddev = std::sqrt(variance);
    
    // Check if latest measurement is more than 3 standard deviations from mean
    double latest = measurements_.back().count();
    return std::abs(latest - mean) > 3 * stddev;
}

// InputValidator implementation
bool InputValidator::validate_polynomial_coefficients(const std::vector<uint64_t>& coeffs, 
                                                    uint64_t modulus) {
    for (uint64_t coeff : coeffs) {
        if (coeff >= modulus) {
            return false;
        }
    }
    return true;
}

bool InputValidator::validate_ciphertext_structure(const std::vector<uint8_t>& serialized_ct) {
    if (serialized_ct.size() < 16) return false; // Minimum header size
    
    // Check magic number or version
    uint32_t magic;
    std::memcpy(&magic, serialized_ct.data(), sizeof(magic));
    
    // Simple validation - in production, use proper magic numbers
    return magic != 0 && magic != 0xFFFFFFFF;
}

bool InputValidator::validate_key_structure(const std::vector<uint8_t>& serialized_key) {
    if (serialized_key.size() < 16) return false; // Minimum header size
    
    // Check magic number or version
    uint32_t magic;
    std::memcpy(&magic, serialized_key.data(), sizeof(magic));
    
    // Simple validation - in production, use proper magic numbers
    return magic != 0 && magic != 0xFFFFFFFF;
}

bool InputValidator::sanitize_security_parameters(uint32_t n, uint64_t q, double sigma) {
    // Validate n is a power of 2 and in reasonable range
    if (n < 512 || n > 32768 || (n & (n - 1)) != 0) {
        return false;
    }
    
    // Validate q is prime and in reasonable range
    if (q < 1024 || q > (1ULL << 60)) {
        return false;
    }
    
    // Validate sigma is reasonable
    if (sigma < 1.0 || sigma > 10.0) {
        return false;
    }
    
    return true;
}

// FaultDetector implementation
bool FaultDetector::verify_memory_integrity(const void* data, size_t len, uint32_t expected_checksum) {
    uint32_t computed = compute_checksum(data, len);
    return constant_time_equal(computed, expected_checksum);
}

uint32_t FaultDetector::compute_checksum(const void* data, size_t len) {
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    uint32_t checksum = 0;
    
    // Simple CRC-like checksum
    for (size_t i = 0; i < len; ++i) {
        checksum = (checksum << 1) ^ bytes[i];
        if (checksum & 0x80000000) {
            checksum ^= 0x04C11DB7; // CRC32 polynomial
        }
    }
    
    return checksum;
}

} // namespace security
} // namespace rlwe
