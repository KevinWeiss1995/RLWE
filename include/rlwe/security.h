#pragma once

#include <cstdint>
#include <vector>
#include <memory>
#include <chrono>

namespace rlwe {
namespace security {

/**
 * @brief Enterprise-grade security utilities for constant-time operations
 * and side-channel attack resistance.
 */

/**
 * @brief Constant-time conditional select
 * @param condition Selection condition (0 or 1)
 * @param true_val Value to return if condition is true
 * @param false_val Value to return if condition is false
 * @return Selected value without timing leaks
 */
template<typename T>
constexpr T constant_time_select(uint8_t condition, T true_val, T false_val) {
    // Ensure condition is 0 or 1
    condition = condition & 1;
    // Create mask: 0x00...00 or 0xFF...FF
    T mask = static_cast<T>(-(static_cast<int8_t>(condition)));
    return (true_val & mask) | (false_val & ~mask);
}

/**
 * @brief Constant-time equality check
 * @param a First value
 * @param b Second value
 * @return 1 if equal, 0 if not equal (no timing leaks)
 */
template<typename T>
constexpr uint8_t constant_time_equal(T a, T b) {
    T diff = a ^ b;
    // For integer types, reduce to single bit
    if constexpr (sizeof(T) == 1) {
        return 1 - ((diff | (diff >> 1) | (diff >> 2) | (diff >> 3) | 
                    (diff >> 4) | (diff >> 5) | (diff >> 6) | (diff >> 7)) & 1);
    } else {
        // For larger types, recursively reduce
        return constant_time_equal(static_cast<uint8_t>(diff), 
                                 static_cast<uint8_t>(diff >> 8));
    }
}

/**
 * @brief Constant-time memory comparison
 * @param a First memory block
 * @param b Second memory block
 * @param len Length in bytes
 * @return 1 if equal, 0 if different
 */
uint8_t constant_time_memcmp(const void* a, const void* b, size_t len);

/**
 * @brief Secure memory zeroing that won't be optimized away
 * @param ptr Pointer to memory to zero
 * @param len Length in bytes
 */
void secure_memzero(volatile void* ptr, size_t len);

/**
 * @brief Secure memory allocation with guard pages
 * @param size Size in bytes
 * @return Pointer to allocated memory
 */
void* secure_malloc(size_t size);

/**
 * @brief Secure memory deallocation
 * @param ptr Pointer to free
 * @param size Size in bytes (for zeroing)
 */
void secure_free(void* ptr, size_t size);

/**
 * @brief RAII wrapper for secure memory management
 */
template<typename T>
class SecureBuffer {
public:
    explicit SecureBuffer(size_t count = 1) 
        : size_(count * sizeof(T))
        , data_(static_cast<T*>(secure_malloc(size_))) {
        if (!data_) {
            throw std::bad_alloc();
        }
    }
    
    ~SecureBuffer() {
        if (data_) {
            secure_memzero(data_, size_);
            secure_free(data_, size_);
        }
    }
    
    // Non-copyable but movable
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    
    SecureBuffer(SecureBuffer&& other) noexcept 
        : size_(other.size_), data_(other.data_) {
        other.size_ = 0;
        other.data_ = nullptr;
    }
    
    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            if (data_) {
                secure_memzero(data_, size_);
                secure_free(data_, size_);
            }
            size_ = other.size_;
            data_ = other.data_;
            other.size_ = 0;
            other.data_ = nullptr;
        }
        return *this;
    }
    
    T* data() { return data_; }
    const T* data() const { return data_; }
    size_t size() const { return size_ / sizeof(T); }
    
    T& operator[](size_t idx) { return data_[idx]; }
    const T& operator[](size_t idx) const { return data_[idx]; }
    
private:
    size_t size_;
    T* data_;
};

/**
 * @brief Timing attack detection and mitigation
 */
class TimingAnalyzer {
public:
    /**
     * @brief Start timing measurement
     */
    void start_measurement();
    
    /**
     * @brief End timing measurement and add noise if needed
     * @param operation_name Name of the operation for logging
     */
    void end_measurement(const char* operation_name);
    
    /**
     * @brief Add random delay to normalize timing
     */
    void add_timing_noise();
    
    /**
     * @brief Check if timing variance is suspicious
     * @return True if potential timing attack detected
     */
    bool detect_timing_anomaly() const;
    
private:
    std::chrono::high_resolution_clock::time_point start_time_;
    std::vector<std::chrono::nanoseconds> measurements_;
    static constexpr size_t MAX_MEASUREMENTS = 1000;
};

/**
 * @brief Input validation and sanitization
 */
class InputValidator {
public:
    /**
     * @brief Validate polynomial coefficients are in valid range
     */
    static bool validate_polynomial_coefficients(const std::vector<uint64_t>& coeffs, 
                                                uint64_t modulus);
    
    /**
     * @brief Validate ciphertext structure
     */
    static bool validate_ciphertext_structure(const std::vector<uint8_t>& serialized_ct);
    
    /**
     * @brief Validate key structure
     */
    static bool validate_key_structure(const std::vector<uint8_t>& serialized_key);
    
    /**
     * @brief Sanitize input parameters
     */
    static bool sanitize_security_parameters(uint32_t n, uint64_t q, double sigma);
};

/**
 * @brief Fault injection detection
 */
class FaultDetector {
public:
    /**
     * @brief Verify computation integrity using redundant calculations
     */
    template<typename Func, typename... Args>
    static auto verify_computation(Func&& func, Args&&... args) 
        -> decltype(func(std::forward<Args>(args)...)) {
        
        // Run computation twice
        auto result1 = func(std::forward<Args>(args)...);
        auto result2 = func(std::forward<Args>(args)...);
        
        // Compare results
        if (!(result1 == result2)) {
            throw std::runtime_error("Fault injection detected: computation mismatch");
        }
        
        return result1;
    }
    
    /**
     * @brief Check memory integrity using checksums
     */
    static bool verify_memory_integrity(const void* data, size_t len, uint32_t expected_checksum);
    
    /**
     * @brief Compute checksum for memory region
     */
    static uint32_t compute_checksum(const void* data, size_t len);
};

} // namespace security
} // namespace rlwe
