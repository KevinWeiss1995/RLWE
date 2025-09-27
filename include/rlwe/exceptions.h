#pragma once

#include <stdexcept>
#include <string>
#include <cstdint>

namespace rlwe {

/**
 * @brief Base exception class for all RLWE crypto system errors
 */
class RLWEException : public std::exception {
public:
    explicit RLWEException(const std::string& message, 
                          const std::string& error_code = "",
                          const std::string& component = "")
        : message_(message), error_code_(error_code), component_(component) {
        full_message_ = "[" + component_ + "] " + error_code_ + ": " + message_;
    }
    
    const char* what() const noexcept override {
        return full_message_.c_str();
    }
    
    const std::string& get_error_code() const { return error_code_; }
    const std::string& get_component() const { return component_; }
    const std::string& get_message() const { return message_; }

private:
    std::string message_;
    std::string error_code_;
    std::string component_;
    std::string full_message_;
};

/**
 * @brief Security-related errors
 */
class SecurityException : public RLWEException {
public:
    explicit SecurityException(const std::string& message, const std::string& error_code = "SEC_ERROR")
        : RLWEException(message, error_code, "Security") {}
};

/**
 * @brief Parameter validation errors
 */
class ParameterException : public RLWEException {
public:
    explicit ParameterException(const std::string& message, const std::string& error_code = "PARAM_ERROR")
        : RLWEException(message, error_code, "Parameters") {}
};

/**
 * @brief Cryptographic operation errors
 */
class CryptographicException : public RLWEException {
public:
    explicit CryptographicException(const std::string& message, const std::string& error_code = "CRYPTO_ERROR")
        : RLWEException(message, error_code, "Cryptography") {}
};

/**
 * @brief Serialization/deserialization errors
 */
class SerializationException : public RLWEException {
public:
    explicit SerializationException(const std::string& message, const std::string& error_code = "SERIAL_ERROR")
        : RLWEException(message, error_code, "Serialization") {}
};

/**
 * @brief Memory allocation and management errors
 */
class MemoryException : public RLWEException {
public:
    explicit MemoryException(const std::string& message, const std::string& error_code = "MEMORY_ERROR")
        : RLWEException(message, error_code, "Memory") {}
};

/**
 * @brief Performance and resource errors
 */
class ResourceException : public RLWEException {
public:
    explicit ResourceException(const std::string& message, const std::string& error_code = "RESOURCE_ERROR")
        : RLWEException(message, error_code, "Resource") {}
};

/**
 * @brief Input validation errors with detailed context
 */
class ValidationException : public RLWEException {
public:
    ValidationException(const std::string& message, 
                       const std::string& parameter_name,
                       const std::string& expected_range = "",
                       const std::string& actual_value = "")
        : RLWEException(build_message(message, parameter_name, expected_range, actual_value), 
                       "VALIDATION_ERROR", "Validation")
        , parameter_name_(parameter_name)
        , expected_range_(expected_range)
        , actual_value_(actual_value) {}
    
    const std::string& get_parameter_name() const { return parameter_name_; }
    const std::string& get_expected_range() const { return expected_range_; }
    const std::string& get_actual_value() const { return actual_value_; }

private:
    std::string parameter_name_;
    std::string expected_range_;
    std::string actual_value_;
    
    static std::string build_message(const std::string& message,
                                   const std::string& parameter_name,
                                   const std::string& expected_range,
                                   const std::string& actual_value) {
        std::string result = message;
        if (!parameter_name.empty()) {
            result += " (Parameter: " + parameter_name;
            if (!expected_range.empty()) {
                result += ", Expected: " + expected_range;
            }
            if (!actual_value.empty()) {
                result += ", Actual: " + actual_value;
            }
            result += ")";
        }
        return result;
    }
};

/**
 * @brief Fault injection detection errors
 */
class FaultInjectionException : public SecurityException {
public:
    explicit FaultInjectionException(const std::string& message)
        : SecurityException(message, "FAULT_INJECTION_DETECTED") {}
};

/**
 * @brief Side-channel attack detection errors
 */
class SideChannelException : public SecurityException {
public:
    explicit SideChannelException(const std::string& message)
        : SecurityException(message, "SIDE_CHANNEL_DETECTED") {}
};

/**
 * @brief NTT computation errors
 */
class NTTException : public CryptographicException {
public:
    explicit NTTException(const std::string& message, const std::string& error_code = "NTT_ERROR")
        : CryptographicException(message, error_code) {}
};

/**
 * @brief Polynomial operation errors
 */
class PolynomialException : public CryptographicException {
public:
    explicit PolynomialException(const std::string& message, const std::string& error_code = "POLY_ERROR")
        : CryptographicException(message, error_code) {}
};

// Error code constants
namespace ErrorCodes {
    constexpr const char* INVALID_PARAMETER = "E001";
    constexpr const char* PARAMETER_OUT_OF_RANGE = "E002";
    constexpr const char* INVALID_KEY_SIZE = "E003";
    constexpr const char* INVALID_CIPHERTEXT = "E004";
    constexpr const char* SERIALIZATION_FAILED = "E005";
    constexpr const char* DESERIALIZATION_FAILED = "E006";
    constexpr const char* MEMORY_ALLOCATION_FAILED = "E007";
    constexpr const char* INVALID_SECURITY_LEVEL = "E008";
    constexpr const char* NTT_INITIALIZATION_FAILED = "E009";
    constexpr const char* POLYNOMIAL_SIZE_MISMATCH = "E010";
    constexpr const char* MODULUS_NOT_PRIME = "E011";
    constexpr const char* INVALID_NOISE_PARAMETER = "E012";
    constexpr const char* ENCRYPTION_FAILED = "E013";
    constexpr const char* DECRYPTION_FAILED = "E014";
    constexpr const char* KEY_GENERATION_FAILED = "E015";
    constexpr const char* TIMING_ANOMALY_DETECTED = "S001";
    constexpr const char* FAULT_INJECTION_DETECTED = "S002";
    constexpr const char* MEMORY_CORRUPTION_DETECTED = "S003";
    constexpr const char* INVALID_INPUT_DETECTED = "S004";
    constexpr const char* RESOURCE_EXHAUSTION = "R001";
    constexpr const char* THREAD_SAFETY_VIOLATION = "R002";
}

} // namespace rlwe
