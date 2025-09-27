#pragma once

#include "polynomial.h"
#include <memory>
#include <string>

namespace rlwe {

// Abstract NTT backend interface - allows pluggable implementations
class NTTBackend {
public:
    virtual ~NTTBackend() = default;
    
    // Core NTT operations
    virtual void forward_transform(Polynomial& poly) = 0;
    virtual void inverse_transform(Polynomial& poly) = 0;
    virtual void pointwise_multiply(Polynomial& result, const Polynomial& a, const Polynomial& b) = 0;
    
    // Backend information
    virtual std::string get_name() const = 0;
    virtual std::string get_version() const = 0;
    virtual bool supports_parameter_set(size_t n, uint64_t q) const = 0;
    
    // Performance characteristics
    virtual size_t get_optimal_batch_size() const { return 1; }
    virtual bool supports_batch_operations() const { return false; }
    
    // Initialization
    virtual bool initialize(size_t n, uint64_t q, uint64_t psi, uint64_t psi_inv, uint64_t n_inv) = 0;
    virtual bool is_initialized() const = 0;
};

// Factory for creating NTT backends
class NTTBackendFactory {
public:
    enum class BackendType {
        NAIVE,          // Our O(n²) implementation
        SEAL,           // Microsoft SEAL (when available)
        PALISADE,       // PALISADE library (when available)
        CUSTOM_OPTIMIZED // Our optimized NTT
    };
    
    static std::unique_ptr<NTTBackend> create(BackendType type);
    static std::vector<BackendType> get_available_backends();
    static BackendType get_best_backend_for_parameters(size_t n, uint64_t q);
    static std::string backend_type_to_string(BackendType type);
};

// Global backend management
void set_ntt_backend(NTTBackendFactory::BackendType type);
NTTBackend* get_ntt_backend();
std::string get_current_ntt_backend_info();

} // namespace rlwe
