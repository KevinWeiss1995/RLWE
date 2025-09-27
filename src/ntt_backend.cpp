#include "rlwe/ntt_backend.h"
#include "rlwe/parameters.h"
#include <stdexcept>
#include <map>
#include <memory>

namespace rlwe {

// Our naive implementation as a backend
class NaiveNTTBackend : public NTTBackend {
public:
    void forward_transform(Polynomial& poly) override {
        // Currently just pass through - no actual NTT
        (void)poly;
    }
    
    void inverse_transform(Polynomial& poly) override {
        // Currently just pass through - no actual NTT
        (void)poly;
    }
    
    void pointwise_multiply(Polynomial& result, const Polynomial& a, const Polynomial& b) override {
        // Use our naive negacyclic multiplication
        result = a.multiply_naive(b);
    }
    
    std::string get_name() const override {
        return "Naive O(n²) Backend";
    }
    
    std::string get_version() const override {
        return "1.0.0";
    }
    
    bool supports_parameter_set(size_t n, uint64_t q) const override {
        // Our naive implementation supports any parameters
        (void)n; (void)q;
        return true;
    }
    
    bool initialize(size_t n, uint64_t q, uint64_t psi, uint64_t psi_inv, uint64_t n_inv) override {
        // Store parameters for potential future use
        n_ = n;
        q_ = q;
        psi_ = psi;
        psi_inv_ = psi_inv;
        n_inv_ = n_inv;
        initialized_ = true;
        return true;
    }
    
    bool is_initialized() const override {
        return initialized_;
    }
    
private:
    bool initialized_ = false;
    size_t n_;
    uint64_t q_, psi_, psi_inv_, n_inv_;
};

// Placeholder for SEAL backend (would be implemented when SEAL is available)
class SealNTTBackend : public NTTBackend {
public:
    void forward_transform(Polynomial& poly) override {
        throw std::runtime_error("SEAL backend not yet implemented - requires SEAL library integration");
    }
    
    void inverse_transform(Polynomial& poly) override {
        throw std::runtime_error("SEAL backend not yet implemented - requires SEAL library integration");
    }
    
    void pointwise_multiply(Polynomial& result, const Polynomial& a, const Polynomial& b) override {
        throw std::runtime_error("SEAL backend not yet implemented - requires SEAL library integration");
    }
    
    std::string get_name() const override {
        return "Microsoft SEAL Backend";
    }
    
    std::string get_version() const override {
        return "4.1.0 (placeholder)";
    }
    
    bool supports_parameter_set(size_t n, uint64_t q) const override {
        // SEAL supports powers of 2 and specific moduli
        return (n & (n - 1)) == 0 && n >= 1024 && n <= 32768;
    }
    
    bool initialize(size_t n, uint64_t q, uint64_t psi, uint64_t psi_inv, uint64_t n_inv) override {
        // Would initialize SEAL context here
        (void)n; (void)q; (void)psi; (void)psi_inv; (void)n_inv;
        return false; // Not implemented yet
    }
    
    bool is_initialized() const override {
        return false; // Not implemented yet
    }
};

// Our optimized NTT backend (future implementation)
class OptimizedNTTBackend : public NTTBackend {
public:
    void forward_transform(Polynomial& poly) override {
        if (!initialized_) {
            throw std::runtime_error("OptimizedNTT backend not initialized");
        }
        
        // TODO: Implement proper negacyclic NTT
        // For now, fall back to naive
        (void)poly;
    }
    
    void inverse_transform(Polynomial& poly) override {
        if (!initialized_) {
            throw std::runtime_error("OptimizedNTT backend not initialized");
        }
        
        // TODO: Implement proper negacyclic NTT
        (void)poly;
    }
    
    void pointwise_multiply(Polynomial& result, const Polynomial& a, const Polynomial& b) override {
        if (!initialized_) {
            throw std::runtime_error("OptimizedNTT backend not initialized");
        }
        
        // For now, use naive multiplication
        result = a.multiply_naive(b);
    }
    
    std::string get_name() const override {
        return "Custom Optimized NTT Backend";
    }
    
    std::string get_version() const override {
        return "1.0.0-dev";
    }
    
    bool supports_parameter_set(size_t n, uint64_t q) const override {
        // Our optimized version supports power-of-2 dimensions
        return (n & (n - 1)) == 0 && n >= 256;
    }
    
    size_t get_optimal_batch_size() const override {
        return 8; // Optimized for batch processing
    }
    
    bool supports_batch_operations() const override {
        return true;
    }
    
    bool initialize(size_t n, uint64_t q, uint64_t psi, uint64_t psi_inv, uint64_t n_inv) override {
        n_ = n;
        q_ = q;
        psi_ = psi;
        psi_inv_ = psi_inv;
        n_inv_ = n_inv;
        initialized_ = true;
        return true;
    }
    
    bool is_initialized() const override {
        return initialized_;
    }
    
private:
    bool initialized_ = false;
    size_t n_;
    uint64_t q_, psi_, psi_inv_, n_inv_;
};

// Factory implementation
std::unique_ptr<NTTBackend> NTTBackendFactory::create(BackendType type) {
    switch (type) {
        case BackendType::NAIVE:
            return std::make_unique<NaiveNTTBackend>();
        case BackendType::SEAL:
            return std::make_unique<SealNTTBackend>();
        case BackendType::PALISADE:
            throw std::runtime_error("PALISADE backend not yet implemented");
        case BackendType::CUSTOM_OPTIMIZED:
            return std::make_unique<OptimizedNTTBackend>();
        default:
            throw std::invalid_argument("Unknown NTT backend type");
    }
}

std::vector<NTTBackendFactory::BackendType> NTTBackendFactory::get_available_backends() {
    return {
        BackendType::NAIVE,
        BackendType::CUSTOM_OPTIMIZED
        // BackendType::SEAL,     // Available when SEAL is linked
        // BackendType::PALISADE  // Available when PALISADE is linked
    };
}

NTTBackendFactory::BackendType NTTBackendFactory::get_best_backend_for_parameters(size_t n, uint64_t q) {
    // Strategy: prefer optimized backends for larger parameters
    if (n >= 2048) {
        // For large parameters, try optimized backends first
        auto backends = get_available_backends();
        for (auto type : {BackendType::SEAL, BackendType::CUSTOM_OPTIMIZED}) {
            if (std::find(backends.begin(), backends.end(), type) != backends.end()) {
                auto backend = create(type);
                if (backend->supports_parameter_set(n, q)) {
                    return type;
                }
            }
        }
    }
    
    // Fall back to naive implementation
    return BackendType::NAIVE;
}

std::string NTTBackendFactory::backend_type_to_string(BackendType type) {
    switch (type) {
        case BackendType::NAIVE: return "Naive";
        case BackendType::SEAL: return "SEAL";
        case BackendType::PALISADE: return "PALISADE";
        case BackendType::CUSTOM_OPTIMIZED: return "CustomOptimized";
        default: return "Unknown";
    }
}

// Global backend management
static std::unique_ptr<NTTBackend> global_backend = nullptr;

void set_ntt_backend(NTTBackendFactory::BackendType type) {
    global_backend = NTTBackendFactory::create(type);
    
    // Initialize with current parameters if available
    if (current_params) {
        global_backend->initialize(
            current_params->n,
            current_params->q,
            current_params->psi,
            current_params->psi_inv,
            current_params->n_inv
        );
    }
}

NTTBackend* get_ntt_backend() {
    if (!global_backend) {
        // Auto-select best backend
        if (current_params) {
            auto best_type = NTTBackendFactory::get_best_backend_for_parameters(
                current_params->n, current_params->q
            );
            set_ntt_backend(best_type);
        } else {
            set_ntt_backend(NTTBackendFactory::BackendType::NAIVE);
        }
    }
    return global_backend.get();
}

std::string get_current_ntt_backend_info() {
    auto backend = get_ntt_backend();
    return backend->get_name() + " v" + backend->get_version();
}

} // namespace rlwe
