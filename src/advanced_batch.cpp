#include "rlwe/advanced_rlwe.h"
#include "rlwe/ntt_backend.h"
#include <thread>
#include <algorithm>
#include <future>
#include <fstream>

namespace rlwe {
namespace advanced {

// BatchProcessor implementation
std::vector<Ciphertext> BatchProcessor::batch_encrypt(
    const PublicKey& pk, 
    const std::vector<std::vector<uint8_t>>& messages
) {
    std::vector<Ciphertext> results;
    results.reserve(messages.size());
    
    // Get optimal batch size from NTT backend
    auto backend = get_ntt_backend();
    size_t batch_size = backend->get_optimal_batch_size();
    
    if (backend->supports_batch_operations() && messages.size() >= batch_size) {
        // Use backend's batch operations if available
        // For now, process sequentially but could be optimized per backend
        for (const auto& message : messages) {
            results.push_back(pk.encrypt(message));
        }
    } else {
        // Standard sequential processing
        for (const auto& message : messages) {
            results.push_back(pk.encrypt(message));
        }
    }
    
    return results;
}

std::vector<std::vector<uint8_t>> BatchProcessor::batch_decrypt(
    const SecretKey& sk,
    const std::vector<Ciphertext>& ciphertexts
) {
    std::vector<std::vector<uint8_t>> results;
    results.reserve(ciphertexts.size());
    
    // Sequential decryption (could be parallelized)
    for (const auto& ct : ciphertexts) {
        results.push_back(sk.decrypt(ct));
    }
    
    return results;
}

std::vector<std::future<Ciphertext>> BatchProcessor::async_encrypt(
    const PublicKey& pk,
    const std::vector<std::vector<uint8_t>>& messages
) {
    std::vector<std::future<Ciphertext>> futures;
    futures.reserve(messages.size());
    
    // Determine optimal number of threads
    size_t num_threads = std::min(
        static_cast<size_t>(std::thread::hardware_concurrency()),
        messages.size()
    );
    
    if (num_threads <= 1 || messages.size() < 4) {
        // Single-threaded for small batches
        for (const auto& message : messages) {
            futures.push_back(std::async(std::launch::deferred, [&pk, message]() {
                return pk.encrypt(message);
            }));
        }
    } else {
        // Multi-threaded processing
        for (const auto& message : messages) {
            futures.push_back(std::async(std::launch::async, [&pk, message]() {
                return pk.encrypt(message);
            }));
        }
    }
    
    return futures;
}

Ciphertext BatchProcessor::pack_encrypt(const PublicKey& pk, const std::vector<bool>& bits) {
    if (bits.empty()) {
        throw std::invalid_argument("Cannot pack empty bit vector");
    }
    
    // Pack bits into polynomial coefficients
    Polynomial packed_poly(get_n());
    
    size_t max_bits = std::min(bits.size(), get_n());
    for (size_t i = 0; i < max_bits; ++i) {
        packed_poly[i] = bits[i] ? 1 : 0;
    }
    
    return pk.encrypt_polynomial(packed_poly);
}

std::vector<bool> BatchProcessor::unpack_decrypt(const SecretKey& sk, const Ciphertext& packed_ct) {
    Polynomial decrypted = sk.decrypt_polynomial(packed_ct);
    
    std::vector<bool> bits;
    bits.reserve(decrypted.size());
    
    for (size_t i = 0; i < decrypted.size(); ++i) {
        bits.push_back(decrypted[i] != 0);
    }
    
    return bits;
}

// StreamCipher implementation
StreamCipher::StreamCipher(const PublicKey& pk, size_t buffer_size)
    : pk_(pk), buffer_size_(buffer_size) {
    buffer_.reserve(buffer_size_);
}

void StreamCipher::write(const uint8_t* data, size_t length) {
    size_t offset = 0;
    
    while (offset < length) {
        size_t space_left = buffer_size_ - buffer_.size();
        size_t to_copy = std::min(space_left, length - offset);
        
        buffer_.insert(buffer_.end(), data + offset, data + offset + to_copy);
        offset += to_copy;
        
        // If buffer is full, encrypt it
        if (buffer_.size() >= buffer_size_) {
            encrypted_chunks_.push_back(pk_.encrypt(buffer_));
            buffer_.clear();
        }
    }
}

std::vector<Ciphertext> StreamCipher::read_encrypted_chunks() {
    std::vector<Ciphertext> chunks = std::move(encrypted_chunks_);
    encrypted_chunks_.clear();
    return chunks;
}

void StreamCipher::finalize() {
    // Encrypt any remaining data in buffer
    if (!buffer_.empty()) {
        encrypted_chunks_.push_back(pk_.encrypt(buffer_));
        buffer_.clear();
    }
}

std::vector<Ciphertext> StreamCipher::encrypt_file(const PublicKey& pk, const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + filename);
    }
    
    StreamCipher cipher(pk);
    std::vector<uint8_t> chunk(4096);
    
    while (file.read(reinterpret_cast<char*>(chunk.data()), chunk.size()) || file.gcount() > 0) {
        size_t bytes_read = static_cast<size_t>(file.gcount());
        cipher.write(chunk.data(), bytes_read);
    }
    
    cipher.finalize();
    return cipher.read_encrypted_chunks();
}

void StreamCipher::decrypt_file(const SecretKey& sk, const std::vector<Ciphertext>& encrypted_chunks, const std::string& output_filename) {
    std::ofstream file(output_filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot create output file: " + output_filename);
    }
    
    for (const auto& chunk : encrypted_chunks) {
        auto decrypted_data = sk.decrypt(chunk);
        file.write(reinterpret_cast<const char*>(decrypted_data.data()), decrypted_data.size());
    }
}

} // namespace advanced
} // namespace rlwe
