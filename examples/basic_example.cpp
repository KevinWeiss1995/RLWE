#include "rlwe/rlwe.h"
#include <iostream>
#include <vector>
#include <iomanip>

using namespace rlwe;

void print_hex(const std::vector<uint8_t>& data, const std::string& label) {
    std::cout << label << ": ";
    for (size_t i = 0; i < std::min(data.size(), size_t(16)); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(data[i]) << " ";
    }
    if (data.size() > 16) std::cout << "...";
    std::cout << std::dec << " (" << data.size() << " bytes)" << std::endl;
}

int main() {
    try {
        std::cout << "=== RLWE Crypto System Demo ===" << std::endl;
        
        // Test different security levels
        for (auto level : {SecurityLevel::LEVEL_128, SecurityLevel::LEVEL_192, SecurityLevel::LEVEL_256}) {
            std::cout << "\n--- Security Level " << static_cast<int>(level) << " ---" << std::endl;
            
            // Initialize system
            initialize_rlwe(level);
            std::cout << "Initialized with n=" << get_n() << ", q=" << get_q() << std::endl;
            
            // Generate keys
            auto [pk, sk] = keygen(level);
            std::cout << "Generated key pair" << std::endl;
            
            // Test single bit encryption/decryption
            std::cout << "\nTesting bit encryption:" << std::endl;
            for (bool bit : {false, true}) {
                auto ct = pk->encrypt_bit(bit);
                bool decrypted = sk->decrypt_bit(ct);
                std::cout << "  " << bit << " -> " << decrypted 
                         << (bit == decrypted ? " ✓" : " ✗") << std::endl;
            }
            
            // Test message encryption/decryption
            std::vector<uint8_t> message = {0x42}; // Single byte
            auto ct = pk->encrypt(message);
            auto decrypted = sk->decrypt(ct);
            
            std::cout << "\nMessage encryption:" << std::endl;
            std::cout << "Original:  0x" << std::hex << static_cast<int>(message[0]) << std::dec << std::endl;
            std::cout << "Decrypted: 0x" << std::hex << static_cast<int>(decrypted[0]) << std::dec;
            std::cout << ((message[0] & 1) == (decrypted[0] & 1) ? " ✓" : " ✗") << std::endl;
            
            // Test serialization
            std::cout << "\nTesting serialization:" << std::endl;
            
            auto pk_data = pk->serialize();
            auto sk_data = sk->serialize();
            auto ct_data = ct.serialize();
            
            print_hex(pk_data, "Public key");
            print_hex(sk_data, "Secret key");
            print_hex(ct_data, "Ciphertext");
            
            // Test deserialization
            auto pk2 = PublicKey::deserialize(pk_data);
            auto sk2 = SecretKey::deserialize(sk_data);
            auto ct2 = Ciphertext::deserialize(ct_data);
            
            auto decrypted2 = sk2->decrypt(*ct2);
            std::cout << "Deserialized decryption: 0x" << std::hex << static_cast<int>(decrypted2[0]) << std::dec;
            std::cout << ((message[0] & 1) == (decrypted2[0] & 1) ? " ✓" : " ✗") << std::endl;
            
            // Test homomorphic addition
            std::cout << "\nTesting homomorphic addition:" << std::endl;
            auto ct_0 = pk->encrypt_bit(false);
            auto ct_1 = pk->encrypt_bit(true);
            auto ct_sum = ct_0 + ct_1; // Should decrypt to 1 (0 + 1 = 1)
            
            bool sum_result = sk->decrypt_bit(ct_sum);
            std::cout << "0 + 1 = " << sum_result << (sum_result == 1 ? " ✓" : " ✗") << std::endl;
        }
        
        std::cout << "\n=== Demo Complete ===" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
