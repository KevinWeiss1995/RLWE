# RLWE Enterprise Cryptographic System

## Overview

This is a RLWE cryptosystem with the following functionality:

- Secure key generation and management
- Bit-level and batch encryption/decryption
- Homomorphic operations (addition, XOR, AND)
- Multiple security levels (128, 192, 256-bit)
- Enterprise logging and monitoring
- Side-channel attack protection
- Memory safety and secure allocation

The core idea behind RLWE, simply put, is hiding a secret with slightly wrong multiplication; just enough error that reversing the math becomes impossible. You start with a familiar linear equation:

$$
b(x) = a(x)\cdot s(x) + e(x) \pmod{q}
$$

where:
- $a(x)$ is a public, uniformly random polynomial  
- $s(x)$ is a secret polynomial  
- $e(x)$ is a small error (noise) polynomial  
- All arithmetic is performed modulo a large integer $q$

If the error term $e(x)$ were zero, recovering $s(x)$ would be straightforward using linear algebra. The problem becomes hard precisely because the equation is *almost* correct, but not exact. The small error prevents exact inversion. 

## Working in a Polynomial Ring

RLWE operates over the quotient ring:

$$
R_q = \mathbb{Z}_q[x] / (x^n + 1)
$$

This means:
- Polynomial coefficients are reduced modulo $q$
- Polynomials “wrap around” due to the relation $x^n = -1$

A degree-$(n-1)$ polynomial in this ring represents an $n$-dimensional vector, but polynomial multiplication mixes coefficients together in a structured way.

---

## Why the Error Matters

Polynomial multiplication already blends coefficients across dimensions:

$$
(a \cdot s)_k = \sum_{i+j=k} a_i s_j \pmod{q}
$$

Adding the error polynomial $e(x)$ slightly perturbs every coefficient. This noise:
- Breaks exact algebraic relationships
- Prevents solving the system using linear or spectral methods
- Cannot be averaged away across samples due to ring wraparound

The result is a system that is easy to compute forward, but extremely hard to reverse.


## Quick Start

### Prerequisites

You need a C++20 compatible compiler and CMake 3.15 or later:

- GCC 9.0+ or Clang 10.0+
- CMake 3.15+
- Make or Ninja build system

### Building the System

1. Clone or download this repository
2. Open a terminal in the project directory
3. Run the build commands:

```bash
# Using Make (recommended for most users)
make

# Or using CMake directly
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

This will create:
- `build/librlwe_crypto.a` - The main library
- `build/basic_example` - Basic demonstration
- `build/enterprise_example` - Advanced features demo
- `build/benchmark` - Performance testing
- `build/test_rlwe` - Unit tests

### Running Your First Example

After building, try the basic example:

```bash
./build/basic_example
```

This will demonstrate key generation, encryption, decryption, and basic homomorphic operations across all security levels.

## Understanding the System

### Core Concepts

**Security Levels**: The system supports three security levels:
- Level 128: Uses 1024-degree polynomials, provides 128-bit security
- Level 192: Uses 2048-degree polynomials, provides 192-bit security  
- Level 256: Uses 4096-degree polynomials, provides 256-bit security

**Bit-Level Encryption**: The system encrypts individual bits rather than full bytes. When you encrypt a byte like 0x42, it encrypts only the least significant bit (LSB). This is by design and allows for efficient homomorphic operations.

**Homomorphic Operations**: You can perform computations on encrypted data:
- Addition: Add two encrypted bits
- XOR: Exclusive OR of two encrypted bits
- AND: Logical AND of two encrypted bits

### Basic Usage Example

Here's how to use the system in your own code:

```cpp
#include "rlwe/rlwe.h"
using namespace rlwe;

int main() {
    // Generate a key pair with 256-bit security
    auto [public_key, secret_key] = keygen(SecurityLevel::LEVEL_256);
    
    // Encrypt some data (encrypts the LSB of the first byte)
    std::vector<uint8_t> data = {0x42};
    auto ciphertext = public_key->encrypt(data);
    
    // Decrypt the data
    auto decrypted = secret_key->decrypt(ciphertext);
    
    // The result will be 0x0 because 0x42's LSB is 0
    std::cout << "Original: 0x42, Decrypted: 0x" << std::hex 
              << static_cast<int>(decrypted[0]) << std::endl;
    
    return 0;
}
```

### Working with Individual Bits

For more control, you can encrypt individual bits:

```cpp
// Encrypt individual bits
auto ct_true = public_key->encrypt_bit(true);
auto ct_false = public_key->encrypt_bit(false);

// Perform homomorphic XOR
auto ct_xor = ct_true + ct_false;  // This performs XOR for bits

// Decrypt the result
bool result = secret_key->decrypt_bit(ct_xor);
// result will be true (true XOR false = true)
```

### Batch Operations

For encrypting multiple bits efficiently:

```cpp
#include "rlwe/advanced_rlwe.h"
using namespace rlwe::advanced;

// Encrypt multiple bits at once
std::vector<bool> bits = {true, false, true, false};
auto batch_ciphertext = BatchProcessor::pack_encrypt(*public_key, bits);

// Decrypt all bits
auto decrypted_bits = BatchProcessor::unpack_decrypt(*secret_key, batch_ciphertext);
```

## Advanced Features

### Enterprise Logging

The system includes comprehensive logging capabilities:

```cpp
#include "rlwe/logging.h"
using namespace rlwe::logging;

// Set up logging
auto logger = std::make_unique<ConsoleLogger>(LogLevel::INFO);
LoggerManager::instance().set_default_logger(std::move(logger));

// Your crypto operations will now be automatically logged
auto [pk, sk] = keygen(SecurityLevel::LEVEL_256);
```

### Security Monitoring

The system includes built-in security features:

```cpp
#include "rlwe/security.h"
using namespace rlwe::security;

// Use secure memory for sensitive data
SecureBuffer<uint64_t> secure_data(1024);
// Memory is automatically zeroed when the buffer is destroyed

// Validate inputs
std::vector<uint64_t> coeffs = {1, 2, 3};
if (!InputValidator::validate_polynomial_coefficients(coeffs, 12289)) {
    throw std::runtime_error("Invalid coefficients");
}
```

### Performance Monitoring

Track the performance of your operations:

```cpp
#include "rlwe/logging.h"

// Performance is automatically tracked, but you can also use manual timers
{
    auto timer = LoggerManager::instance().start_performance_timer("my_operation");
    // Your code here
} // Timer automatically logs when it goes out of scope
```

## Configuration Options

### Security Levels

Choose the appropriate security level for your use case:

```cpp
// For development or low-security applications
auto [pk, sk] = keygen(SecurityLevel::LEVEL_128);

// For most production applications
auto [pk, sk] = keygen(SecurityLevel::LEVEL_192);

// For high-security applications
auto [pk, sk] = keygen(SecurityLevel::LEVEL_256);
```

### Memory Management

The system uses secure memory management by default, but you can configure it:

```cpp
// Use secure buffers for sensitive data
SecureBuffer<uint8_t> sensitive_key_material(32);

// Regular memory for non-sensitive data
std::vector<uint8_t> public_data(1024);
```

## Testing and Validation

### Running Tests

The system includes comprehensive tests:

```bash
# Run basic functionality tests
./build/test_rlwe

# Run performance benchmarks
./build/benchmark

# Run the enterprise demo with all features
./build/enterprise_example
```

### Validating Your Installation

To ensure everything is working correctly:

1. Run the basic example - it should show successful encryption/decryption for all security levels
2. Run the test suite - all tests should pass
3. Run the benchmark - you should see reasonable performance numbers

Expected performance on a modern CPU:
- Key generation: 10-50ms depending on security level
- Encryption: Sub-millisecond for individual bits
- Decryption: Sub-millisecond for individual bits

## Integration Guide

### Adding to Your Project

**Option 1: Include as a subdirectory**
```cmake
add_subdirectory(rlwe-crypto)
target_link_libraries(your_target rlwe_crypto)
```

**Option 2: Install system-wide**
```bash
make install  # Installs to /usr/local by default
```

Then in your CMake:
```cmake
find_package(RLWECrypto REQUIRED)
target_link_libraries(your_target RLWECrypto::rlwe_crypto)
```

**Option 3: Direct linking**
```bash
g++ -std=c++20 -I/path/to/rlwe/include your_code.cpp /path/to/rlwe/build/librlwe_crypto.a
```

### Thread Safety

The system is thread-safe for concurrent operations:

```cpp
// Multiple threads can safely use the same keys
auto [pk, sk] = keygen(SecurityLevel::LEVEL_256);

// Thread 1
std::thread t1([&pk]() {
    auto ct = pk->encrypt({0x01});
    // Process ciphertext...
});

// Thread 2
std::thread t2([&pk]() {
    auto ct = pk->encrypt({0x02});
    // Process ciphertext...
});
```

### Error Handling

The system uses a comprehensive exception hierarchy:

```cpp
#include "rlwe/exceptions.h"

try {
    auto [pk, sk] = keygen(SecurityLevel::LEVEL_256);
    auto ct = pk->encrypt({0x42});
    auto result = sk->decrypt(ct);
    
} catch (const ParameterException& e) {
    std::cout << "Parameter error: " << e.what() << std::endl;
} catch (const CryptographicException& e) {
    std::cout << "Crypto error: " << e.what() << std::endl;
} catch (const SecurityException& e) {
    std::cout << "Security error: " << e.what() << std::endl;
} catch (const RLWEException& e) {
    std::cout << "General RLWE error: " << e.what() << std::endl;
}
```

## Performance Optimization

### Compiler Flags

For best performance, use these compiler flags:

```bash
g++ -std=c++20 -O3 -march=native -DNDEBUG your_code.cpp
```

### Memory Optimization

- Use appropriate security levels (don't use LEVEL_256 if LEVEL_128 is sufficient)
- Reuse key pairs when possible (key generation is expensive)
- Use batch operations for multiple bits

### CPU Optimization

The system automatically uses available CPU features, but you can help by:

- Compiling with `-march=native` to use your CPU's specific features
- Using multiple threads for independent operations
- Avoiding frequent key generation

## Troubleshooting

### Common Issues

**Build Errors:**
- Ensure you have C++20 support (GCC 9.0+ or Clang 10.0+)
- Check that CMake is version 3.15 or later
- Make sure you have sufficient memory (at least 4GB for compilation)

**Runtime Issues:**
- If encryption/decryption fails, check that you're using the same security level for both operations
- Memory errors might indicate insufficient RAM - try a lower security level
- Performance issues might be due to debug builds - use Release builds for production

**Understanding Results:**
- Remember that the system encrypts bits, not bytes
- The LSB (least significant bit) is what gets encrypted
- 0x42 has LSB=0, so it decrypts to 0x0
- 0x43 has LSB=1, so it decrypts to 0x1

### Getting Help

If you encounter issues:

1. Check that your input data is valid
2. Verify that you're using matching security levels
3. Look at the example code to see correct usage patterns
4. Check the logs for detailed error information

### Performance Expectations

Typical performance on a modern CPU (Intel Core i7 or equivalent):

| Operation | Security Level 128 | Security Level 192 | Security Level 256 |
|-----------|-------------------|--------------------|--------------------|
| Key Generation | ~5ms | ~15ms | ~40ms |
| Encrypt Bit | ~0.1ms | ~0.2ms | ~0.5ms |
| Decrypt Bit | ~0.1ms | ~0.2ms | ~0.5ms |
| Homomorphic Add | ~0.1ms | ~0.2ms | ~0.5ms |

If your performance is significantly worse, check:
- You're using Release build (`-O3 -DNDEBUG`)
- You have sufficient CPU and memory
- You're not running in a debugger or profiler

## Architecture Overview

The system is organized into several key components:

**Core Cryptography** (`src/rlwe.cpp`, `include/rlwe/rlwe.h`):
- Key generation, encryption, decryption
- Basic homomorphic operations

**Polynomial Mathematics** (`src/polynomial.cpp`, `include/rlwe/polynomial.h`):
- Polynomial arithmetic operations
- Coefficient management

**Security Parameters** (`src/parameters.cpp`, `include/rlwe/parameters.h`):
- Security level definitions
- Cryptographic parameter sets

**Advanced Features** (`src/advanced_*.cpp`, `include/rlwe/advanced_rlwe.h`):
- Batch processing
- Advanced homomorphic operations
- Noise analysis

**Enterprise Features**:
- Logging system (`src/logging.cpp`, `include/rlwe/logging.h`)
- Security monitoring (`src/security.cpp`, `include/rlwe/security.h`)
- Error handling (`include/rlwe/exceptions.h`)

**NTT Backend** (`src/ntt*.cpp`, `include/rlwe/ntt*.h`):
- Number Theoretic Transform for efficient polynomial multiplication
- Pluggable backend architecture for future optimizations

This architecture allows for easy extension and optimization while maintaining a clean, easy-to-use API.

## License and Legal

This implementation is designed for educational and research purposes. For production use, ensure compliance with:

- Export control regulations (ITAR/EAR)
- Local cryptography laws and regulations
- Any applicable patents or licensing requirements

The system implements well-known cryptographic algorithms and does not contain proprietary cryptographic techniques.

## Contributing

The codebase is structured for easy extension:

- Add new security levels in `src/parameters.cpp`
- Implement new homomorphic operations in `src/advanced_homomorphic.cpp`
- Add new NTT backends in `src/ntt_backend.cpp`
- Extend logging in `src/logging.cpp`

Follow the existing code style and ensure all tests pass before submitting changes.
