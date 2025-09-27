// rlwe_part1_fixed.cpp -- Part 1: headers, types, RNG, helpers, basic poly operations

#include <array>
#include <cstdint>
#include <iostream>
#include <random>
#include <chrono>
#include <vector>
#include <algorithm>
#include <stdexcept>
#include <Security/Security.h> // macOS CSPRNG

// Constants
constexpr size_t N = 16;           // ring degree
constexpr int64_t Q = 12289;       // modulus

using coeff_t = int64_t;                // coefficient type
using poly = std::array<coeff_t, N>;    // polynomial type

// Reduce integer into [0, Q)
inline coeff_t modq(int64_t x) {
    x %= Q;
    if (x < 0) x += Q;
    return x;
}

// --------------------
// CSPRNG wrapper (conforms to URNG)
// --------------------
struct RNG {
    using result_type = uint64_t;

    static constexpr result_type min() noexcept { return 0; }
    static constexpr result_type max() noexcept { return UINT64_MAX; }

    // returns a fresh 64-bit random word from the OS CSPRNG
    result_type operator()() {
        result_type val;
        if (SecRandomCopyBytes(kSecRandomDefault, sizeof(val), reinterpret_cast<uint8_t*>(&val)) != errSecSuccess) {
            throw std::runtime_error("CSPRNG failure: SecRandomCopyBytes");
        }
        return val;
    }
} rng;

// Sample a uniformly random polynomial in R_q
inline poly sample_uniform_poly() {
    std::uniform_int_distribution<int64_t> dist(0, Q - 1);
    poly r{};
    for (size_t i = 0; i < N; ++i) r[i] = dist(rng);
    return r;
}

// Sample a small polynomial using a centered binomial-like sampler
inline poly sample_small_poly(int k = 4) {
    poly r{};
    std::uniform_int_distribution<int> bit(0, 1);
    for (size_t i = 0; i < N; ++i) {
        int acc = 0;
        for (int j = 0; j < k; ++j) acc += bit(rng);
        for (int j = 0; j < k; ++j) acc -= bit(rng);
        r[i] = acc;
    }
    return r;
}

// Negacyclic polynomial multiplication (naive O(N^2)) for R_q = Z_q[x]/(x^N + 1)
inline poly poly_mul(const poly &a, const poly &b) {
    std::array<int64_t, 2 * N> tmp{};
    for (size_t i = 0; i < N; ++i) {
        for (size_t j = 0; j < N; ++j){
            tmp[i + j] += a[i] * b[j];
        }
    }
    poly res{};
    for (size_t k = 0; k < 2 * N; ++k) {
        if (k < N) res[k] += tmp[k];
        else res[k - N] -= tmp[k];   // x^N == -1 (negacyclic)
    }
    for (size_t i = 0; i < N; ++i) res[i] = modq(res[i]);
    return res;
}

// Add two polynomials
inline poly poly_add(const poly &a, const poly &b) {
    poly res{};
    for (size_t i = 0; i < N; ++i) res[i] = modq(a[i] + b[i]);
    return res;
}

// Scalar multiplication
inline poly poly_scalar_mul(const poly &a, coeff_t s) {
    poly res{};
    for (size_t i = 0; i < N; ++i) res[i] = modq(a[i] * s);
    return res;
}

// Print a polynomial
inline void print_poly(const poly &p) {
    for (size_t i = 0; i < N; ++i) {
        std::cout << p[i] << (i + 1 == N ? "" : " ");
    }
    std::cout << "\n";
}

// (rest of your keygen/encrypt/decrypt code follows...)


// Key structs (consistent naming)
struct PublicKey {
    poly a;
    poly b;
};

struct SecretKey {
    poly s;
};

inline std::pair<PublicKey, SecretKey> keygen() {
    poly a = sample_uniform_poly();
    poly s = sample_small_poly();
    poly e = sample_small_poly();

    poly b = poly_add(poly_mul(a, s), e);

    PublicKey pk{a, b};
    SecretKey sk{s};
    return {pk, sk};
}

struct Ciphertext {
    poly u;
    poly v;
};

// message m is a polynomial with coefficients 0 or 1
inline Ciphertext encrypt(const PublicKey &pk, const poly &m) {
    poly r = sample_small_poly();
    poly e1 = sample_small_poly();
    poly e2 = sample_small_poly();

    poly u = poly_add(poly_mul(pk.a, r), e1);
    poly v = poly_add(poly_mul(pk.b, r), e2);

    // encode (use parentheses to ensure correct order)
    for (size_t i = 0; i < N; ++i) {
        v[i] = modq(v[i] + m[i] * (Q / 2));
    }
    return Ciphertext{u, v};
}

// Decrypt a ciphertext
inline poly decrypt(const SecretKey &sk, const Ciphertext &ct) {
    // compute v - u*s
    poly us = poly_mul(ct.u, sk.s);
    poly diff{};
    for (size_t i = 0; i < N; ++i) {
        diff[i] = modq(ct.v[i] - us[i]);
    }

    // recover message by threshold
    poly m{};
    for (size_t i = 0; i < N; ++i) {
        int64_t x = diff[i];
        if (x > Q/4 && x < 3 * Q / 4)
            m[i] = 1;
        else
            m[i] = 0;
    }
    return m;
}

// Small test harness
int main() {
    auto [pk, sk] = keygen();

    std::cout << "a = "; print_poly(pk.a);
    std::cout << "b = "; print_poly(pk.b);
    std::cout << "s = "; print_poly(sk.s);

    // make a random message of bits (0/1)
    poly m{};
    for (size_t i = 0; i < N; ++i) m[i] = (rng() & 1);

    std::cout << "m = "; print_poly(m);

    Ciphertext ct = encrypt(pk, m);
    std::cout << "u = "; print_poly(ct.u);
    std::cout << "v = "; print_poly(ct.v);

    poly m2 = decrypt(sk, ct);
    std::cout << "m_dec = "; print_poly(m2);

    return 0;
}
