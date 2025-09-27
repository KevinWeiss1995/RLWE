#include "rlwe/parameters.h"
#include <stdexcept>

namespace rlwe {

const Parameters* current_params = nullptr;

Parameters Parameters::get(SecurityLevel level) {
    switch (level) {
        case SecurityLevel::LEVEL_128:
            // n=1024, q=12289 (NTT-friendly: q = 1 + 12*1024)
            // psi = 1945 (primitive 2048-th root of unity)
            return Parameters(1024, 12289, 3.2, 6, 
                            1945, 4050, 12277);
            
        case SecurityLevel::LEVEL_192:
            // n=2048, q=12289
            // psi = 1331 (primitive 4096-th root of unity)
            return Parameters(2048, 12289, 3.2, 8,
                            1331, 7968, 12283);
            
        case SecurityLevel::LEVEL_256:
            // n=4096, q=40961 (NTT-friendly: q = 1 + 10*4096)
            // psi = 243 (primitive 8192-th root of unity)
            return Parameters(4096, 40961, 3.2, 10,
                            243, 15845, 40951);
            
        default:
            throw std::invalid_argument("Invalid security level");
    }
}

void set_parameters(SecurityLevel level) {
    static Parameters params_128 = Parameters::get(SecurityLevel::LEVEL_128);
    static Parameters params_192 = Parameters::get(SecurityLevel::LEVEL_192);
    static Parameters params_256 = Parameters::get(SecurityLevel::LEVEL_256);
    
    switch (level) {
        case SecurityLevel::LEVEL_128:
            current_params = &params_128;
            break;
        case SecurityLevel::LEVEL_192:
            current_params = &params_192;
            break;
        case SecurityLevel::LEVEL_256:
            current_params = &params_256;
            break;
        default:
            throw std::invalid_argument("Invalid security level");
    }
}

} // namespace rlwe
