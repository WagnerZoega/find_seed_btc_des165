#pragma once
#include <cstdint>
#include <array>

class EllipticCurve {
public:
    // Constantes da curva secp256k1
    static constexpr uint32_t P = 0xFFFFFFFF;
    static constexpr uint32_t A = 0;
    static constexpr uint32_t B = 7;
    
    struct Point {
        uint32_t x[8];  // 256 bits
        uint32_t y[8];  // 256 bits
        bool infinity;
        
        Point() : infinity(true) {
            for(int i = 0; i < 8; i++) {
                x[i] = y[i] = 0;
            }
        }
    };

    // Ponto gerador G da curva secp256k1
    static const Point G;

    // Operações básicas no campo finito
    static uint32_t add_mod(uint32_t a, uint32_t b) {
        uint64_t sum = static_cast<uint64_t>(a) + static_cast<uint64_t>(b);
        return static_cast<uint32_t>(sum % P);
    }

    static uint32_t sub_mod(uint32_t a, uint32_t b) {
        return (a >= b) ? (a - b) : (P - (b - a));
    }

    static uint32_t mul_mod(uint32_t a, uint32_t b) {
        uint64_t product = static_cast<uint64_t>(a) * static_cast<uint64_t>(b);
        return static_cast<uint32_t>(product % P);
    }

    static uint32_t inv_mod(uint32_t a) {
        // Implementação do algoritmo estendido de Euclides
        int64_t t = 0, newt = 1;
        int64_t r = P, newr = a;

        while(newr != 0) {
            int64_t quotient = r / newr;
            int64_t temp = newt;
            newt = t - quotient * newt;
            t = temp;
            temp = newr;
            newr = r - quotient * newr;
            r = temp;
        }

        if(t < 0) t += P;
        return static_cast<uint32_t>(t);
    }

    // Operações com pontos da curva
    static Point double_point(const Point& p) {
        if(p.infinity) return Point();

        uint32_t lambda = calculate_lambda_double(p);
        Point result;
        
        result.x[0] = sub_mod(mul_mod(lambda, lambda), add_mod(p.x[0], p.x[0]));
        result.y[0] = sub_mod(mul_mod(lambda, sub_mod(p.x[0], result.x[0])), p.y[0]);
        result.infinity = false;
        
        return result;
    }

    static Point add_points(const Point& p1, const Point& p2) {
        if(p1.infinity) return p2;
        if(p2.infinity) return p1;
        
        if(equal_points(p1, p2)) return double_point(p1);
        
        uint32_t lambda = calculate_lambda_add(p1, p2);
        Point result;
        
        result.x[0] = sub_mod(sub_mod(mul_mod(lambda, lambda), p1.x[0]), p2.x[0]);
        result.y[0] = sub_mod(mul_mod(lambda, sub_mod(p1.x[0], result.x[0])), p1.y[0]);
        result.infinity = false;
        
        return result;
    }

    // Multiplicação escalar (multiplicação de ponto por número)
    static Point scalar_multiply(const Point& p, const uint32_t* k) {
        Point result;
        Point temp = p;
        
        for(int i = 255; i >= 0; i--) {
            result = double_point(result);
            if(k[i/32] & (1 << (i%32))) {
                result = add_points(result, temp);
            }
        }
        
        return result;
    }

private:
    static bool equal_points(const Point& p1, const Point& p2) {
        if(p1.infinity || p2.infinity) return p1.infinity == p2.infinity;
        
        for(int i = 0; i < 8; i++) {
            if(p1.x[i] != p2.x[i] || p1.y[i] != p2.y[i]) return false;
        }
        return true;
    }

    static uint32_t calculate_lambda_double(const Point& p) {
        // λ = (3x²) / (2y)
        uint32_t numerator = mul_mod(3, mul_mod(p.x[0], p.x[0]));
        uint32_t denominator = mul_mod(2, p.y[0]);
        return mul_mod(numerator, inv_mod(denominator));
    }

    static uint32_t calculate_lambda_add(const Point& p1, const Point& p2) {
        // λ = (y2 - y1) / (x2 - x1)
        uint32_t numerator = sub_mod(p2.y[0], p1.y[0]);
        uint32_t denominator = sub_mod(p2.x[0], p1.x[0]);
        return mul_mod(numerator, inv_mod(denominator));
    }
};

// Inicialização do ponto gerador G
const EllipticCurve::Point EllipticCurve::G = {
    {0x79BE667E, 0xF9DCBBAC, 0x55A06295, 0xCE870B07,
     0x029BFCDB, 0x2DCE28D9, 0x59F2815B, 0x16F81798},
    {0x483ADA77, 0x26A3C465, 0x5DA4FBFC, 0x0E1108A8,
     0xFD17B448, 0xA6855419, 0x9C47D08F, 0xFB10D4B8},
    false
}; 