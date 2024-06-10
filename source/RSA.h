#ifndef RSA_H
#define RSA_H

#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
#include <vector>
#include <random>
#include <string>
//#include <cassert>
#include <numeric> // std::lcm


class RSA
{
    public:
        RSA(int key_size);
        RSA(mpz_class e, mpz_class d, mpz_class K);
        mpz_class sign(mpz_class m);
        mpz_class decode(mpz_class m); 
        mpz_class encode(mpz_class m);
        mpz_class K, e;
    protected:
        mpz_class p, q, d, phi;
};

#endif // RSA_H
