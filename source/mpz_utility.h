//#ifndef MPZ_UTILITY_H
//#define MPZ_UTILITY_H
#pragma once

#include <iomanip>
#include <sstream>
#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
#include <vector>
#include <random>
#include <string>
#include <cassert>


int powm(int base, int exp, int mod);
mpz_class nextprime(mpz_class n);
mpz_class powm(mpz_class base, mpz_class exp, mpz_class mod);
mpz_class random_prime(unsigned byte); // byte길이의 소수를 리턴한다.

template<typename It> 
void mpz2bnd(mpz_class n, It begin, It end) //mpz to big endian
{
    for(It i=end; i!=begin; n /= 0x100)
        *--i = mpz_class{n % 0x100}.get_ui();
    //[begin, end) 의 연속적인 메모리 구조에 빅 엔디안 형식으로 n을 써넣는다.
}

template<typename It> 
mpz_class bnd2mpz(It begin, It end) // big endian to mpz 
{
    std::stringstream ss; 
    ss << "0x";
    for(It i=begin; i != end; i++)
        ss << std::hex << std::setfill('0') << std::setw(2) << +*i;
    //빅 엔디안 형식의 메모리 구조를 읽어들여 mpz를 리턴한다.
    return mpz_class{ss.str()};
}

template<class C> 
std::string hexprint(const char *p, const C &c) // 컨테이너 c의 내용을 16진수 스트링으로 리턴
{
    std::stringstream ss;
    ss << p << " : 0x";
    for(unsigned char a : c)
        ss << std::hex << std::setw(2) << std::setfill('0') << +a;
    return ss.str();
}

struct DiffieHellman
{// 256 byte = 2048 bit 
    mpz_class p{"0xFFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1\
    D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9\
    7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561\
    2433F51F5F066ED0856365553DED1AF3B557135E7F57C935\
    984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735\
    30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB\
    B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19\
    0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61\
    9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73\
    3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA\
    886B423861285C97FFFFFFFFFFFFFFFF"};

    mpz_class K; // K = ya ^ xb mod p = yb ^ xa mod p
    mpz_class g = 2; // p와 g는 rfc7919에 있는 원시근
    mpz_class x = random_prime(255); //private key(256byte크기의 소수)
    mpz_class y = powm(g, x, p); // public key ya = g^xa mod p, yb = g ^ xb mod p
    mpz_class set_peer_pubkey(mpz_class pub_key);
};

//#endif // MPZ_UTILITY_H
