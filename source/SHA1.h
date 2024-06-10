#ifndef SHA1_H
#define SHA1_H
//#pragma once
#include <iostream> //cout
#include <gmp.h> 
#include <gmpxx.h>
#include <vector> //std::Vector
#include <random> //random함수
#include <string> //string class
#include <cassert> //assert()
#include <algorithm> // std::equal, std::copy, std::min함수 호출용
#include <cstring> // std::memcpy
#include <array> //std::array
#include <cstdint> //uint32_t, uint64_t
#include <arpa/inet.h> // htonls용
#include <nettle/sha.h> //sha1용
#include <nettle/sha2.h>
//#include<nettle/sha3.h>
//#include <cstddef> //size_t
//#include "mpz_utility.h" //mpz2bnd, random_prime

class SHA1
{
    public:
        static const int block_size = 64;
        static const int output_size = 20;
        SHA1();
        template<class It> std::array<unsigned char, 20> hash(const It begin, const It end);

    protected: 
        bool big_endian_ = false;
        uint32_t h[5], w[80];
        static constexpr uint32_t h_stored_value[5] = 
            {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};

    private: 
        static void preprocess(std::vector<unsigned char> &v);
        void process_chunk(unsigned char *p); //64 byte chunk
};

template<class It>
std::array<unsigned char, 20> SHA1::hash(const It begin, const It end)
{
    for(int i=0; i<5; i++) h[i] = h_stored_value[i];
    std::vector<unsigned char> msg(begin, end);
    preprocess(msg);
    for(int i=0; i<msg.size(); i+=64) process_chunk(&msg[i]);
    if(!big_endian_) for(int i=0; i<5; i++) h[i] = htonl(h[i]); // 인텔(LE)이든 ARM(LE)이든 상관없이 
    std::array<unsigned char, 20> digest;
    unsigned char *p = (unsigned char*) h;
    for(int i=0; i<20; i++) digest[i] = *p++; // h[0]h[1]..h[4] 빅엔디안으로 붙인게 해시값(4B * 5 = 20)
    return digest;
}

class SHA2
{
public:
	static const int block_size = 64;
	static const int output_size = 32;
	SHA2() {
		sha256_init(&sha_);
	}
	template<typename It>
	std::array<unsigned char, output_size> hash(const It begin, const It end) {
		std::array<unsigned char, output_size> r;
		sha256_update(&sha_, end - begin, (const unsigned char*)&*begin);
		sha256_digest(&sha_, output_size, &r[0]);
		return r;
	}
protected:
	sha256_ctx sha_;
};

#endif // SHA1_H