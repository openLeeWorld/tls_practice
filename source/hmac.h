#ifndef HMAC_H
#define HMAC_H
//#pragma once
#include <iostream> //cout
#include <gmp.h> 
#include <gmpxx.h>
#include <vector> //std::Vector
//#include <random> //random함수
#include <string> //string class
//#include <cassert> //assert()
#include <algorithm> // std::equal, std::copy, std::min함수 호출용
//#include <cstring> // std::memcpy
//#include <array> //std::array
//#include <cstdint> //uint32_t, uint64_t
//#include <arpa/inet.h> // htonls용
//#include <nettle/sha.h> //sha256용
#include<valarray> //std::valarray(벡터 연산용)
//#include <cstddef> //size_t
//#include "mpz_utility.h" //mpz2bnd, random_prime

template<class H> class HMAC // H: Hash function(md5, SHA1 등)
{
    public:
        HMAC() : o_key_pad_(H::block_size), i_key_pad_(H::block_size) 
        { }
        template<typename It> void key(const It begin, const It end)
        { //block size보다 작으면 0으로 패딩, 크면 해쉬 -> 20
            int length = end - begin;
            // 아래의 (int)0x0은 컴파일러가 null pointer와 혼동하지 않게 함.
            std::valarray<unsigned char> key((int)0x0, H::block_size),
                out_xor(0x5c, H::block_size), in_xor(0x36, H::block_size);
            if(length > H::block_size) {
                auto h = sha_.hash(begin, end);
                for(int i=0; i<H::output_size; i++) key[i] = h[i];
            } else if(int i=0; length <= H::block_size) {
                for(auto it = begin; it != end; it++) key[i++] = *it;
            }
            o_key_pad_ = key ^ out_xor;
            i_key_pad_ = key ^ in_xor;
        }
        template<typename It> auto hash(const It begin, const It end)
        {
            std::vector<unsigned char> v;
            v.insert(v.begin(), std::begin(i_key_pad_), std::end(i_key_pad_));
            v.insert(v.end(), begin, end); //  vec.insert(vec.begin() + 위치, to_insert.begin(), to_insert.end());
            auto h = sha_.hash(v.begin(), v.end());
            v.clear();
            v.insert(v.begin(), std::begin(o_key_pad_), std::end(o_key_pad_));
            v.insert(v.end(), h.begin(), h.end());
            return sha_.hash(v.begin(), v.end());
        }
    protected:
        H sha_;
        std::valarray<unsigned char> o_key_pad_, i_key_pad_;
};

#endif 