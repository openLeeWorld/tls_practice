#ifndef CBC_H
#define CBC_H
#pragma once
#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
#include <vector>
#include <random>
#include <string>
#include <cassert>
#include <algorithm> // std::equal함수 호출용
#include <cstring> // for memcpy
//#include <openssl/sha.h> //sha256 함수용
#include "CipherMode.h" //public class CipherMode<Cipher>

//cipher mode base 클래스와 이로부터 상속받은 CBC 클래스 
template<class Cipher> class CBC : public CipherMode<Cipher> {
    public: 
        void iv(const unsigned char *p); //가상함수 iv 구하는 함수 구현
        void encrypt(unsigned char *p, int sz) const;
        void decrypt(unsigned char *p, int sz) const;
}; 

template<class Cipher>
void CBC<Cipher>::iv(const unsigned char *p) {
    memcpy(this->iv_, p , 16); 
}

template<class Cipher>
void CBC<Cipher>::encrypt(unsigned char *p, int sz) const 
{ //순차적
    assert(sz % 16 == 0); //사이즈가 16byte의 배수여야함
    for(int i=0; i<16; i++) p[i] ^= this->iv_[i];
    for(int j=1; j<sz/16; j++) {
        this->cipher_.encrypt(p); //xor후 16byte 암호화
        for(int i=0; i<16; i++, p++) *(p+16) ^= *p; //p+=16
    }
    this->cipher_.encrypt(p); //마지막 부분은 그냥 암호화
}

template<class Cipher>
void CBC<Cipher>::decrypt(unsigned char *p, int sz) const 
{ //병행 프로그래밍 가능
    assert(sz % 16 == 0); //사이즈가 16byte의 배수여야함
    unsigned char buf[sz];
    memcpy(buf, p, sz);
    for(int i=0; i<sz; i+=16) this->cipher_.decrypt(p+i);
    for(int i=0; i<16; i++) *p++ ^= this->iv_[i]; //p+=16
    for(int i=0; i<sz-16; i++) *p++ ^= buf[i];
}

#endif // CBC_H