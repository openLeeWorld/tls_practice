#ifndef GCM_H
#define GCM_H
//#pragma once

#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
#include <vector>
#include <random>
#include <string>
//#include <cassert>
#include <algorithm> // std::equal, std::copy, std::min함수 호출용
#include <cstring> // for memcpy
#include <array> //std::array
#include "CipherMode.h" //public class CipherMode<Cipher>
#include "mpz_utility.h" //mpz2bnd, random_prime

template<class Cipher> class GCM : public CipherMode<Cipher>
{
public:
	void iv(const unsigned char *p);
	void iv(const unsigned char *p, int from, int sz);
	void xor_with_iv(const unsigned char *p);
	void aad(const unsigned char *p, int sz);
	std::array<unsigned char, 16> encrypt(unsigned char *p, int sz);
	std::array<unsigned char, 16> decrypt(unsigned char *p, int sz);
	//void debug();
protected:
	std::vector<unsigned char> aad_;
	unsigned char lenAC_[16];
private:
	void xor_with_enc_ivNcounter(unsigned char *p, int sz, int ctr);
	std::array<unsigned char, 16> generate_auth(unsigned char *p, int sz);
};

void doub(unsigned char *p); //p Ⓧ 2 정의 in GCM 갈루아 군
void gf_mul(unsigned char *x, unsigned char *y); //mult_H

template<class Cipher> void GCM<Cipher>::iv(const unsigned char *p)
{
	memcpy(this->iv_, p, 12);
}

template<class Cipher> void GCM<Cipher>::iv(const unsigned char *p, int from, int sz) 
{
	memcpy(this->iv_ + from, p, sz);
}

template<class Cipher>
std::array<unsigned char, 16> GCM<Cipher>::encrypt(unsigned char *p, int sz)
{
	for(int i=0; i<sz; i+=16) xor_with_enc_ivNcounter(p + i, std::min(16, sz-i), i/16 + 2);
	return generate_auth(p, sz);
}

template<class Cipher> 
std::array<unsigned char, 16> GCM<Cipher>::generate_auth(unsigned char *p, int sz) {
	unsigned char H[16]={0,};
	std::array<unsigned char, 16> Auth;
	this->cipher_.encrypt(H);
	if(!aad_.empty()) {
		gf_mul(&aad_[0], H);
		for(int i=0; i<aad_.size()-16; i+=16) {//aad process
			for(int j=0; j<16; j++) aad_[i+16+j] ^= aad_[i+j];
			gf_mul(&aad_[i+16], H);
		}
		copy(aad_.end() - 16, aad_.end(), Auth.begin());
	}
	for(int i=0; i<sz; i+=16) {
		for(int j=0; j<std::min(16, sz-i); j++) Auth[j] ^= p[i+j];
		gf_mul(&Auth[0], H);
	}
	
	mpz2bnd(sz * 8, lenAC_ + 8, lenAC_ + 16);
	for(int i=0; i<16; i++) Auth[i] ^= lenAC_[i];
	gf_mul(&Auth[0], H);
	xor_with_enc_ivNcounter(&Auth[0], 16, 1);
	return Auth;
}

template<class Cipher>
void GCM<Cipher>::xor_with_enc_ivNcounter(unsigned char *p, int sz, int ctr)
{
	unsigned char ivNcounter[16];
	memcpy(ivNcounter, this->iv_, 12);
	mpz2bnd(ctr, ivNcounter + 12, ivNcounter + 16);
	this->cipher_.encrypt(ivNcounter);
	for(int i=0; i<sz; i++) p[i] ^= ivNcounter[i];
}

template<class Cipher>
std::array<unsigned char, 16> GCM<Cipher>::decrypt(unsigned char *p, int sz) 
{
	auto a = generate_auth(p, sz);
	for(int i=0; i<sz; i+=16) xor_with_enc_ivNcounter(p + i, std::min(16, sz-i), i/16 + 2);
	return a;
}

template<class Cipher> void GCM<Cipher>::xor_with_iv(const unsigned char *p) 
{
	for(int i=0; i<4; i++) this->iv_[i] ^= 0;
	for(int i=0; i<8; i++) this->iv_[4 + i] ^= p[i];
}

template<class Cipher> void GCM<Cipher>::aad(const unsigned char *p, int sz)
{
	aad_ = std::vector<uint8_t>{p, p+sz};
	mpz2bnd(aad_.size() * 8, lenAC_, lenAC_ + 8);
	while(aad_.size() % 16) aad_.push_back(0);
}

#endif // GCM_H