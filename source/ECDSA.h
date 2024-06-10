#ifndef ECDSA_H
#define ECDSA_H
//#pragma once
#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
#include <vector>
#include <random>
#include <string>
#include <cassert>
#include <openssl/sha.h> //sha256 함수용
#include "elliptic_curve.h"
#include "mpz_utility.h"


class ECDSA : public EC_Point // 타원 곡선 점 클래스 상속
{
    public:
        ECDSA(const EC_Point &G, mpz_class n); //Generator point와 차수
        std::pair<mpz_class, mpz_class> sign(mpz_class m, mpz_class d) const; //메시지 m, 비밀키 d로 서명
        bool verify(mpz_class m, std::pair<mpz_class, mpz_class> sig, EC_Point Q) const; //메시지 m, (r,s) 서명결과, 공개키 Q로 서명확인 
        mpz_class mod_inv(const mpz_class &z) const; //나머지 역원은 mod가 아닌 차수 n값에 대한 역원을 구한다.(메서드 오버라이딩) 
    protected:
        mpz_class n_; //차수
    private:
        int nBit_; // 차수의 비트 수
        mpz_class d_; //비밀키       
};

std::string sha256(const std::string& input);

#endif // ECDSA_H