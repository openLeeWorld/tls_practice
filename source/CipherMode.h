#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
//#include <vector>
//#include <random>
//#include <string>
//#include <cassert>
//#include <algorithm> // std::equal함수 호출용
//#include <cstring> // for memcpy

template<class Cipher> class CipherMode { //템플릿 추상 클래스
    public:
        void key(const unsigned char *p) {
            cipher_.key(p); //key확장함수 호출
        } 
        virtual void iv(const unsigned char *p) = 0; // 순수 가상함수(상속받아서 구현해야함)

    protected: 
        Cipher cipher_; //우리는 AES(AES를 제외한 (RSA, 타원곡선 등) 다른 암호화 클래스도 가능)
        unsigned char iv_[16]; //16byte 초기 벡터
};