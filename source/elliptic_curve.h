#ifndef ELLIPTIC_CURVE_H
#define ELLIPTIC_CURVE_H

#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
#include <vector>
#include <random>
#include <string>
#include <cassert>
/* 연산자 오버로딩 연습용
struct B {
    int b;
};

struct A {
    int operator-(const B &b) {
        return a - b.b;
    }
    int operator-() {
        return -a;
    }
    int a;
};
*/

class EC_Field
{ // y^2 = x^3 + ax + b mod mod
    public: 
        EC_Field(mpz_class a, mpz_class b, mpz_class mod);

    protected: 
        mpz_class a, b, mod;
        mpz_class mod_inv(const mpz_class& r) const; // 나머지 역원
};

struct EC_Point : EC_Field
{ // EC_FIELD 상의 한 좌표
    EC_Point(mpz_class x, mpz_class y, const EC_Field &f);
    mpz_class x, y;
    EC_Point operator+(const EC_Point &r) const; // 두 좌표의 합
    EC_Point operator*(mpz_class r) const; // Pk만 해당
    bool operator==(const EC_Point &r) const;

    //friend ostream& operator<<(ostream&, const EC_Point&); // private변수에 접근할 수 있게 friend선언
};

std::ostream& operator<<(std::ostream &os, const EC_Point &r); // 타원곡선 좌표 간편 출력
EC_Point operator*(const mpz_class &l, const EC_Point &r); //kP만 해당(교환법칙 구현)

#endif // ELLIPTIC_CURVE_H
