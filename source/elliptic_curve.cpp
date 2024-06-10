#include "elliptic_curve.h"

using namespace std;
/* 연산자 오버로딩 예제
int main() {
    A a; B b;
    a.a = 3; b.b = 1;
    cout << a - b << endl; // 2
    cout << -a << endl; // -3
    // cout << b - a << endl; // 컴파일 에러
}
*/

EC_Field::EC_Field(mpz_class a, mpz_class b, mpz_class mod)
{ // y^2 = x^3 + ax + b
    this->a = a;
    this->b = b;
    this->mod = mod;
}

mpz_class EC_Field::mod_inv(const mpz_class &z) const
{ // 나머지 역원을 구함
    mpz_class r;
    mpz_invert(r.get_mpz_t(), z.get_mpz_t(), mod.get_mpz_t());
    return r;
}

EC_Point::EC_Point(mpz_class x, mpz_class y, const EC_Field &f) : EC_Field{f}
{
    if(y != mod) {
        mpz_class lhs, rhs;
        lhs = y * y;
        rhs = x*x*x + a*x + b;
        if(lhs > rhs) assert((y*y - (x*x*x + a*x + b)) % mod == 0);
        else assert(((x*x*x + a*x + b) - y*y) % mod == 0);
    }
    // 점이 유한체 상의 타원 곡선 방정식을 만족하는지 확인하는 함수
    this->x = x;
    this->y = y;
}

bool EC_Point::operator==(const EC_Point &r) const{
    assert(a == r.a && b == r.b && mod == r.mod);
    return x == r.x && y == r.y;
}

EC_Point EC_Point::operator+(const EC_Point &r) const
{ // y값이 mod와 같은 것을 0(항등원, 역원으로 삼음)
    if(r.y == mod) return *this; // P + O = P
    if(y == mod) return r; //O + P = P, y좌표가 mod와 같은 것은 무한으로 삼는다.
    mpz_class s; //slope
    if(r == *this) { // P==Q인 경우
        if (y == 0) return {x, mod, *this}; //항등원 리턴
        s = (3 * x * x + a) * mod_inv(2 * y) % mod;
    } else { // P!= Q인 경우
        if (x == r.x) return {x, mod, *this}; // 항등원 리턴
        s = (r.y - y) * mod_inv(r.x - x) % mod;
    }
    mpz_class x3 = (s * s - x - r.x) % mod;
    mpz_class y3 = (s * (x - x3) - y) % mod;
    return { x3 <0 ? x3 + mod : x3, y3 < 0 ? y3 + mod : y3, *this};
}

EC_Point EC_Point::operator*(mpz_class r) const
{ // P * k
    vector<bool> bits; // r을 bit단위로 저장
    for(; r > 0 ; r /= 2) bits.push_back(r % 2 == 1);
    EC_Point X = *this, R{0, mod, *this};
    for(auto a : bits) {
        if(a) R = R + X;
        X = X + X; // X, 2X, 4X...
    } // O(log N)으로 연산 시간 줄이기
    return R;
}

EC_Point operator*(const mpz_class &l, const EC_Point &r) 
{
    return r * l; // 교환법칙 
}

ostream& operator<<(ostream &os, const EC_Point &r) // 타원곡선 좌표 간편 출력
{
    os << '(' << r.x << ", " << r.y << ')' << endl;
    return os;
}
/*
int main() {
    EC_Field f{2, 2, 17};
    EC_Point p{5, 1, f};
    for (int i = 1; i <= 20; i++) cout << i * p;
    auto xA = p * 3;
    auto xB = p * 7;
    auto KA = xB * 3;
    auto KB = xA * 7;
    assert(KA == KB);
    cout << endl << xA << xB << KA << endl;
    // 차수 n=19의 (10,17)은 무한 O이다.
}
*/




