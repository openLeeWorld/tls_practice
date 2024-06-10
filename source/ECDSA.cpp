#include "ECDSA.h"

using namespace std;

ECDSA::ECDSA(const EC_Point &g, mpz_class n): EC_Point{g} //Generator point와 차수
{ // g는 제너레이터 포인트다. (시작점)
    n_ = n;
    nBit_ = mpz_sizeinbase(n.get_mpz_t(), 2); //2진수로 몇 자리 수인지 리턴
}

mpz_class ECDSA::mod_inv(const mpz_class &z) const 
{ // mod n에 대한 나머지 역원을 구함
    mpz_class r;
    mpz_invert(r.get_mpz_t(), z.get_mpz_t(), n_.get_mpz_t());
    return r;
} 

pair<mpz_class, mpz_class> ECDSA::sign(mpz_class m, mpz_class d) const
{ //해쉬된 메시지 m, 인증서의 비밀키 d로 서명
    int mBit = mpz_sizeinbase(m.get_mpz_t(), 2);
    mpz_class z = m >> max(mBit - nBit_, 0); //해쉬된 값이 너무 클 경우는 뒤쪽의 비트를 버린다.
    mpz_class k, s, r;
    EC_Point P = *this;
    do {
        do {
            k = random_prime(31);
            P = k * *this; //kG, 연산자 오버로딩
            r = P.x % n_;
        } while(r == 0); // r이 0이 아니면 탈출
        s = (mod_inv(k) * (z + r * d)) % n_; 
    } while(s == 0); // s가 0이 아니면 탈출
    return {r, s}; //(r, s)가 서명값임
}

bool ECDSA::verify(mpz_class m, pair<mpz_class, mpz_class> sig, EC_Point Q) const 
//메시지 m, (r,s) 서명결과, 공개키 Q(pubkey)로 서명확인 
{
    auto [r, s] = sig;
    for(auto a: {r, s}) if(a < 1 || a >= n_) return false; // 범위를 벗어나면 실패
    
    int mBit = mpz_sizeinbase(m.get_mpz_t(), 2);
    mpz_class z = m >> max(mBit - nBit_, 0);
    mpz_class u1 = z * mod_inv(s) % n_;
    mpz_class u2 = r * mod_inv(s) % n_;
    EC_Point P = u1 * *this + u2 * Q;
    if(P.y == this->mod) return false; //if P is 0

    mpz_class exp = P.x - r;
    if (exp < 0) exp = r - P.x;        

    if (exp % n_ == 0) {
        return true; // 서명 성공
    }
    else return false; // 서명 실패
}

std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.size());
    SHA256_Final(hash, &sha256);

    std::string output;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        output += hash[i];
    }
    return output;
}
/*
int main() {
    std::string message = "hello world";
    std::string hashed_message = sha256(message);
    std::cout << "SHA-256 hash of 'hello world': " << hashed_message << std::endl;
    return 0;
}
*/

