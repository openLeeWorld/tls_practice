#include "RSA.h"
#include "mpz_utility.h"

using namespace std;

RSA::RSA(int key_size)
{//랜덤한 p, q에서 K, phi, e, d를 찾아낸다.
    p = random_prime(key_size / 2);
    q = random_prime(key_size / 2);
    K = p * q;
    phi = lcm(p-1, q-1);
    for(e = 0x10001; gcd(e, phi) != 1; e = nextprime(e)); // e와 phi는 서로소
    mpz_invert(d.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t()); // d 는 e의 역원
}

RSA::RSA(mpz_class e, mpz_class d, mpz_class K)
{ // 직접 파라미터를 생성하지 않고 인증서 혹은 메모리에서 읽어온 경우
    this->e = e;
    this->d = d;
    this->K = K;
}

mpz_class RSA::encode(mpz_class m)
{// K는 m보다 커야 한다.
    return powm(m, e, K);
}

mpz_class RSA::decode(mpz_class m) 
{
    return powm(m, d, K);
}

mpz_class RSA::sign(mpz_class m)
{
    return RSA::decode(m);
} 



