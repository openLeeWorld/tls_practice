// mpz_utility.cpp
#include "mpz_utility.h"

int powm(int base, int exp, int mod) { // power modular
	int r = 1;
	for(int i=0; i<exp; i++) {
		r *= base;
		r %= mod;
	}
	return r;
}

mpz_class nextprime(mpz_class n) 
{ // n보다 큰 최초의 소수 리턴
    mpz_class r;
    mpz_nextprime(r.get_mpz_t(), n.get_mpz_t()); // c함수 사용을 위해 get_mpz_t()로 c++ wrapper class 값을 뺀다.
    return r;
}

mpz_class powm(mpz_class base, mpz_class exp, mpz_class mod)
{ // return base ^ exp % mod
    mpz_class r;
    assert(mod);
    mpz_powm(r.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
    return r;
}

mpz_class random_prime(unsigned byte) // byte길이의 소수를 리턴한다. 
{
    std::vector<unsigned char> arr(byte); // 바이트 배열 초기화
    std::uniform_int_distribution<> di(0, 0xff);
    std::random_device rd;
    std::mt19937 gen(rd()); // 랜덤숫자 생성 결정

    for(unsigned char &a : arr)
        a = di(gen); // 랜덤 바이트 생성 결정

    auto z = nextprime(bnd2mpz(arr.begin(), arr.end())); // 소수 결정
    std::fill(arr.begin(), arr.end(), 0xff); // 바이트의 최대 숫자(255)로 채우기

    if(z > bnd2mpz(arr.begin(), arr.end())) // 바이트 길이의 해당하는 최대값보다 크다면 
        return random_prime(byte); // 재귀 호출로 byte 크기의 랜덤 소수를 찾는다.
    else
        return z; // 범위가 맞다면 해당 소수를 반환한다.
}

mpz_class DiffieHellman::set_peer_pubkey(mpz_class pub_key)
{
    K = powm(pub_key, x, p); 
    return K;
}



