#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include "mpz_utility.h"

using namespace std;

TEST_CASE("mpz", "[mpz2bnd, bnd2mpz]") { // 테스트(이름, 태그)
    uint8_t arr[8];
    mpz_class a{"0x1234567890abcdef"};
    mpz2bnd(a, arr, arr + 8);
    mpz_class b = bnd2mpz(arr, arr + 8);
    
    REQUIRE(a == b);
}

TEST_CASE("Diffie Hellman", "[set_peer_pubkey]") { // 테스트(이름, 태그)
    DiffieHellman Alice, Bob;
    Alice.set_peer_pubkey(Bob.y); //상대와 맞출 수 있는 K를 계산 가능
    Bob.set_peer_pubkey(Alice.y); //상대와 맞출 수 있는 K를 계산 가능
    REQUIRE(Alice.K == Bob.K);
    /*
    Alice.x = random_prime(255);
    Bob.x = random_prime(255); // 비밀 키 재생성
    Alice.y = powm(Alice.g, Alice.x, Alice.p);
    Bob.y = powm(Bob.g, Bob.x, Bob.p);
    Alice.set_peer_pubkey(Bob.y); //상대와 맞출 수 있는 K를 계산 가능
    Bob.set_peer_pubkey(Alice.y); //상대와 맞출 수 있는 K를 계산 가능
    REQUIRE(Alice.K == Bob.K);
    */
}