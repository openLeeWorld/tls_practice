#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include "ECDSA.h"

using namespace std;

TEST_CASE("ECDSA")
{
    EC_Field secp256r1{// 타원곡선 정의
                       0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC_mpz,
                       0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B_mpz,
                       0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF_mpz};

    EC_Point G{// secp256r1 generator point(x, y)정의
               0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296_mpz,
               0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_mpz,
               secp256r1};

    auto n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551_mpz; // 차수
    mpz_class d = random_prime(31);                                                  // 31byte크기의 랜덤 소수 반환
    auto Q = d * G;                                                                  // 공개키

    ECDSA ecdsa{G, n};
    char message[] = "This is a Test message";
    // 일반적으로 메시지를 해쉬해 그 결과에 대해 서명한다.
    auto m = sha256(message);
    auto z = bnd2mpz(m.begin(), m.end()); 
    auto sign = ecdsa.sign(z, d);
    REQUIRE(ecdsa.verify(z, sign, Q)); // 서명 확인에 성공해야한다.
    // 저장 안되는 오류 고침
}
