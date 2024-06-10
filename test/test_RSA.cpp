// test_RSA.cpp
#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include "RSA.h"

TEST_CASE("RSA") {
    RSA rsa{256}; //256byte 키 크기
    auto a = rsa.encode(mpz_class{"0x23423423"});
    REQUIRE(0x23423423 == rsa.decode(a));

    mpz_class msg = 0x143214324234_mpz;
    auto b = rsa.sign(msg); // 서명 생성, decode함수를 부른다.
    REQUIRE(rsa.encode(b) == msg); //서명 확인
}