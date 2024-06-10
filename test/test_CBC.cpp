#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include "CBC.h"
#include "AES.h"

using namespace std;

TEST_CASE("CBC with padding") {
    CBC<AES> cbc;
    unsigned char key[16] = { //임의의 숫자
        0, 9, 13, 11, 11, 14, 9, 13, 13, 11, 14, 9, 9, 13, 11, 14
    };

    unsigned char iv[16] = {
        14, 21, 13, 11, 11 ,7, 9, 13 ,0, 11, 14, 9, 9, 13, 11, 14
    };

    cbc.key(key);
    cbc.iv(iv);
    string msg = "Hello this is test";
    for(int i=0; i<14; i++) msg += 13; //msg가 18바이트이므로 14바이트의 패딩
    cbc.encrypt((unsigned char*)msg.data(), 32);
    cbc.decrypt((unsigned char*)msg.data(), 32);
    for(int i=msg.back(); i>=0; i--) msg.pop_back(); //패딩 제거(마지막 숫자는 패딩 개수임)
    REQUIRE(msg == "Hello this is test");
} 