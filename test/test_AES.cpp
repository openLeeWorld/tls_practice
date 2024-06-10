#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#define private public
#define protected public
#include "../source/AES.h"
#undef private
#undef protected
#include <iomanip>

using namespace std;

void printUnsignedCharArrayHex(const unsigned char* array, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(array[i]) << " ";
    }
    std::cout << std::dec << std::endl;
}

TEST_CASE("substitute & inv_substitute") {
    AES aes;
    unsigned char schedule_extra[16] = {
        0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75
    };
    unsigned char schedule_answer[16] = {
        0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75
    };
    aes.substitute(schedule_extra); // 첫 16바이트만 키 값으로 주어진다.
    aes.inv_substitute(schedule_extra); // 첫 16바이트만 키 값으로 주어진다.
    REQUIRE(equal(schedule_extra, schedule_extra + 16, schedule_answer));  
} 

TEST_CASE("inverse mix column matrix verify") {
    unsigned char inv[16] = { // 열을 기준으로 역함수 행렬을 배열한다. (전치)
        14, 9, 13, 11,
        11, 14, 9, 13,
        13, 11, 14, 9, 
        9, 13, 11, 14
    };

    AES aes;
    unsigned char o[16] = { 1,0,0,0, 0,1,0,0, 0,0,1,0, 0,0,0,1 }; //항등원
    aes.mix_column(inv);
    REQUIRE(equal(inv, inv + 16, o));
}

TEST_CASE("shift_row & mix_column") {
    AES aes;
    unsigned char data[16], oneto16[16];
    for(int i=0; i<16; i++) data[i] = oneto16[i] = i+1;
    unsigned char shift_row_result[16] = { 1, 6, 0x0b, 0x10, 5, 0xa, 0xf, 4, 9, 0xe, 3, 8, 0xd, 2, 7, 0xc};
    unsigned char mix_column_result[16] = { 3, 4, 9, 0xa, 0xf, 8, 0x15, 0x1e, 0xb, 0xc, 1, 2, 0x17, 0x10, 0x2d, 0x36};
    
    aes.shift_row(data);
    REQUIRE(equal(data, data+16, shift_row_result));
    aes.inv_shift_row(data);
    REQUIRE(equal(data, data+16, oneto16));

    aes.mix_column(data);
    REQUIRE(equal(data, data+16, mix_column_result));
    aes.inv_mix_column(data);
    REQUIRE(equal(data, data+16, oneto16));
}

/*
TEST_CASE("key scheduling") {
    AES aes;
    aes.key(schedule); // 첫 16바이트만 키 값으로 주어진다.
    REQUIRE(equal(schedule, schedule + 11*16, &aes.schedule_[0][0]));
} // 11라운드로 키가 확장됨 확인
*/


TEST_CASE("key scheduling") {
    AES aes;
    unsigned char schedule[16 * AES::ROUND]; // 필요한 키 스케줄 크기

    // 초기 키를 설정
    unsigned char initialKey[16] = {
        0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75
    };
    memcpy(schedule, initialKey, 16);
    
    // AES 객체에 키를 설정하고 키 스케줄링 수행
    //aes.key(initialKey);
    aes.key(schedule);

    // 예상되는 키 스케줄링 값을 schedule 배열에 설정
    unsigned char *p = schedule + 16;
    for (int i = 1; i < AES::ROUND; ++i) {
        // 예상 키 스케줄링 알고리즘 수행
        unsigned char temp[4];
        memcpy(temp, p - 4, 4);

        // RotWord
        unsigned char t = temp[0];
        for (int j = 0; j < 3; ++j) {
            temp[j] = temp[j + 1];
        }
        temp[3] = t;

        // SubWord
        for (int j = 0; j < 4; ++j) {
            temp[j] = AES::sbox[temp[j]];
        }

        // Rcon
        temp[0] ^= AES::rcon[i - 1][0];

        for (int j = 0; j < 4; ++j) {
            p[j] = schedule[(i - 1) * 16 + j] ^ temp[j];
        }

        for (int j = 4; j < 16; ++j) {
            p[j] = schedule[(i - 1) * 16 + j] ^ p[j - 4];
        }

        p += 16;
    }
    /* // 결과 16진수로 프린트용
    for(int i=0; i< 11;i++) printUnsignedCharArrayHex(schedule + i * 16, 16);
    cout<<endl;
    for(int i=0; i< 11;i++) printUnsignedCharArrayHex(aes.schedule_[i], 16);
    */
    REQUIRE(std::equal(schedule, schedule + 16 * AES::ROUND, &aes.schedule_[0][0]));
}

TEST_CASE("add_round_key") {
    AES aes;
    // 초기 키를 설정
    unsigned char iv[16] = {
        0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75
    };

    unsigned char result[16] = {0, };
    aes.key(iv);
    aes.add_round_key(iv, 0); //자신과 자신을 더함
    REQUIRE(equal(iv, iv + 16, result));
} // 11라운드로 키가 확장됨 확인

TEST_CASE("AES encrypt and decrypt") {
    AES aes;
    // 초기 키를 설정
    unsigned char iv[16] = {
        0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75
    };

    unsigned char message[16] = "Hello, World!!!";  // 16바이트 길이로 맞춤
    unsigned char result[16] = "Hello, World!!!";  // 16바이트 길이로 맞춤
    //printUnsignedCharArrayHex(message, 16); 
    aes.key(iv);
    aes.encrypt(message);
    //printUnsignedCharArrayHex(message, 16); 
    aes.decrypt(message);
    //printUnsignedCharArrayHex(message, 16);
    //cout << result << endl;
    //cout << message << endl;
    REQUIRE(equal(message, message + 16, result));
} // 11라운드로 키가 확장됨 확인


