// test_caesar_cipher.cpp
#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include "caesar_cipher.h"

TEST_CASE("Caesar Cipher Encoding", "[caesar_encode]") {
    REQUIRE(caesar_encode("Hello, World!", 3) == "Khoor, Zruog!");
    REQUIRE(caesar_encode("abc", 1) == "bcd");
    REQUIRE(caesar_encode("ABC", 1) == "BCD");
}

TEST_CASE("Caesar Cipher Decoding", "[caesar_decode]") {
    REQUIRE(caesar_decode("Khoor, Zruog!", 3) == "Hello, World!");
    REQUIRE(caesar_decode("bcd", 1) == "abc");
    REQUIRE(caesar_decode("BCD", 1) == "ABC");
}


