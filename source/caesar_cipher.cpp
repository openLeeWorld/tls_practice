// caesar_cipher.cpp
#include "caesar_cipher.h"
#include <cctype>

std::string caesar_encode(const std::string &message, int key) {
    std::string encoded = message;
    for (char &c : encoded) {
        if (isalpha(c)) {
            char base = islower(c) ? 'a' : 'A';
            c = (c - base + key) % 26 + base;
        }
    }
    return encoded;
}

std::string caesar_decode(const std::string &message, int key) {
    return caesar_encode(message, 26 - key);
}

