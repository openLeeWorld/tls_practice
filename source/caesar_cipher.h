// caesar_cipher.h
#ifndef CAESAR_CIPHER_H
#define CAESAR_CIPHER_H

#include <string>

std::string caesar_encode(const std::string &message, int key);
std::string caesar_decode(const std::string &message, int key);

#endif // CAESAR_CIPHER_H

