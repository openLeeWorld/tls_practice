#pragma once

//#include<iostream>
#include<optional>
#include"AES.h" //AES 클래스
#include"elliptic_curve.h" //EC_FIELD, EC_POINT
#include "der.h" //der2json
//#include <vector> //std::Vector
//#include <random> //random함수
//#include <string> //string class
//#include <cassert> //assert()
//#include <algorithm> // std::equal, std::copy, std::min함수 호출용
//#include <cstring> // std::memcpy
//#include <array> //std::array
//#include <cstdint> //uint8_t, uint32_t, uint64_t
//#include <arpa/inet.h> // htonls용
//#include <nettle/sha.h> //sha256용
//#include<valarray> //std::valarray(벡터 연산용)
//#include <cstddef> //size_t
//#include <sstream> // stringstream ss
//#include <iomanip> // hexprint의 setw
//#include <jsoncpp/json/json.h> //json
#include <utility> // std::move 사용을 위해 필요
#include<fstream>
#include"log.h"
#include"SHA1.h" //sha256
#include"cert.h"
#include"PRF.h"
#include"RSA.h" //RSA 클래스
#include"GCM.h" //GCM 클래스
//#include"mpz_utility.h"

template<bool SV = true> class TLS //SV는 서버, 빈 스트링일 경우 메시지 생성, 값이 있으면 메시지 분석 상정
{//just deals with memory structure -> decoupled from underlying file-descriptor
public:
	std::pair<int, int> get_content_type(const std::string &s);
	std::optional<std::string> decode(std::string &&s = "");//if not rvalue use set_buf
	std::string encode(std::string &&s = "", int type = 0x17);//for finished 0x16

	//handshaking functions
	std::string client_hello(std::string &&s = "");//s != "" -> buffer is set to s
	std::string server_hello(std::string &&s = "");//s == "" -> manual buffer set
	std::string server_certificate(std::string &&s = "");
	std::string server_key_exchange(std::string &&s = "");
	std::string server_hello_done(std::string &&s = "");
	std::string client_key_exchange(std::string &&s = "");
	std::string change_cipher_spec(std::string &&s = "");//if s=="" send, else recv
	std::string finished(std::string &&s = "");//if s=="" send, else recv
	int alert(std::string &&s = "");
	std::string alert(uint8_t level, uint8_t desc);

protected:
	GCM<AES> aes_[2];//0 client 1 server
	mpz_class enc_seq_num_ = 0, dec_seq_num_ = 0, prv_key_ = random_prime(31); // 암복호화 시 사용할 순서값, 타원곡선의 비밀키
	EC_Field secp256r1_{ // secp256r1 타원곡선 정의
		0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC_mpz,
		0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B_mpz, 
		0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF_mpz
	};
	EC_Point G_{ // 타원곡선 secp256r1의 Generator point
		0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296_mpz,
		0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5_mpz, 
		secp256r1_
	}, P_{G_ * prv_key_}; // P: 타원곡선 공개키
	std::array<unsigned char, 32> session_id_, server_random_, client_random_;
	std::vector<unsigned char> master_secret_; // 키 교환으로 얻어진다.
	std::string accumulated_handshakes_; // handshake과정의 누적 기록
	static std::string certificate_; // RSA 인증서를 읽어들여 이 변수에 저장
	std::string accumulate(const std::string &s);
	static RSA rsa_; // 인증서의 공개키 값으로 초기화
		
private:
	void generate_signature(unsigned char* p_length, unsigned char* p);
	void derive_keys(mpz_class premaster_secret);
};

const int CHANGE_CIPHER_SPEC = 0x14
		, ALERT = 0x15
		, HANDSHAKE = 0x16
		, APPLICATION_DATA = 0x17
		; // TLS 헤더 type
const int HELLO_REQUEST = 0x00
		, CLIENT_HELLO = 0x01
		, SERVER_HELLO = 0x02
		, CERTIFICATE = 0x0b
		, SERVER_KEY_EXCHANGE = 0x0c
		, CERTIFICATE_REQUEST = 0x0d
		, SERVER_DONE = 0x0e
		, CERTIFICATE_VERIFY = 0x0f
		, CLIENT_KEY_EXCHANGE = 0x10
		, FINISHED = 0x14
		; // HS 헤더 type

const bool SERVER = true, CLIENT = false;

template<class S> static std::string struct2str(const S &s)
{
	return std::string{(const char*)&s, sizeof(s)};
}


