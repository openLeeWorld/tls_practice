#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include "hmac.h"
#include "SHA1.h"
#include "mpz_utility.h"

using namespace std;

TEST_CASE("hmac") {
	const string data[] = {
		"Sample message for keylen=blocklen",
		"Sample message for keylen<blocklen",
		"Sample message for keylen=blocklen",
		"Sample message for keylen<blocklen, with truncated tag"
	};
	const char *key[] = {
		"0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021\
			22232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
		"0x000102030405060708090A0B0C0D0E0F10111213",
		"0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021\
			22232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F4041424\
			34445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263",
		"0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021\
			22232425262728292A2B2C2D2E2F30"
	};
	const char *result[] = {"0x5FD596EE78D5553C8FF4E72D266DFD192366DA29",
							"0x4C99FF0CB1B31BD33F8431DBAF4D17FCD356A807",
							"0x2D51B2F7750E410584662E38F133435F4C4FD42A",
							"0xFE3529565CD8E28C5FA79EAC9D8023B53B289D96"};

	int data_len[] = {34, 34, 34, 54};
	int key_len[] = {64, 20, 100, 49};
	unsigned char nkey[100], nresult[32];

	HMAC<SHA1> hmac;
	for(int i=0; i<4; i++) {
		mpz2bnd(mpz_class{key[i]}, nkey, nkey + key_len[i]);
		mpz2bnd(mpz_class{result[i]}, nresult, nresult + 20);
		hmac.key(nkey, nkey + key_len[i]);
		auto a = hmac.hash(data[i].begin(), data[i].end());
		REQUIRE(equal(a.begin(), a.end(), nresult));
	}
	auto a = hmac.hash(data[3].begin(), data[3].end());
	REQUIRE(equal(a.begin(), a.end(), nresult));
	REQUIRE(hmac.hash(data[2].begin(), data[2].end()) == hmac.hash(data[2].begin(), data[2].end()));
}