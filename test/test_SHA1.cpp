#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include "SHA1.h"
#include "mpz_utility.h"

using namespace std;

TEST_CASE("sha1") {
	const string s[] = {"abc", 
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"};
	const char *result[] = {"0xa9993e364706816aba3e25717850c26c9cd0d89d",
							"0x84983e441c3bd26ebaae4aa1f95129e5e54670f1",
							"0xa49b2446a02c645bf419f995b67091253a04a259"};
	unsigned char nresult[20];
	SHA1 sha;
	for(int i=0; i<3; i++) {
		mpz2bnd(mpz_class{result[i]}, nresult, nresult + 20);
		auto a = sha.hash(s[i].begin(), s[i].end());
		REQUIRE(equal(a.begin(), a.end(), nresult));
	}
}
