#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include "GCM.h"
#include "AES.h"
#include <nettle/gcm.h>
#include <nettle/aes.h>

using namespace std;

TEST_CASE("GCM") {
	unsigned char K[16], A[70], IV[12], P[48], Z[16], C[48];
	mpz2bnd(random_prime(16), K, K + 16);
	mpz2bnd(random_prime(70), A, A + 70);
	mpz2bnd(random_prime(12), IV, IV + 12);
	mpz2bnd(random_prime(48), P, P + 48);
	SECTION("GCM compare with nettle") {
		gcm_aes128_ctx ctx;
		gcm_aes128_set_key(&ctx, K);
		gcm_aes128_set_iv(&ctx, 12, IV);
		gcm_aes128_update(&ctx, 28, A);
		gcm_aes128_encrypt(&ctx, 48, C, P);
		gcm_aes128_digest(&ctx, 16, Z);

		GCM<AES> gcm;
		gcm.iv(IV);
		gcm.key(K);
		gcm.aad(A, 28);
		auto a = gcm.encrypt(P, 48);
		REQUIRE(equal(P, P+48, C));
		REQUIRE(equal(a.begin(), a.end(), Z));

		mpz2bnd(random_prime(12), IV, IV+12);
		mpz2bnd(random_prime(70), A, A + 70);
		gcm_aes128_set_iv(&ctx, 12, IV);
		gcm_aes128_update(&ctx, 28, A);
		gcm_aes128_encrypt(&ctx, 48, C, P);
		gcm_aes128_digest(&ctx, 16, Z);
		
		gcm.iv(IV);
		gcm.aad(A, 28);
		a = gcm.encrypt(P, 48);
		REQUIRE(equal(P, P+48, C));
		REQUIRE(equal(a.begin(), a.end(), Z));
	}
}
