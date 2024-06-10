#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include"mpz_utility.h" // #include <iomanip>, #include <sstream> 중복 포함 방지용 미리 포함
#define private public
#define protected public
#include"tls.h"
#undef private
#undef protected

using namespace std;

TEST_CASE("tls") {
	Log::get_instance()->set_log_filter("TdIWEF");
	TLS<true> server; TLS<false> client;
	server.client_hello(client.client_hello());
	client.server_hello(server.server_hello());
	client.server_certificate(server.server_certificate());
	client.server_key_exchange(server.server_key_exchange());
	client.server_hello_done(server.server_hello_done());
	server.client_key_exchange(client.client_key_exchange());
	server.change_cipher_spec(client.change_cipher_spec());
	server.finished(client.finished());
	client.change_cipher_spec(server.change_cipher_spec());
	client.finished(server.finished());
	//REQUIRE(server.diffie_.K == client.diffie_.K); // diffie_(premaster secret)는 개발 안함
	REQUIRE(equal(server.master_secret_.begin(), server.master_secret_.end(),
				client.master_secret_.begin())); // master secret을 검증
	REQUIRE(equal(server.client_random_.begin(), server.client_random_.end(),
				client.client_random_.begin()));
	REQUIRE(equal(server.server_random_.begin(), server.server_random_.end(),
				client.server_random_.begin()));
	for(int i=0; i<2; i++) {//check key expansion
		REQUIRE(equal(server.aes_[i].cipher_.schedule_[0],
					server.aes_[i].cipher_.schedule_[0] + 11*16,
					client.aes_[i].cipher_.schedule_[0]));
	} // 루프를 돌면서 assertions 2개 
	//LOGD << server.decode(client.encode("hello world")) << endl;
	REQUIRE(server.decode(client.encode("hello world")) == "hello world");
	REQUIRE(client.decode(server.encode("Hello!! world")) == "Hello!! world");
}




