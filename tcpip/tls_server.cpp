#include<iostream>
#include"log.h"
#include"tls.h"
#include"Server.h"
using namespace std;

class TServer : public Server {
public:
	TServer(int port) : Server{port} {}
private:
	int get_full_length(const string &s) {
		return s.size() < 5 ? 0 : static_cast<unsigned char>(s[3]) * 0x100 + static_cast<unsigned char>(s[4]) + 5;
	}
};

// 서버 함수에서 실행할 함수 객체
class Func {
public:
	Func() = default; // 기본 생성자를 사용
	Func(const Func &r) { }
	string operator()(string s) { // 괄호연산자를 정의해 클래스 자체가 함수 객체로서 기능
		string to_send;
		switch(count) {
		case 0 : t.client_hello(move(s));
				 to_send = t.server_hello();
				 to_send += t.server_certificate();
				 to_send += t.server_key_exchange();
				 to_send += t.server_hello_done();
				 break;
		case 1 : t.client_key_exchange(move(s)); break;
		case 2 : t.change_cipher_spec(move(s)); break;
		case 3 : t.finished(move(s));
				 to_send = t.change_cipher_spec();
				 to_send += t.finished();
				 break;
		default: cout << *t.decode(move(s)) << endl;
				 to_send = t.encode("Learning cryptography by implementing TLS");
		}
		count++; // TLS클라이언트 클래스와 얼마나 비슷한가를 보여주기 위해 만든 단순 코드(다중 스레드, 에러 처리 없음)
		return to_send;
	}
private:
	static int count;//init 0 outside of main
	TLS<true> t;
};

int Func::count = 0;

int main() {
	Log::get_instance()->set_log_filter("DI");
	TServer sv{4433};
	Func func;
	sv.start(func);
}
