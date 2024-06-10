#include "TlsLayer.h"

using namespace std;

TlsLayer::TlsLayer(int port) : Vrecv{port}
{ }

int TlsLayer::get_full_length(const string& s)
{ // 4,5번째 바이트가 TLS 패킷의 길이이므로 계산으로 구할 수 있다.
	if(s.size() < 5) return -1;
	return static_cast<unsigned char>(s[3]) * 0x100 + static_cast<unsigned char>(s[4]) + 5;
} // 4,5번째 바이트를 빅 엔디안 형식으로 계산하고 TLS헤더의 크기인 5를 더한다.

