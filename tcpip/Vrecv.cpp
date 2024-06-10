#include<iostream>
#include<thread>
#include"Vrecv.h"

using namespace std;

Vrecv::Vrecv(int port) : Tcpip{port} //Tcpip를 상속
{ }


optional<string> Vrecv::recv(int fd)
{ // 부모 클래스의 recv 함수를 반복 호출해 정확한 길이의 메시지를 리턴
	int len;
	static thread_local std::string trailing_string;//for thread safety
    // 초과된 메시지를 받았을 경우, 여기에 저장
	while(!(0 < (len = get_full_length(trailing_string)) && 
				len <= trailing_string.size())) {
		if(len == -2) return {};//wrong protocol
		if(auto a = Tcpip::recv(fd)) trailing_string += *a;
		else return {}; // 에러 처리
	}
	string r = trailing_string.substr(0, len);
	trailing_string = trailing_string.substr(len); //static변수는 함수를 빠져나가도 소멸되지 않음
    // 앞부분의 리턴하여 사용될 메시지는 잘라내고(r), 뒤의 잉여메시지만 trailing_string 변수에 남긴다.
	return r;
}

int Vrecv::get_full_length(const string& s) 
{//this should be replaced with inherent class function
	return s.size();
} // 디폴트로 패킷 크기가 항상 정확히 왔다고 가정