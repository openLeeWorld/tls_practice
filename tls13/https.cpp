#include"https.h"
#include<iostream>
#include<unistd.h>
#include<cassert>
#include<thread>
#include"tls13.h"
#include"log.h"

using namespace std;

Middle::Middle(int outport, int inport, int timeout, int queue, string end)
	: Server{outport, timeout, queue, end}, inport_{inport}
{//hI = this; 
	LOGI << "opening inner port " << inport << endl;
} 
	
int Middle::get_full_length(const string &s) 
{//this make HTTP recv into TLS recv
	if(s.size() < 5) return -1;
	else if((uint8_t)s[0] < 0x14 || (uint8_t)s[0] > 0x18) return -2;//not tls message
	return static_cast<unsigned char>(s[3]) * 0x100 + static_cast<unsigned char>(s[4]) + 5;
} // recv 함수가 TLS 패킷 사이즈만큼 받아오는 것을 가능하게 한다.
	
void Middle::conn()
{ // 각각의 접속마다 새로운 스레드를 생성한다.
	int cl_size = sizeof(client_addr);
	vector<thread> v;
	while(1) {
		client_fd = accept(server_fd, (sockaddr*)&client_addr, (socklen_t*)&cl_size); // 접속 대기
		LOGI << "accepting " << client_fd << " fd" << endl;
		if(client_fd == -1) LOGF << "accept() error" << endl;
		else {//fork가 아니므로 client_fd가 변함. (접속 시 connected 함수 스레드를 생성한다.)
			v.emplace_back(thread{&Middle::connected, this, client_fd}); // 벡터에 끝에 스레드 요소 추가
			v.back().detach(); // 스레드를 분리해서 백그라운드에서 독립적으로 시행(join 호출 필요 없이 종료 가능)
		}
	}
}

void Middle::start()
{//middle server can be managed here (커맨드 라인 상에서 운영 가능)
	thread th{&Middle::conn, this}; // 접속 대기 스레드
	th.detach();
	string s;
	cout << "starting middle server, enter '?' to see commands." << endl;
	while(cin >> s) {
		if(s == "end") break;
		else if(s == "help" || s == "?")
			cout << "end, timeout [sec]" << endl << "current timeout " << time_out << endl;
		else if(s == "timeout") {
			cin >> time_out;
			cout << "time out set " << time_out << endl;
		}
	} // 부모 클래스인 Server 자체에 타임아웃 기능을 심어둠
}

void Middle::connected(int fd) // 한 스레드당 tls 함수를 수행할 클라이언트 생성
{//will be used in parallel
	TLS13<SERVER> t;//TLS is decoupled from file descriptor (지역변수)
	if(t.handshake(bind(&Middle::recv, this, fd),
			bind(&Middle::send, this, placeholders::_1, fd))) { // 핸드셰이크 성공 시 내부 서버와 통신할 클라이언트 생성
		Client cl{"localhost", inport_};
		while(1) { // 로컬호스트에 있는 내부 서버와 통신
			if(auto a = recv(fd)) { // 외부에서 읽어 들임
				if(a = t.decode(move(*a))) cl.send(*a);//to inner server
				else break;
				if(auto b = cl.recv()) send(t.encode(move(*b)), fd);//to browser
				else break;
			} else break;
		}
	}
	close(fd); 		LOGI << "closing connection " << fd << endl;
}

