#include<chrono>
#include<unistd.h>
#include<x86_64-linux-gnu/sys/wait.h>
#include<x86_64-linux-gnu/sys/time.h>
#include <signal.h> // sigaction
#include<map>
#include<functional> //function f
#include "Server.h"

using namespace std;

//waitpid: 자식 프로세스의 상태 변화를 기다리는 함수
static void kill_zombie(int) { // 서버는 비동기적으로 좀비 프로세스를 죽임
	int status; // 자식 프로세스의 종료 상태를 저장할 정수 포인터
	waitpid(-1, &status, WNOHANG); // pid_t waitpid(pid_t pid, int *status, int options); 
} // -1: 모든 자식 프로세스에 대해 , WNOHANG: 자식 프로세스가 아직 종료되지 않았을 경우에도 블록 x 즉시 반환

Server::Server(int port, unsigned int t, int queue, string e) : Http(port) 
{
	end_string = e;
	time_out = t;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if(bind(server_fd, (sockaddr*)&server_addr, sizeof(server_addr)) == -1)
		cout << "bind() error" << endl;
	else cout << "binding" << endl;
	if(listen(server_fd, queue) == -1) cout << "listen() error" << endl;
	else cout << "listening port " << port << endl;

	struct sigaction sa; // 좀비 프로세스를 제거하기 위한 시그널 핸들러 설정
	sa.sa_handler = kill_zombie;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGCHLD, &sa, 0); // 부모가 자식 프로세스에 대한 시그널(SIGCHLD)을 처리함
}

void Server::start(function<string(string)> f) // f 함수 객체는 서버에서 실행할 웹사이트 클래스를 상정
{ // 웹사이트에서 브라우저로부터의 메시지를 받아서 서버측의 프로그램 실행 후 결과물로 나온 웹페이지를 보여주기
	int cl_size = sizeof(client_addr);
	while(1) {
		client_fd = accept(server_fd, (sockaddr*)&client_addr, (socklen_t*)&cl_size);
		struct timeval tv; // 시간값을 사용하기 위해 쓰는 구조체
		tv.tv_sec = time_out; // 초 단위, 시간 초과 시 접속 종료
		tv.tv_usec = 0; // 마이크로 초 단위
		setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv); // 소켓 옵션 설정  SO_RCVTIMEO: 수신 타임아웃
		if(client_fd == -1) cout << "accept() error" << endl;
		else if(!fork()) { // 자식 프로세스인 경우 각자의 요청에 대해 처리(f함수 객체와 client_fd가 복사됨)
			for(optional<string> s; s = recv(); send(f(*s)));//recv server fail 시 에러, string size 0 : error -> s.size() : verify
			send(end_string); // echo하고 end를 보낸다.
			break;//forked process ends here(while break 후 소멸)
		} // 자식 프로세스가 부모 프로세스보다 먼저 종료되고 처리가 없으므로(리턴값 전달) 좀비 프로세스가 됨
	} // 접속이 종료되거나, 에러 메시지가 오거나, 시간 초과 인터럽트가 발생할 때까지 반복한다.
} 

void Server::nokeep_start(function<string(string)> f)
{//does not keep connection
	int cl_size = sizeof(client_addr);
	while(true) {
		client_fd = accept(server_fd, (sockaddr*)&client_addr, (socklen_t*)&cl_size);
		if(client_fd == -1) cout << "accept() error" << endl;
		else {//connection established
			cout << "accepting" << endl;
			send(f(*recv()));
		}
	}
}