//tcpip.h class definition
#pragma once
#include<iostream>
#include <string>
#include<optional>
#include <arpa/inet.h> //htonl, inet_addr, inet_ntoa
#include <netinet/in.h> // 소켓 프로그래밍에서 쓰이는 sockaddr_in 구조체
#define BUF_SIZE 4096

class Tcpip 
{//c library wrapper 
public:
	Tcpip(int port = 2001); // 기본 생성자
	virtual ~Tcpip(); // 가상 소멸자(상속 후 구현 위해 virtual)
	void send(const std::string& s, int fd = 0); // 표준 입력에 대한 send
//	void send(int n);
	std::optional<std::string> recv(int fd = 0); // 표준 입력에서 받는 recv
    // 네트워킹 데이터가 없을 경우도 다루기 위해 에러 처리 대신 optional(string)
protected:
	int server_fd; //서버 파일 디스크립터
	int client_fd; //클라이언트 파일 디스크립터
	struct sockaddr_in server_addr, client_addr;
	char buffer[BUF_SIZE];

private:
};

