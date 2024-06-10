//tcpip.cc class 구현부
#include <x86_64-linux-gnu/sys/socket.h>
#include <x86_64-linux-gnu/sys/types.h>
#include<unistd.h>//close
#include<cstring>//memset
//#include<iostream>
#include<fcntl.h> // read, write
#include"tcpip.h"
using namespace std;

Tcpip::Tcpip(int port)
{
	memset(&server_addr, 0, sizeof(server_addr));//fill 0 into memset
	memset(&client_addr, 0, sizeof(client_addr)); // 구조체를 0으로 채운다
	server_addr.sin_family = AF_INET; // ipv4 주소 체계
	server_addr.sin_port = htons(port);
	server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);//get file descriptor
	client_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

Tcpip::~Tcpip()
{
	close(client_fd);
	close(server_fd);
	cout << "destroying Tcpip" << endl;
}
void Tcpip::send(const string& s, int fd) 
{
	write(!fd ? client_fd : fd, s.data(), s.size()); // fd를 생략한 디폴트(0)면 client_fd로 통신하고 명시하면 fd로 통신
}

//void Tcpip::send(int n)
//{
//	write(client_fd, buffer, n);
//}

optional<string> Tcpip::recv(int fd)
{
	int i = read(!fd ? client_fd : fd, buffer, BUF_SIZE);// fd를 생략한 디폴트(0)면 client_fd로 통신하고 명시하면 fd로 통신
	cout << "read " << i << " byte" << endl;
	if(i > 0) return string(buffer, i);
	else return {};
}

