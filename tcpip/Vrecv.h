#pragma once
#include"tcpip.h"

class Vrecv : public Tcpip
{//virtual class that provide interface to get recv work just as expected
public:
	Vrecv(int port);
	std::optional<std::string> recv(int fd=0);
	//check content length header and get one full request
protected:
	virtual int get_full_length(const std::string& s);//define this to make recv adapt to environment
    // recv함수가 적절한 길이의 메시지를 리턴
};