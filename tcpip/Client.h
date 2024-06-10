#pragma once
#include "Http.h"
#include<netdb.h>//gethostbyname

class Client : public Http
{
public:
	Client(std::string ip = "127.0.0.1", int port = 2001); ///<constructor
private:
	std::string get_addr(std::string host);
};