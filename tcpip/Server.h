#pragma once
#include "Http.h"

class Server : public Http
{
public:
	Server(int port = 2001, unsigned int time_out = 600, int queue_limit = 10,
			std::string end_string = "end");
	void start(std::function<std::string(std::string)> f);
	void nokeep_start(std::function<std::string(std::string)> f);

protected:
	std::string end_string;
	int time_out;
};