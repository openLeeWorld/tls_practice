#pragma once
#include<map>
#include<chrono>
#include"Server.h"
#include"Client.h"
// 브라우저와 HTTP 서버 사이에서 TLS 기능을 제공하는 (https로 만드는) 미들서버
class Middle : public Server
{//use thread for multiple connection, should overload read func-> return exact one req
public:
	Middle(int outport = 4433, int inport = 2001, int time_out = 1800, int queue_limit = 10, std::string end_string = "end");
	void start();

protected:
	int inport_; // 내부 서버의 포트 번호
	bool debug_ = false;

private:
	void connected(int client_fd), conn();
	int get_full_length(const std::string &s);
};


