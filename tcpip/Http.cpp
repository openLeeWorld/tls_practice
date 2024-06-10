#include "Http.h"

using namespace std;

Http::Http(int port) : Vrecv{port}
{ }

int Http::get_full_length(const string &s)
{//get full length of one request. assume that s is a first received string
	smatch m;
	if(regex_search(s, m, regex{R"(Content-Length:\s*(\d+))"})) 
		return stoi(m[1].str()) + s.find("\r\n\r\n") + 4; 
	else return s.size();
} // Content length는 헤더 자체는 포함하지 않은 길이이므로 헤더의 종료지점인 \r\n\r\n 까지의 길이를 더하고 개행문자 
// 자체의 길이인 4를 더했다. 헤더가 오지 않은 경우에는 제대로 받은 것으로 상정하고 스트링 사이즈를 리턴한다.