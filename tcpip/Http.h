#pragma once
#include "Vrecv.h"
//#include <string>
#include<regex> // 정규식 표현

class Http : public Vrecv
{ // 길이를 처리하기 위한 클래스
public:
	Http(int port);

protected:
	int get_full_length(const std::string& s); // http프로토콜에 따라 정확한 단위 길이의 메시지 받음
};