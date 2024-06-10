#include "Server.h"

using namespace std;

int main() {
    Server sv{2002};
    sv.start([](string s){return "Learn cryptography by implementing TLS";}); 
} // 다음 문자열을 반환하는 익명 함수를 start f에 전달한다.