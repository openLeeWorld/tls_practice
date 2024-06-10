#include <iostream>
//#include <string>
//#include <cstring>
#include <arpa/inet.h> // htons, htonl
#include <unistd.h>
//#include <netdb.h>
//#include <x86_64-linux-gnu/sys/socket.h>
//#include <x86_64-linux-gnu/sys/types.h>
#include <netinet/in.h> // 소켓 프로그래밍에서 쓰이는 sockaddr_in 구조체
#include <fcntl.h> // 파일 컨트롤

using namespace std;

int main() {
    struct sockaddr_in server_addr;
    const int port = 2001;
    char buffer[4096];
    server_addr.sin_family = PF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    int client_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    if(connect(client_fd, (sockaddr*)&server_addr, sizeof(server_addr)) == -1) return -1;
    else {
        write(client_fd, "GET /", 5);
        read(client_fd, buffer, 4096);
        cout << "서버가 보낸 문자: " << buffer << endl;
    }

    close(client_fd);
    return 0;
}