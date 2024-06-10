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
    struct sockaddr_in server_addr, client_addr;
    const int port = 2001, queue = 10, cl_size = sizeof(client_addr);
    char buffer[4096];
    server_addr.sin_family = PF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int server_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    if(bind(server_fd, (sockaddr*)&server_addr, sizeof(server_addr)) == -1)
        cout << "bind() error" << endl;
    else cout << "binding" << endl;

    if(listen(server_fd, queue) == -1) cout << "listen() error\n";
    else cout << "listening port: " << port << endl;
    while(1) {
        int client_fd = accept(server_fd, (sockaddr*)&client_addr, (socklen_t*)&cl_size);

        if(client_fd == -1) cout << "accept() error" << endl;
        else {
            int n = read(client_fd, buffer, 4096);
            cout << "클라이언트가 보낸 문자: " << buffer << endl;
            write(client_fd, buffer, n); // echo
        }

        close(client_fd);
    }
    return 0;
}