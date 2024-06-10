#include "Client.h"

using namespace std;

int main() {
    Client cl{"localhost", 2002};
    cl.send("GET /");
    cout << *cl.recv() << endl;
}