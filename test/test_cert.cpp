#include <fstream>
#include <string>
#include <iostream>
#include <sstream>
#include "SHA1.h"
#include "mpz_utility.h"
#include "cert.h"

using namespace std;

int main() {
    // 파일 열기 시도
    ifstream f("/home/amy/cmake_my_project/server-cert.pem");
    if (!f.is_open()) {
        cerr << "Failed to open file: server-cert.pem" << endl;
        return 1;
    }

    try {
        // 첫 번째 인증서 처리
        string s = get_certificate_core(f);
        auto v = base64_decode(s);
        SHA2 sha;
        int length = v[6] * 256 + v[7] + 4; // 첫 번째 인증서의 TBSCertificate 길이 계산
        cout << hexprint("hash", sha.hash(v.begin() + 4, v.begin() + length + 4)) << endl;

        stringstream ss;
        for(uint8_t c : v) ss << c;
        auto jv = der2json(ss);
        auto [K, e, sign] = get_pubkeys(jv);
        // 추출한 TBS 인증서의 서명(상위 인증서의 개인 키로 서명됨)을 상위 인증서의 공개 키를 사용하여 검증합니다.
        // 두 번째 인증서 처리
        s = get_certificate_core(f);
        v = base64_decode(s);
        stringstream ss2;
        for(uint8_t c : v) ss2 << c;
        jv = der2json(ss2);
        auto [K2, e2, sign2] = get_pubkeys(jv);
        auto k = powm(sign, e2, K2); // 첫번째 인증서의 해시값을 구한다.
        cout << hex << k << endl;
    } catch (const exception& ex) {
        cerr << "An error occurred: " << ex.what() << endl;
        return 1;
    }

    f.close();
    return 0;
}
