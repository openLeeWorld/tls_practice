#include "SHA1.h"

using namespace std;
/* //해쉬 연습용
int hash1(const char *p) {
    int sum = 0;
    while(*p) sum += *p++;
    return sum % 256;
}

int main() {
    char p[100] = "give him 1000 dollars";
    cout << hash1(p) << endl; // 해쉬값 251
    p[9] = '2';
    cout << hash1(p) << endl; //해쉬값 252
    strcpy(p, "give him 182222000 dollars"); // 해쉬값 251
    cout << hash1(p) << endl;
}
*/
SHA1::SHA1() {
    unsigned int k = 0x12345678;
    if(htonl(k) == k) big_endian_ = true; //32비트 정수를 호스트 바이트 순서에서 네트워크 바이트 순서로 변환합니다.
}

static uint32_t left_rotate(uint32_t a, int bits) {
    return a << bits | a >> (32 - bits); //부호 없는 4B는 시프트 시 0으로 채운다. 
} //static함수는 이 파일에서만 참조가 가능

void SHA1::preprocess(vector<unsigned char> &v)
{
	size_t sz = v.size() * 8;
	v.push_back(0x80);
	for(int i=0; i<8; i++) v.push_back(0);//make space for size
	while(v.size() % 64) v.push_back(0);
	for(auto it = v.rbegin(); sz; sz /= 0x100) *it++ = sz % 0x100;
}

void SHA1::process_chunk(unsigned char *p) //64 byte chunk
{ //p는 w[0]~w[15]를 가리키고 있다. (모든 블럭의 64B chunk)
    //블록의 확장
    memcpy(w, p, 64);
    if(!big_endian_) for(int i=0; i<16; i++) w[i] = htonl(w[i]); // 인텔(LE)이든 ARM(LE)이든 상관없이 
    for(int i=16; i<80; i++) {
        w[i] = left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }

    //블록의 처리
    uint32_t a=h[0], b=h[1], c=h[2], d=h[3], e=h[4], f, tmp;
    const uint32_t k[4] =
        { 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 };

    for(int i=0; i<80; i++) {
        switch(i/20) {
            case 0: f = (b & c) | ((~b) & d); break;
            case 1: f = b ^ c  ^ d; break;
            case 2: f = (b & c) | (b & d) | (c & d); break;
            case 3: f = b ^ c ^ d; break;
        }

        tmp = left_rotate(a, 5) + f + e + k[i/20] + w[i];
        e = d; d = c; c = left_rotate(b, 30); b = a; a = tmp;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

