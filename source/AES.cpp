#include "AES.h"

using namespace std;
/*
void AES::key(const unsigned char *pkey) // AES 키 확장
{
    memcpy(schedule_[0], pkey, 16); // 최초 키 가져오기
    unsigned char *p = &schedule_[1][0]; // 2라운드의 첫번째 바이트
    for(int i=1; i<ROUND; i++) { // 2라운드 부터 11라운드까지(1~10)
        for(int j=0; j<3; j++) *(p+j)=*(p+j-3); // 1. 첫번째 라운드의 마지막 4바이트 rotate -> 두번째 첫 4B
        *(p+3) = *(p-4); // 1. 마지막 4바이트 rotate(첫번째 -> 마지막)
        for(int j=0; j<4; j++) *(p+j) = sbox[*(p+j)]; //2. 각 byte당 sbox로 암호화
        for(int j=0; j<4; j++, p++) { // p+=4(포인터 연산, 포인터는 4B)
            *p ^= rcon[i-1][j]; //3. rcon({rc_i,0,0,0})과 xor
            *p ^= *(p - 4*N); // 3. 앞라운드의 첫번째 4B와 xor 
        }
        for(int j=0; j<12; j++, p++) *p = *(p - 4*N) ^ *(p - 4); //4. 두번째 나머지 12B: 앞라운드 해당 위치 B랑 
    }
} // 책에 있는 오류 코드
*/

void AES::key(const unsigned char *pkey) {
    memcpy(schedule_[0], pkey, 16); // 최초 키 가져오기

    for (int i = 1; i < ROUND; ++i) {
        unsigned char temp[4];
        memcpy(temp, schedule_[i - 1] + 12, 4); // 마지막 4바이트 복사

        // RotWord
        unsigned char t = temp[0];
        for (int j = 0; j < 3; ++j) {
            temp[j] = temp[j + 1];
        }
        temp[3] = t;

        // SubWord
        for (int j = 0; j < 4; ++j) {
            temp[j] = sbox[temp[j]];
        }

        // Rcon
        temp[0] ^= rcon[i - 1][0];

        for (int j = 0; j < 4; ++j) {
            schedule_[i][j] = schedule_[i - 1][j] ^ temp[j];
        }

        for (int j = 4; j < 16; ++j) {
            schedule_[i][j] = schedule_[i - 1][j] ^ schedule_[i][j - 4];
        }
    }
}

void AES::encrypt(unsigned char *m) const
{
    add_round_key(m, 0);
    for(int round=1; round<ROUND-1; round++) {
        substitute(m);
        shift_row(m);
        mix_column(m);
        add_round_key(m, round);
    }
    substitute(m);
    shift_row(m);
    add_round_key(m, ROUND-1);
} //16byte 암호화

void AES::decrypt(unsigned char *p) const
{
    add_round_key(p, ROUND-1);
    for(int round=ROUND-2; round>0; round--) {
        inv_shift_row(p);
        inv_substitute(p);
        add_round_key(p, round);
        inv_mix_column(p);
    }
    inv_shift_row(p);
    inv_substitute(p);
    add_round_key(p, 0);
} //16byte 복호화

void AES::shift_row(unsigned char *p) const
{
    unsigned char tmp, tmp2; //0행은 그대로
    tmp=p[1]; p[1]=p[5]; p[5]=p[9]; p[9]=p[13]; p[13]=tmp; // 1행을 좌측으로 1씩 옮김
    tmp=p[2]; tmp2=p[6]; p[2]=p[10]; p[6]=p[14]; p[10]=tmp; p[14]=tmp2; // 2행을 좌측으로 2씩 옮김
    tmp=p[3]; p[3]=p[15]; p[15]=p[11]; p[11]=p[7]; p[7]=tmp; //3행을 좌측으로 3씩 옮김
}

void AES::inv_shift_row(unsigned char *p) const
{
    unsigned char tmp, tmp2;
    tmp=p[13]; p[13]=p[9]; p[9]=p[5]; p[5]=p[1]; p[1]=tmp; // 1행을 우측으로 1씩 옮김
    tmp=p[10]; tmp2=p[14]; p[14]=p[6]; p[10]=p[2]; p[6]=tmp2; p[2]=tmp; // 2행을 우측으로 2씩 옮김
    tmp=p[7]; p[7]=p[11]; p[11]=p[15]; p[15]=p[3]; p[3]=tmp; // 2행을 우측으로 2씩 옮김
}

void AES::substitute(unsigned char *p) const
{
    for(int i=0; i<16; i++) p[i] = AES::sbox[p[i]];
}

void AES::inv_substitute(unsigned char *p) const
{
    for(int i=0; i<16; i++) p[i] = AES::inv_sbox[p[i]];
}

void AES::mix_column(unsigned char *p) const
{ // c Ⓧ 1, c Ⓧ 2, c Ⓧ 3을 사용하여 갈루아 행렬 연산을 수행한다.
    static const unsigned char mix[4][4] // 변환 행렬을 행 순서로 씀
    = {{2, 3, 1, 1}, {1, 2, 3, 1}, {1, 1, 2, 3}, {3, 1, 1, 2}};
    unsigned char c[4], d, result[16];
    for(int y=0; y<4; y++) for(int x=0; x<4; x++) { //열->행 순으로 순회
        for(int i=0; i<4; i++) {
            d = p[4*x + i]; // 16byte의 메시지를 행렬로 하여 열별로 원소 가져오기
            switch(mix[y][i]) {
                case 1: c[i] = d; break;
                case 2: c[i] = d << 1; break;
                case 3: c[i] = d << 1 ^ d; break; // 쉬프트 후 자기자신과 exclusive-or
            }
            if((d & 1<<7) && (mix[y][i] != 1)) c[i] ^= 0x1b; //결합법칙
        }
        result[4*x + y] = c[0] ^ c[1] ^ c[2] ^ c[3]; //갈루아 곱 결과들을 다 갈루아 합(행->열 순서로 저장)
    }
    memcpy(p, result, 16); // void* memcpy(void* dest, const void* src, std::size_t count);
}

void AES::inv_mix_column(unsigned char *p) const
{
    static const unsigned char mix[4][4] // 역변환 행렬을 행 순서로 씀
    = {{14, 11, 13, 9}, {9, 14, 11, 13}, {13, 9, 14, 11}, {11, 13, 9, 14}};
    
    unsigned char c[4], d, result[16];
    for(int y=0; y<4; y++) for(int x=0; x<4; x++) {
        for(int i=0; i<4; i++) {
            d = p[4*x + i]; // 열 순서대로 가져옴
            switch(mix[y][i]) {
                case 9: c[i]= doub(doub(doub(d))) ^ d; break;
                case 11 :c[i]= doub(doub(doub(d)) ^ d) ^ d; break;
                case 13: c[i]= doub(doub(doub(d) ^ d)) ^ d; break;
                case 14: c[i]= doub(doub(doub(d) ^ d) ^ d); break;
            }
        }
        result[4*x + y] = c[0] ^ c[1] ^ c[2] ^ c[3]; //갈루아 곱 결과들을 다 갈루아 합(행->열 순서로 저장)
    }
    memcpy(p, result, 16); // void* memcpy(void* dest, const void* src, std::size_t count);
}

void AES::add_round_key(unsigned char *p, int round) const //역변환도 가능
{
    for(int i=0; i<16; i++) p[i] ^= schedule_[round][i]; 
} //확장된 키를 각 라운드에 맞춰서 메시지와 xor(변환과 역변환이 동일)

unsigned char AES::doub(unsigned char c) const// 갈루아 필드에서의 c Ⓧ 2 연산 구현
{
    bool left_most_bit = c & 1 << 7;
    c <<= 1; // 2배 후 저장
    if(left_most_bit) c ^= 0x1b;
    return c;
}