#include<iomanip>
#include<sstream>
#include<string>
#include<istream>
#include<vector>
#include "jsoncpp/json/json.h"
#include "mpz_utility.h"
#include "der.h"
#include "cert.h"
// der은 json형식처럼 데이터를 형식과 값의 쌍으로 표현
using namespace std;
// der은 Type 1B, length, contents으로 이루어짐
static ber::Type read_type(unsigned char c)
{ //한 바이트를 줬을 때 그것을 해석해 Type 구조체를 반환하는 함수
	ber::Type type;
	type.cls = static_cast<ber::Class>((c & 0b11000000) >> 6);
	type.pc = static_cast<ber::PC>((c & 0b00100000) >> 5);
	type.tag = static_cast<ber::Tag>(c & 0b00011111);
	return type;
}

static int read_length(istream& is)
{ // (int) length 읽기
	unsigned char c;
	if(!(is >> noskipws >> c)) throw "reached eof in read_length"; // noskipws: 공백 입력 스킵 안함 
	if(c & 0b10000000) { // 여러 바이트로 길이(128byte이상이라 길이로 2byte이상)를 표현하는 경우
		vector<unsigned char> v;
		for(int i = 0, j = c & 0b01111111; i < j; i++) {// j는 길이 byte(i를 늘리면서 길이 바이트 값을 가져옴)
			is >> c; // c에다 입력 스트림의 한 글자 입력 
			v.push_back(c);
		}
		return bnd2mpz(v.begin(), v.end()).get_si(); // 총 길이를 signed long int로 변환
	} else return c & 0b01111111; // 한 바이트로 길이 표현 시 길이가 127byte미만임
}

static vector<unsigned char> read_value(istream& is, int len)
{ // contents 읽기 : len만큼 입력 스트림에서 읽어 들여 벡터에 채워 리턴
	unsigned char c; vector<unsigned char> v;
	for(int i=0; i<len; i++) {
		if(!(is >> noskipws >> c)) throw "reached eof in read_value"; // noskipws: 공백 입력 스킵 안함
		v.push_back(c);
	}
	return v;
}

static Json::Value type_change(ber::Tag tag, vector<unsigned char> v)
{ // 벡터에 담긴 contents를 타입에 따라서 형식을 달리 해 json 값으로 만든다.
	switch(tag) {
		case ber::EOC: return "eoc";
		case ber::BOOLEAN: return v[0] ? true : false;
		case ber::INTEGER: //return (int)bnd2mpz(v.begin(), v.end()).get_si();
		case ber::BIT_STRING:
		case ber::OCTET_STRING:
		case ber::NUMERIC_STRING:
		case ber::OBJECT_IDENTIFIER:
		case ber::OBJECT_DESCRIPTOR:
		{ // 두 바이트씩 16진수로 해석
			stringstream ss;
			for(auto a : v) ss << hex << setw(2) << setfill('0') << +a << ':';
			return ss.str();
		}
		case ber::NULL_TYPE: return "null";
		case ber::EXTERNAL:
		case ber::REAL: return *(float*)v.data();
		case ber::ENUMERATED:
		case ber::EMBEDDED_PDV:
		case ber::RELATIVE_OID:

		default:
		{//strings
			stringstream ss;
			for(auto a : v) ss << a;
			return ss.str();
		}
	}
}

static Json::Value read_constructed(istream& is, int length) 
{ // 복합적인 데이터일 경우 재귀적으로 호출돼, 중층적인 json값을 만든다.
	Json::Value jv;
	int start_pos = is.tellg(); // tellg() 함수: 입력 스트림의 현재 읽기 위치(바이트 오프셋)
	unsigned char c;
	for(int i=0, l; (int)is.tellg()-start_pos < length && is >> noskipws >> c; i++) {
		auto type = read_type(c);
		l = read_length(is);
		jv[i] = type.pc == ber::PRIMITIVE ? 
			type_change(type.tag, read_value(is, l)) : read_constructed(is, l);
	}
	return jv;
}

Json::Value der2json(istream& is) 
{
	Json::Value jv;
	unsigned char c;
	for(int i=0, l; is >> noskipws >> c; i++) {
		auto type = read_type(c);
		l = read_length(is);
		jv[i] = type.pc == ber::PRIMITIVE ? 
			type_change(type.tag, read_value(is, l)) : read_constructed(is, l);
	}
	return jv;
}
