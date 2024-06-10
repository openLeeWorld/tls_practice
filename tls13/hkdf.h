#pragma once
#include<cstring>
#include"hmac.h"

template<class H> class HKDF : public HMAC<H>
{ // tls13에서는 PRF 대신 HKDF를 사용해 키 확장을 한다. (H: 해시함수)
	public:	
	void zero_salt() { // 해시 함수의 아웃풋 길이만큼 0으로 채워진 것을 key로 삼는 함수(key scheduling)
		uint8_t zeros[H::output_size] = {0,};
		this->key(zeros, zeros + H::output_size);
	} // 부모 클래스의 key함수를 사용
	void salt(uint8_t *p, int sz) {
		this->key(p, p + sz); // this로 부모 클래스의 함수를 사용
	} // 내부적인 HMAC의 key를 세팅
	std::vector<uint8_t> extract(uint8_t *p, int sz) {
		auto a = this->hash(p, p + sz);
		return std::vector<uint8_t>{a.begin(), a.end()}; //return PRK(pseudorandom key)
	} // 내부적인 해시 함수를 불러다 extract (salt를 부르고 extract)
	std::vector<uint8_t> derive_secret(std::string label, std::string msg) {
		auto a = this->sha_.hash(msg.begin(), msg.end());
		return expand_label(label, std::string{a.begin(), a.end()}, H::output_size);
	} 
	std::vector<uint8_t> expand(std::string info, int L) {
		std::vector<uint8_t> r;
		int k = H::output_size + info.size() + 1;
		uint8_t t[k];
		memcpy(t + H::output_size, info.data(), info.size());
		t[k-1] = 1;
		auto a = this->hash(t + H::output_size, t + k);
		r.insert(r.end(), a.begin(), a.end());
		while(r.size() < L) {
			memcpy(t, &a[0], a.size());
			t[k-1]++;
			a = this->hash(t, t + k);
			r.insert(r.end(), a.begin(), a.end());
		}
		r.resize(L);
		return r;
	}
	std::vector<uint8_t> expand_label(std::string label, std::string context, int L) {
		std::string s = "xxxtls13 " + label + 'x' + context;
		s[0] = L / 0x100;
		s[1] = L % 0x100;
		s[2] = label.size() + 6;
		s[label.size() + 9] = context.size();
		return expand(s, L);
	}
};

