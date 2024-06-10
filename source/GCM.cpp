#include "GCM.h"

void doub(unsigned char *p) {
	bool bit1 = p[15] & 1;
	for(int i=15; i>0; i--) p[i] = (p[i] >> 1) | (p[i-1] << 7) ;
	p[0] >>= 1;
	if(bit1) p[0] ^= 0b11100001;
}

void gf_mul(unsigned char *x, unsigned char *y)
{//x = x * y
	unsigned char z[16] = {0,};
	for(int i=0; i<16; i++) {
		for(int j=0; j<8; j++) {//left most bit is 0 order
			if(y[i] & 1<<(7-j)) for(int k=0; k<16; k++) z[k] ^= x[k];
			doub(x);
		}
	}
	memcpy(x, z, 16);
//	cout << hexprint("aad", z) << endl;
}
