#include "RSA.h"
std::vector <integer> RSA_keygen(const unsigned int & bits){
	integer p = 3, q = 3;
	while (p == q){
	    p = integer("1" +  BBS(rand(), bits).rand(), 2);
	    q = integer("1" +  BBS(rand(), bits).rand(), 2);
		p += !(p & 1);
		q += !(q & 1);
		while (!MillerRabin(p)){
			p += 2;
        }
		while (!MillerRabin(q)){
			q += 2;
        }
	}
	integer n = p * q;
	integer tot = (p - 1) * (q - 1);
	integer e(BBS(rand(), bits).rand(), 2);
	e += !(e & 1);
	while (gcd(tot, e) != 1){
        e += 2;
    }
	return {e, invmod(tot, e), n}; // split this into {e, n} and {d}
}


integer RSA_encrypt(integer & data, const std::vector <integer> & key){
    return POW(data, key[1], key[0]);
}

integer RSA_encrypt(std::string & data, const std::vector <integer> & key){
    return POW(integer(data, 256), key[1], key[0]);
}

std::string RSA_decrypt(integer & data, const std::vector <integer> & key){
    // key = {d, p, q, u=p^-1 mod q}
    // done backwards since u=p^-1 mod q rather than q^-1 mod p
    integer dp = key[0] % (key[2] - 1);
    integer dq = key[0] % (key[1] - 1);
    integer m1 = POW(data, dp, key[2]);
    integer m2 = POW(data, dq, key[1]);
    integer h = (key[3] * (m1 - m2)) % key[2];
    return (m2 + h * key[1]).str(256);
}

integer RSA_sign(std::string & data, const integer & d, const integer & n){
    return POW(integer(data, 256), d, n);
}

bool RSA_verify(std::string & data, std::vector <integer> & signature, std::vector <integer> & key, const uint8_t & hash){
    integer mod; mod.fill(Hash_Length.at(Hash_Algorithms.at(hash)));// sort of skips RFC 4880 sec 13.1.3
    return ((POW(signature[0], key[1], key[0]) & mod) == integer(data, 256));
}
