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


integer RSA_encrypt(integer & data, const std::vector <integer> & pub){
    return POW(data, pub[1], pub[0]);
}

integer RSA_encrypt(std::string & data, const std::vector <integer> & pub){
    return POW(integer(data, 256), pub[1], pub[0]);
}

integer RSA_decrypt(integer & data, const std::vector <integer> & pri){
    // pri = {d, p, q, u=p^-1 mod q}
    // done backwards since u=p^-1 mod q rather than q^-1 mod p
    integer dp = pri[0] % (pri[2] - 1);
    integer dq = pri[0] % (pri[1] - 1);
    integer m1 = POW(data, dp, pri[2]);
    integer m2 = POW(data, dq, pri[1]);
    integer h = (pri[3] * (m1 - m2)) % pri[2];
    return (m2 + h * pri[1]);
}

integer RSA_sign(std::string & data, const std::vector <integer> & pri){
    integer d(data, 256);
    return RSA_decrypt(d, pri);
}

integer RSA_sign(integer & data, const std::vector <integer> & pri){
    return RSA_decrypt(data, pri);
}

bool RSA_verify(std::string & data, std::vector <integer> & signature, std::vector <integer> & pub, const uint8_t & hash){
    return (RSA_encrypt(data, pub) == integer(data, 256));
}
