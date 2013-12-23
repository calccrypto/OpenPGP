#include "RSA.h"
std::vector <mpz_class> RSA_keygen(const unsigned int & bits){
	mpz_class p = 3, q = 3;
	while (p == q){
	    p = mpz_class("1" +  BBS().rand(bits), 2);
	    q = mpz_class("1" +  BBS().rand(bits), 2);
		p += ((p & 1) == 0);
		q += ((q & 1) == 0);
		while (!MillerRabin(p)){
			p += 2;
        }
		while (!MillerRabin(q)){
			q += 2;
        }
	}
	mpz_class n = p * q;
	mpz_class tot = (p - 1) * (q - 1);
	mpz_class e(BBS().rand(bits), 2);
	e += ((e & 1) == 0);
	while (gcd(tot, e) != 1){
        e += 2;
    }
	return {e, invmod(tot, e), n}; // split this into {e, n} and {d}
}

mpz_class RSA_encrypt(mpz_class & data, const std::vector <mpz_class> & pub){
    return POW(data, pub[1], pub[0]);
}

mpz_class RSA_encrypt(std::string & data, const std::vector <mpz_class> & pub){
    return POW(mpz_class(data, 256), pub[1], pub[0]);
}

mpz_class RSA_decrypt(mpz_class & data, const std::vector <mpz_class> & pri, const std::vector <mpz_class> & pub){
    // pri = {d, p, q, u=p^-1 mod q}
    // done backwards since u=p^-1 mod q rather than q^-1 mod p
    mpz_class dp = pri[0] % (pri[2] - 1);
    mpz_class dq = pri[0] % (pri[1] - 1);
    mpz_class m1 = POW(data, dp, pri[2]);
    mpz_class m2 = POW(data, dq, pri[1]);
    mpz_class h = (pri[3] * (m1 - m2)) % pri[2];
    return (m2 + h * pri[1]);
//    return POW(data, pri[0], pub[0]);
}

mpz_class RSA_sign(std::string & data, const std::vector <mpz_class> & pri, const std::vector <mpz_class> & pub){
    mpz_class d(data, 256);
    return RSA_decrypt(d, pri, pub);
}

mpz_class RSA_sign(mpz_class & data, const std::vector <mpz_class> & pri, const std::vector <mpz_class> & pub){
    return RSA_decrypt(data, pri, pub);
}

bool RSA_verify(std::string & data, std::vector <mpz_class> & signature, std::vector <mpz_class> & pub, const uint8_t & hash){
    return (RSA_encrypt(data, pub) == mpz_class(data, 256));
}
