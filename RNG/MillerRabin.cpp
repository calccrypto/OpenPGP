#include "MillerRabin.h"

bool test(mpz_class a, mpz_class & n){
  mpz_class b = n - 1;
  mpz_class d = 1;
  for(unsigned int i = makebin(b).size(); i > 0; i--){
    mpz_class x = d;
    d = (d * d) % n;
    if ((d == 1) && (x != 1) && (x != n - 1)){
      return 1;//True # Complex
    }
    if ((b >> (i - 1) & 1) == 1){
      d = (d * a) % n;
    }
  }
  if (d != 1){
    return 1;//True # Complex
  }
  return 0;//False # Prime
}

bool MillerRabin(mpz_class n, uint8_t s){
  for(uint8_t j = 1; j < s + 1; j++){
    if (test((mpz_class(rand()) % (n - 3)) + 2, n)){// can't use BBS: infinite recursion. No other RBG availible
      return 0;//False # n is complex
    }
  }
  return 1;//True # n is prime
}
// ////////////////////////////////////////////////////////////////////

// FIPS 186-3 C.3.1 Miller-Rabin Probabilistic Primality Test
bool MillerRabin_FIPS186(mpz_class w, uint8_t iterations){
    // check FIPS 186-3 Tables C.1, C.2, C.3 for iterations values
    unsigned int a = 0;
    mpz_class W = w - 1, m = W;
    while ((m & 1) == 0){
        m >>= 1;
        a++;
    }
    unsigned int wlen = makebin(w).size();
    for(uint8_t i = 0; i < iterations; i++){
        mpz_class b = (mpz_class(BBS(wlen).rand(), 2) % (W - 2)) + 2;// probably better but really slow
//        mpz_class b = (mpz_class(rand()) % (W - 2)) + 2;
        mpz_class z = POW(b, m, w);
        bool cont = false;
        if ((z == 1) || (z == W)){}
        else{
            for(unsigned int j = 1; j < a; j++){
                z = POW(z, 2, w);
                if (z == W){
                    cont = true;
                    break;
                }
                if (z == 1){
                    return 0;// Composite
                }
            }
            if (!cont){
                return 0;
            }
        }
    }
    return 1;// Probably Prime
}
