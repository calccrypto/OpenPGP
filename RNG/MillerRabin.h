// Miller-Rabin Primality Test

#include <algorithm>
#include <ctime>
#include <iostream>
#include <vector>

#include <gmpxx.h>

#include "../common/cryptomath.h"
#include "BBS.h"
#include "mt19937.h"

#ifndef __MILLER_RABIN__
#define __MILLER_RABIN__

bool test(mpz_class a, mpz_class & n);
bool MillerRabin(mpz_class n, uint8_t s = 50);
bool MillerRabin_FIPS186(mpz_class w, uint8_t iterations = 50);

// ////////////////////////////////////////////////////////////////////
// Thanks to whoever from http://snippets.dzone.com/posts/show/4200 wrote this!
// I converted this code from python to C++, and changed significantly since
template <typename T> std::vector <uint8_t> toBinary(T n){
    std::vector <uint8_t> out;
    while (n){
        out.push_back(n & 1);
        n >>= 1;
    }
    return out;
}

template <typename T> bool test(T & a, T & n){
  std::vector <uint8_t> b = toBinary(n - 1);
  T d = 1;
  for(unsigned int i = b.size(); i > 0; i--){
    T x = d;
    d = (d * d) % n;
    if ((d == 1) && (x != 1) && (x != n - 1))
      return 1;//True # Complex
    if (b[i - 1])
      d = (d * a) % n;
  }
  if (d != 1)
    return 1;//True # Complex
  return 0;//False # Prime
}

template <typename T> bool MillerRabin(T n, uint8_t s){
  for(uint8_t i = 0; i < s; i++){
    T a(mt19937().randInt());
    a <<= 32;
    a += mt19937().randInt();
    a %= n - 3;
    a += 2;
    if (test(a, n))
      return 0;//False # n is complex
  }
  return 1;//True # n is prime
}
#endif
