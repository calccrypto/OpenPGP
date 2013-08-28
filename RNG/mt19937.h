/* Mersenne Twister 2^19937-1
Range of [0, 2**32-1]*/

#include <ctime>
#include <iostream>

#include "../common/includes.h"

#ifndef __MT19937__
#define __MT19937__
class mt19937{
    private:
        int32_t MT[624], index;

        void init(int32_t seed);
        void generateNumbers();

    public:
        mt19937();
        mt19937(int32_t seed);
        int32_t randInt();
        float rand();
};
#endif
