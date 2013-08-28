#include "../common/cryptomath.h"
#include "../common/includes.h"
#include "Hash.h"

#ifndef __SHA512__
#define __SHA512__

#include "SHA2_Functions.h"
#include "SHA512_Const.h"

class SHA512 : public Hash{
    protected:
        uint64_t h0, h1, h2, h3, h4, h5, h6, h7;
        uint64_t S0(uint64_t & value);
        uint64_t S1(uint64_t & value);
        uint64_t s0(uint64_t & value);
        uint64_t s1(uint64_t & value);

        virtual void original_h();
        void run();

    public:
        SHA512(const std::string & str = "");
        std::string hexdigest();
        unsigned int blocksize();
        virtual unsigned int digestsize();
};
#endif
