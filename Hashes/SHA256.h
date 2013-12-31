#include "../common/cryptomath.h"
#include "../common/includes.h"
#include "Hash.h"

#ifndef __SHA256__
#define __SHA256__

#include "SHA2_Functions.h"
#include "SHA256_Const.h"

class SHA256 : public Hash{
    protected:
        uint32_t h0, h1, h2, h3, h4, h5, h6, h7;

        uint32_t S0(const uint32_t & value);
        uint32_t S1(const uint32_t & value);
        uint32_t s0(const uint32_t & value);
        uint32_t s1(const uint32_t & value);

        virtual void original_h();
        void run();

    public:
        SHA256(const std::string & str = "");
        std::string hexdigest();
        unsigned int blocksize();
        virtual unsigned int digestsize();
};

#endif
