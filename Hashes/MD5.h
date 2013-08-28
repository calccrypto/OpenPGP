#include "../common/cryptomath.h"
#include "../common/includes.h"
#include "Hash.h"

#ifndef __MD5__
#define __MD5__

#include "MD5_Const.h"

class MD5 : public Hash{
    private:
        uint32_t h0, h1, h2, h3;
        void run();

    public:
        MD5(const std::string & str = "");
        std::string hexdigest();
        unsigned int blocksize();
        unsigned int digestsize();
};
#endif
