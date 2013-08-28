#include "../common/cryptomath.h"
#include "../common/includes.h"
#include "Hash.h"

#ifndef __SHA1__
#define __SHA1__
class SHA1 : public Hash{
    private:
        uint32_t h0, h1, h2, h3, h4;
        void run();

    public:
        SHA1(const std::string & str = "");
        std::string hexdigest();
        unsigned int blocksize();
        unsigned int digestsize();
};
#endif
