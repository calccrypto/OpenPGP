#include <iostream>

#include "../common/includes.h"

#ifndef __HASH__
#define __HASH__
class Hash{
    protected:
        std::string total = "";
        virtual void run() = 0;

    public:
        Hash();
        void update(const std::string & str);
        virtual std::string hexdigest() = 0;
        std::string digest();
        virtual unsigned int blocksize() = 0;
        virtual unsigned int digestsize() = 0;
};
#endif
