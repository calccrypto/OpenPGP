#ifndef __SHA224__
#define __SHA224__

#include "SHA256.h"

class SHA224 : public SHA256{
    private:
        void original_h();

    public:
        SHA224(const std::string & str = "");
        std::string hexdigest();
        unsigned int digestsize();
};
#endif
