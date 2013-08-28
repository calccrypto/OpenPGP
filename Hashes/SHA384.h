#ifndef __SHA384__
#define __SHA384__

#include "SHA512.h"

class SHA384 : public SHA512{
    private:
        void original_h();

    public:
        SHA384(const std::string & str = "");
        std::string hexdigest();
        unsigned int digestsize();
};
#endif
