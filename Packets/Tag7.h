// Secret-Subkey Packet
#include "Tag5.h"

#ifndef __TAG7__
#define __TAG7__
class Tag7 : public Tag5{
    public:
        Tag7();
        Tag7(const Tag7 & tag7);
        Tag7(std::string & data);
        ~Tag7();

        Tag7 * clone();
        Tag7 operator=(const Tag7 & tag7);
};
#endif
