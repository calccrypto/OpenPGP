// Public-Subkey Packet
#ifndef __TAG14__
#define __TAG14__

#include "Tag6.h"

class Tag14 : public Tag6{
    public:
        typedef std::shared_ptr<Tag14> Ptr;

        Tag14();
        Tag14(std::string & data);
        Packet::Ptr clone() const;
};
#endif
