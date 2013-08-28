// Embedded Signature
#include "../Packets/Tag2.h"
#include "subpacket.h"

#ifndef __TAG2SUB32__
#define __TAG2SUB32__
class Tag2Sub32 : public Subpacket{
    private:
        Tag2 * embedded;

    public:
        Tag2Sub32();
        Tag2Sub32(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        Tag2Sub32 * clone();

        Tag2 * get_embedded();

        void set_embedded(Tag2 * e);
};
#endif
