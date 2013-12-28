// Issuer
#include "subpacket.h"

#ifndef __TAG2SUB16__
#define __TAG2SUB16__
class Tag2Sub16 : public Subpacket{
    private:
        std::string keyid; // 8 octets

    public:
        Tag2Sub16();
        Tag2Sub16(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        std::string get_keyid();

        void set_keyid(const std::string & k);

        Tag2Sub16 * clone();
};
#endif
