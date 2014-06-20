// Issuer
#ifndef __TAG2SUB16__
#define __TAG2SUB16__

#include "subpacket.h"

class Tag2Sub16 : public Subpacket{
    private:
        std::string keyid; // 8 octets

    public:
        typedef std::shared_ptr<Tag2Sub16> Ptr;

        Tag2Sub16();
        Tag2Sub16(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        std::string get_keyid();

        void set_keyid(const std::string & k);

        Subpacket::Ptr clone() const;
};
#endif
