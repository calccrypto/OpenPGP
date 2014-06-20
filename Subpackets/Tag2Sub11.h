// Preferred Symmetric Algorithms
#ifndef __TAG2SUB11__
#define __TAG2SUB11__

#include "subpacket.h"

class Tag2Sub11 : public Subpacket{
    private:
        std::string psa;

    public:
        typedef std::shared_ptr<Tag2Sub11> Ptr;

        Tag2Sub11();
        Tag2Sub11(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        std::string get_psa();  // string containing Symmetric Key Algorithm values (ex: "\x07\x08\x09")

        void set_psa(const std::string & s);

        Subpacket::Ptr clone() const;
};
#endif
