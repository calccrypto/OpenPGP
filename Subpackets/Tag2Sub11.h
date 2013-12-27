// Preferred Symmetric Algorithms
#include "subpacket.h"

#ifndef __TAG2SUB11__
#define __TAG2SUB11__
class Tag2Sub11 : public Subpacket{
    private:
        std::string psa;

    public:
        Tag2Sub11();
        Tag2Sub11(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        Tag2Sub11 * clone();

        std::string get_psa();  // string containing Symmetric Key Algorithm values (ex: "\x07\x08\x09")

        void set_psa(const std::string & s);
};
#endif
