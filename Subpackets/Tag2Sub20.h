// Notation Data
#include "subpacket.h"

#ifndef __TAG2SUB20__
#define __TAG2SUB20__
class Tag2Sub20 : public Subpacket{
    private:
        std::string flags;  // 4 octets
        uint16_t mlen;
        uint16_t nlen;
        std::string m;      // mlen octets long
        std::string n;      // nlen octets long

    public:
        Tag2Sub20();
        Tag2Sub20(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        Tag2Sub20 * clone();

        std::string get_flags();
        std::string get_m();
        std::string get_n();

        void set_flags(std::string f);
        void set_m(std::string s);
        void set_n(std::string s);
};
#endif
