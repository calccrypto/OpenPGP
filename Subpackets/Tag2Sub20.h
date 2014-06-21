// Notation Data
#ifndef __TAG2SUB20__
#define __TAG2SUB20__

#include "subpacket.h"

class Tag2Sub20 : public Subpacket{
    private:
        std::string flags;  // 4 octets
        uint16_t mlen;
        uint16_t nlen;
        std::string m;      // mlen octets long
        std::string n;      // nlen octets long

    public:
        typedef std::shared_ptr<Tag2Sub20> Ptr;

        Tag2Sub20();
        Tag2Sub20(std::string & data);
        void read(std::string & data);
        std::string show() const;
        std::string raw() const;

        std::string get_flags() const;
        std::string get_m() const;
        std::string get_n() const;

        void set_flags(const std::string & f);
        void set_m(const std::string & s);
        void set_n(const std::string & s);

        Subpacket::Ptr clone() const;
};
#endif
