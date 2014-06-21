// Trust Signature
#ifndef __TAG2SUB5__
#define __TAG2SUB5__

#include "subpacket.h"

class Tag2Sub5 : public Subpacket{
    private:
        uint8_t level;
        uint8_t amount;

    public:
        typedef std::shared_ptr<Tag2Sub5> Ptr;

        Tag2Sub5();
        Tag2Sub5(std::string & data);
        void read(std::string & data);
        std::string show() const;
        std::string raw() const;

        uint8_t get_level() const;
        uint8_t get_amount() const;

        void set_level(const uint8_t l);
        void set_amount(const uint8_t a);

        Subpacket::Ptr clone() const;
};
#endif
