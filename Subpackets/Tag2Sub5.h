// Trust Signature
#include "subpacket.h"

#ifndef __TAG2SUB5__
#define __TAG2SUB5__
class Tag2Sub5 : public Subpacket{
    private:
        uint8_t level;
        uint8_t amount;

    public:
        Tag2Sub5();
        Tag2Sub5(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        Tag2Sub5 * clone();

        uint8_t get_level();
        uint8_t get_amount();

        void set_level(uint8_t l);
        void set_amount(uint8_t a);
};
#endif
