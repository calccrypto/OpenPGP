#include "subpacket.h"

#ifndef __TAG2SUB29__
#define __TAG2SUB29__
// Reason for Revocation
class Tag2Sub29 : public Subpacket{
    private:
        uint8_t code;
        std::string reason;

    public:
        Tag2Sub29();
        Tag2Sub29(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        Tag2Sub29 * clone();

        uint8_t get_code();
        std::string get_reason();

        void set_code(uint8_t c);
        void set_reason(std::string r);
};
#endif
