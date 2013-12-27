// Key Server Preferences
#include "subpacket.h"

#ifndef __TAG2SUB23__
#define __TAG2SUB23__
class Tag2Sub23 : public Subpacket{
    private:
        char flags;

    public:
        Tag2Sub23();
        Tag2Sub23(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        Tag2Sub23 * clone();

        char get_flags();

        void set_flags(const char c);
};
#endif
