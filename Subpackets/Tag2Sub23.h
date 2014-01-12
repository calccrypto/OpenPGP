// Key Server Preferences
#ifndef __TAG2SUB23__
#define __TAG2SUB23__

#include "subpacket.h"

class Tag2Sub23 : public Subpacket{
    private:
        char flags;

    public:
        Tag2Sub23();
        Tag2Sub23(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        char get_flags();

        void set_flags(const char c);

        Tag2Sub23 * clone();
};
#endif
