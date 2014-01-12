// Features
#ifndef __TAG2SUB30__
#define __TAG2SUB30__

#include "subpacket.h"

class Tag2Sub30 : public Subpacket{
    private:
        char flags;

    public:
        Tag2Sub30();
        Tag2Sub30(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        char get_flags();

        void set_flags(const char f);

        Tag2Sub30 * clone();
};
#endif
