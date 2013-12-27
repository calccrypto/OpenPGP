// Features
#include "subpacket.h"

#ifndef __TAG2SUB30__
#define __TAG2SUB30__
class Tag2Sub30 : public Subpacket{
    private:
        char flags;

    public:
        Tag2Sub30();
        Tag2Sub30(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        Tag2Sub30 * clone();

        char get_flags();

        void set_flags(const char f);
};
#endif
