// Placeholder for backward compatibility
#ifndef __TAG2SUB10__
#define __TAG2SUB10__

#include "subpacket.h"

class Tag2Sub10 : public Subpacket{
    private:
        std::string stuff;

    public:
        Tag2Sub10();
        Tag2Sub10(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        std::string get_stuff();

        void set_stuff(const std::string & s);

        Tag2Sub10 * clone();
};
#endif
