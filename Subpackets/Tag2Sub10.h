// Placeholder for backward compatibility
#include "subpacket.h"

#ifndef __TAG2SUB10__
#define __TAG2SUB10__
class Tag2Sub10 : public Subpacket{
    private:
        std::string stuff;

    public:
        Tag2Sub10();
        Tag2Sub10(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        Tag2Sub10 * clone();

        std::string get_stuff();

        void set_stuff(const std::string & s);
};
#endif
