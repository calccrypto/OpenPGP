// Signature Creation Time
#include "subpacket.h"

#ifndef __TAG2SUB2__
#define __TAG2SUB2__
class Tag2Sub2 : public Subpacket{
    private:
        time_t time;

    public:
        Tag2Sub2();
        Tag2Sub2(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        Tag2Sub2 * clone();

        time_t get_time();

        void set_time(time_t t);
};
#endif
