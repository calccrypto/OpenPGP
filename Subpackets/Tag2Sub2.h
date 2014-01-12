// Signature Creation Time
#ifndef __TAG2SUB2__
#define __TAG2SUB2__

#include "subpacket.h"

class Tag2Sub2 : public Subpacket{
    private:
        time_t time;

    public:
        Tag2Sub2();
        Tag2Sub2(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        time_t get_time();

        void set_time(const time_t t);

        Tag2Sub2 * clone();
};
#endif
