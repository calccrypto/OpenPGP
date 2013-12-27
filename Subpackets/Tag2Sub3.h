// Signature Expiration Time
#include "subpacket.h"

#ifndef __TAG2SUB3__
#define __TAG2SUB3__
class Tag2Sub3 : public Subpacket{
    private:
        time_t time;

    public:
        Tag2Sub3();
        Tag2Sub3(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        Tag2Sub3 * clone();

        time_t get_time();

        void set_time(const time_t t);
};
#endif
