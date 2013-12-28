// Key Experiation Time
#include "subpacket.h"

#ifndef __TAG2SUB9__
#define __TAG2SUB9__
class Tag2Sub9 : public Subpacket{
    private:
        time_t time;

    public:
        Tag2Sub9();
        Tag2Sub9(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        time_t get_time();

        void set_time(const time_t t);

        Tag2Sub9 * clone();
};
#endif
