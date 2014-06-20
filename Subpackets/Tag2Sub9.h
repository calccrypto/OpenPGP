// Key Experiation Time
#ifndef __TAG2SUB9__
#define __TAG2SUB9__

#include "subpacket.h"

class Tag2Sub9 : public Subpacket{
    private:
        time_t time;

    public:
        typedef std::shared_ptr<Tag2Sub9> Ptr;

        Tag2Sub9();
        Tag2Sub9(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        time_t get_time();

        void set_time(const time_t t);

        Subpacket::Ptr clone();
};
#endif
