// Signature Expiration Time
#ifndef __TAG2SUB3__
#define __TAG2SUB3__

#include "subpacket.h"

class Tag2Sub3 : public Subpacket{
    private:
        time_t time;

    public:
        typedef std::shared_ptr<Tag2Sub3> Ptr;

        Tag2Sub3();
        Tag2Sub3(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        time_t get_time();

        void set_time(const time_t t);

        Subpacket::Ptr clone() const;
};
#endif
