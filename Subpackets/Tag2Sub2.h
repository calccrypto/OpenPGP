// Signature Creation Time
#ifndef __TAG2SUB2__
#define __TAG2SUB2__

#include "subpacket.h"

class Tag2Sub2 : public Subpacket{
    private:
        time_t time;

    public:
        typedef std::shared_ptr<Tag2Sub2> Ptr;

        Tag2Sub2();
        Tag2Sub2(std::string & data);
        void read(std::string & data);
        std::string show() const;
        std::string raw() const;

        time_t get_time() const;

        void set_time(const time_t t);

        Subpacket::Ptr clone() const;
};
#endif
