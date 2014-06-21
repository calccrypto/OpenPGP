// Features
#ifndef __TAG2SUB30__
#define __TAG2SUB30__

#include "subpacket.h"

class Tag2Sub30 : public Subpacket{
    private:
        char flags;

    public:
        typedef std::shared_ptr<Tag2Sub30> Ptr;

        Tag2Sub30();
        Tag2Sub30(std::string & data);
        void read(std::string & data);
        std::string show() const;
        std::string raw() const;

        char get_flags() const;

        void set_flags(const char f);

        Subpacket::Ptr clone() const;
};
#endif
