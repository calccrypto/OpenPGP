// Key Flags
#ifndef __TAG2SUB27__
#define __TAG2SUB27__

#include "subpacket.h"

class Tag2Sub27 : public Subpacket{
    private:
        char flags;

    public:
        typedef std::shared_ptr<Tag2Sub27> Ptr;

        Tag2Sub27();
        Tag2Sub27(std::string & data);
        void read(std::string & data);
        std::string show() const;
        std::string raw() const;

        char get_flags() const;

        void set_flags(const char f);

        Subpacket::Ptr clone() const;
};
#endif
