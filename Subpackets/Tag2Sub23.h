// Key Server Preferences
#ifndef __TAG2SUB23__
#define __TAG2SUB23__

#include "subpacket.h"

class Tag2Sub23 : public Subpacket{
    private:
        char flags;

    public:
        typedef std::shared_ptr<Tag2Sub23> Ptr;

        Tag2Sub23();
        Tag2Sub23(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        char get_flags();

        void set_flags(const char c);

        Subpacket::Ptr clone() const;
};
#endif
