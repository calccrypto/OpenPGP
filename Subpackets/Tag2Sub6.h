// Regular Expression
#ifndef __TAG2SUB6__
#define __TAG2SUB6__

#include "subpacket.h"

class Tag2Sub6 : public Subpacket{
    private:
        std::string regex;

    public:
        typedef std::shared_ptr<Tag2Sub6> Ptr;

        Tag2Sub6();
        Tag2Sub6(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        std::string get_regex();

        void set_regex(const std::string & r);

        Subpacket::Ptr clone() const;
};
#endif
