// Regular Expression
#include "subpacket.h"

#ifndef __TAG2SUB6__
#define __TAG2SUB6__
class Tag2Sub6 : public Subpacket{
    private:
        std::string regex;

    public:
        Tag2Sub6();
        Tag2Sub6(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        std::string get_regex();

        void set_regex(const std::string & r);

        Tag2Sub6 * clone();
};
#endif
