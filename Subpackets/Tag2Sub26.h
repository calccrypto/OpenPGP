// Policy URI
#ifndef __TAG2SUB26__
#define __TAG2SUB26__

#include "subpacket.h"

class Tag2Sub26 : public Subpacket{
    private:
        std::string uri;

    public:
        Tag2Sub26();
        Tag2Sub26(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        std::string get_uri();

        void set_uri(const std::string & u);

        Tag2Sub26 * clone();
};
#endif
