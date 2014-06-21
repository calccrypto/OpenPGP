// Policy URI
#ifndef __TAG2SUB26__
#define __TAG2SUB26__

#include "subpacket.h"

class Tag2Sub26 : public Subpacket{
    private:
        std::string uri;

    public:
        typedef std::shared_ptr<Tag2Sub26> Ptr;

        Tag2Sub26();
        Tag2Sub26(std::string & data);
        void read(std::string & data);
        std::string show() const;
        std::string raw() const;

        std::string get_uri() const;

        void set_uri(const std::string & u);

        Subpacket::Ptr clone() const;
};
#endif
