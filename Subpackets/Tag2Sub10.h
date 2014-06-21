// Placeholder for backward compatibility
#ifndef __TAG2SUB10__
#define __TAG2SUB10__

#include "subpacket.h"

class Tag2Sub10 : public Subpacket{
    private:
        std::string stuff;

    public:
        typedef std::shared_ptr<Tag2Sub10> Ptr;

        Tag2Sub10();
        Tag2Sub10(std::string & data);
        void read(std::string & data);
        std::string show() const;
        std::string raw() const;

        std::string get_stuff() const;

        void set_stuff(const std::string & s);

        Subpacket::Ptr clone() const;
};
#endif
