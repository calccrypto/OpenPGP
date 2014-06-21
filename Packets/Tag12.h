// Trust Packet
#ifndef __TAG12__
#define __TAG12__

#include "packet.h"

class Tag12 : public Packet{
    private:
        std::string trust;

    public:
        typedef std::shared_ptr<Tag12> Ptr;

        Tag12();
        Tag12(std::string & data);
        Tag12(std::ifstream & f);
        void read(std::string & data);
        std::string show() const;
        std::string raw() const;

        std::string get_trust() const;

        void set_trust(const std::string & t);

        Packet::Ptr clone() const;
};
#endif
