// Trust Packet
#include "packet.h"

#ifndef __TAG12__
#define __TAG12__
class Tag12 : public Packet{
    private:
        std::string trust;

    public:
        Tag12();
        Tag12(std::string & data);
        Tag12(std::ifstream & f);
        void read(std::string & data);
        std::string show();
        std::string raw();

        Tag12 * clone();

        std::string get_trust();

        void set_trust(const std::string & t);
};
#endif
