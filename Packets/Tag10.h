// Marker Packet
#include "packet.h"

#ifndef __TAG10__
#define __TAG10__
class Tag10 : public Packet{
    private:
        std::string pgp; // "PGP"

    public:
        Tag10();
        Tag10(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        Tag10 * clone();

        std::string get_pgp();

        void set_pgp(std::string s);
};
#endif
