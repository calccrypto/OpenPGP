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

        std::string get_pgp();

        void set_pgp(const std::string & s = "PGP");

        Tag10 * clone();
};
#endif
