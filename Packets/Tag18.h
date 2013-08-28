// Sym. Encrypted and Integrity Protected Data Packet
#include "packet.h"

#ifndef __TAG18__
#define __TAG18__
class Tag18 : public Packet{
    private:
        std::string protected_data;

    public:
        Tag18();
        Tag18(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        Tag18 * clone();

        std::string get_protected_data();

        void set_protected_data(std::string p);
};
#endif
