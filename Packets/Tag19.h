// Modification Detection Code Packet
#include "packet.h"

#ifndef __TAG19__
#define __TAG19__
class Tag19 : public Packet{
    private:
        std::string hash;

    public:
        Tag19();
        Tag19(std::string & data);
        std::string show();
        void read(std::string & data);
        std::string raw();

        Tag19 * clone();

        std::string get_hash();

        void set_hash(const std::string & h);
};
#endif
