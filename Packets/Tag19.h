// Modification Detection Code Packet
#ifndef __TAG19__
#define __TAG19__

#include "packet.h"

class Tag19 : public Packet{
    private:
        std::string hash;

    public:
        typedef std::shared_ptr<Tag19> Ptr;

        Tag19();
        Tag19(std::string & data);
        std::string show();
        void read(std::string & data);
        std::string raw();

        std::string get_hash();

        void set_hash(const std::string & h);

        Packet::Ptr clone();
};
#endif
