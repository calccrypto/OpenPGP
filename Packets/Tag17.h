// User Attribute Packet
#include "../Subpackets/subpackets.h"
#include "packet.h"

#ifndef __TAG17__
#define __TAG17__
class Tag17 : public ID{
    private:
        uint64_t length;
        uint8_t type;

        // only defined subpacket is 1
        std::vector <Subpacket *> attributes;

        std::string read_subpacket(std::string & data);
        std::string write_subpacket(uint8_t s_type, std::string data);

    public:
        Tag17();
        Tag17(std::string & data);
        ~Tag17();
        void read(std::string & data);
        std::string show();
        std::string raw();

        Tag17 * clone();

        std::vector <Subpacket *> get_attributes_pointers();
        std::vector <Subpacket *> get_attributes_copy();
        void set_attibutes(std::vector <Subpacket *> a);
};
#endif
