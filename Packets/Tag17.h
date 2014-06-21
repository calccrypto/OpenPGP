// User Attribute Packet
#ifndef __TAG17__
#define __TAG17__

#include "../Subpackets/subpackets.h"
#include "packet.h"

class Tag17 : public ID{
    private:
        uint64_t length;
        uint8_t type;

        // only defined subpacket is 1
        std::vector <Subpacket::Ptr> attributes;

        std::string read_subpacket(std::string & data);
        std::string write_subpacket(uint8_t s_type, std::string data) const;

    public:
        typedef std::shared_ptr<Tag17> Ptr;

        Tag17();
        Tag17(std::string & data);
        ~Tag17();
        void read(std::string & data);
        std::string show() const;
        std::string raw() const;

        std::vector <Subpacket::Ptr> get_attributes() const;
        std::vector <Subpacket::Ptr> get_attributes_clone() const;
        void set_attibutes(const std::vector <Subpacket::Ptr> & a);

        Packet::Ptr clone() const;
};
#endif
