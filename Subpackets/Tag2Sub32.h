// Embedded Signature
#ifndef __TAG2SUB32__
#define __TAG2SUB32__

#include "../Packets/Tag2.h"
#include "subpacket.h"

class Tag2Sub32 : public Subpacket{
    private:
        Tag2::Ptr embedded;

    public:
        typedef std::shared_ptr<Tag2Sub32> Ptr;

        Tag2Sub32();
        Tag2Sub32(const Tag2Sub32 & tag2sub32);
        Tag2Sub32(std::string & data);
        ~Tag2Sub32();
        void read(std::string & data);
        std::string show();
        std::string raw();

        Tag2::Ptr get_embedded();

        void set_embedded(Tag2::Ptr e);

        Subpacket::Ptr clone() const;
        Tag2Sub32 & operator=(const Tag2Sub32 & copy);
};
#endif
