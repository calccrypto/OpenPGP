// Preferred Key Server
#ifndef __TAG2SUB24__
#define __TAG2SUB24__

#include "subpacket.h"

class Tag2Sub24 : public Subpacket{
    private:
        std::string pks;

    public:
        typedef std::shared_ptr<Tag2Sub24> Ptr;

        Tag2Sub24();
        Tag2Sub24(std::string & data);
        void read(std::string & data);
        std::string show() const;
        std::string raw() const;

        std::string get_pks() const;

        void set_pks(const std::string & p);

        Subpacket::Ptr clone() const;
};
#endif
