// Revocable
#ifndef __TAG2SUB7__
#define __TAG2SUB7__

#include "subpacket.h"

class Tag2Sub7 : public Subpacket{
    private:
        bool revocable;

    public:
        typedef std::shared_ptr<Tag2Sub7> Ptr;

        Tag2Sub7();
        Tag2Sub7(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        bool get_revocable();

        void set_revocable(const bool r);

        Subpacket::Ptr clone() const;
};
#endif
