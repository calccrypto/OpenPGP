#include "subpacket.h"

#ifndef __TAG2SUB7__
#define __TAG2SUB7__
// Revocable
class Tag2Sub7 : public Subpacket{
    private:
        bool revocable;

    public:
        Tag2Sub7();
        Tag2Sub7(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        Tag2Sub7 * clone();

        bool get_revocable();

        void set_revocable(const bool r);
};
#endif
