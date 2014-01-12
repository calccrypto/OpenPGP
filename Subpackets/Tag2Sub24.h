// Preferred Key Server
#ifndef __TAG2SUB24__
#define __TAG2SUB24__

#include "subpacket.h"

class Tag2Sub24 : public Subpacket{
    private:
        std::string pks;

    public:
        Tag2Sub24();
        Tag2Sub24(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        std::string get_pks();

        void set_pks(const std::string & p);

        Tag2Sub24 * clone();
};
#endif
