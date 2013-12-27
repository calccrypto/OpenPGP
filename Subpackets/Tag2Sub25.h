// Primary User ID
#include "subpacket.h"

#ifndef __TAG2SUB25__
#define __TAG2SUB25__
class Tag2Sub25 : public Subpacket{
    private:
        bool primary;

    public:
        Tag2Sub25();
        Tag2Sub25(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        Tag2Sub25 * clone();

        bool get_primary();

        void set_primary(const bool p);
};
#endif
