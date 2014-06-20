// Primary User ID
#ifndef __TAG2SUB25__
#define __TAG2SUB25__

#include "subpacket.h"

class Tag2Sub25 : public Subpacket{
    private:
        bool primary;

    public:
        typedef std::shared_ptr<Tag2Sub25> Ptr;

        Tag2Sub25();
        Tag2Sub25(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        bool get_primary();

        void set_primary(const bool p);

        Subpacket::Ptr clone();
};
#endif
