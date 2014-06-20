// Exportable Certification
#ifndef __TAG2SUB4__
#define __TAG2SUB4__

#include "subpacket.h"

class Tag2Sub4 : public Subpacket{
    private:
        bool exportable;

    public:
        typedef std::shared_ptr<Tag2Sub4> Ptr;

        Tag2Sub4();
        Tag2Sub4(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        bool get_exportable();

        void set_exportable(const bool e);

        Subpacket::Ptr clone() const;
};
#endif
