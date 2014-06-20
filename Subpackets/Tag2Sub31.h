// Signature Target
#ifndef __TAG2SUB31__
#define __TAG2SUB31__

#include "subpacket.h"

class Tag2Sub31 : public Subpacket{
    private:
        uint8_t pka;
        uint8_t ha;
        std::string hash;

    public:
        typedef std::shared_ptr<Tag2Sub31> Ptr;

        Tag2Sub31();
        Tag2Sub31(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        uint8_t get_pka();
        uint8_t get_ha();
        std::string get_hash();

        void set_pka(const uint8_t p);
        void set_ha(const uint8_t h);
        void set_hash(const std::string & h);

        Subpacket::Ptr clone();
};
#endif
