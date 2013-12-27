// Signature Target
#include "subpacket.h"

#ifndef __TAG2SUB31__
#define __TAG2SUB31__
class Tag2Sub31 : public Subpacket{
    private:
        uint8_t pka;
        uint8_t ha;
        std::string hash;

    public:
        Tag2Sub31();
        Tag2Sub31(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        Tag2Sub31 * clone();

        uint8_t get_pka();
        uint8_t get_ha();
        std::string get_hash();

        void set_pka(const uint8_t p);
        void set_ha(const uint8_t h);
        void set_hash(const std::string & h);
};
#endif
