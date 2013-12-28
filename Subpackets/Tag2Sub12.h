// Revocation Key
#include "subpacket.h"

#ifndef __TAG2SUB12__
#define __TAG2SUB12__
class Tag2Sub12 : public Subpacket{
    private:
        uint8_t _class;
        uint8_t pka;
        std::string fingerprint; // 20 octets

    public:
        Tag2Sub12();
        Tag2Sub12(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        uint8_t get_class();
        uint8_t get_pka();
        std::string get_fingerprint();

        void set_class(const uint8_t c);
        void set_pka(const uint8_t p);
        void set_fingerprint(const std::string & f);

        Tag2Sub12 * clone();
};
#endif
