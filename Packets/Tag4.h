// One-Pass Signature Packet
#include "packet.h"

#ifndef __TAG4__
#define __TAG4__
class Tag4 : public Packet{
    private:
        uint8_t type;
        uint8_t hash;
        uint8_t pka;
        std::string keyid; // 8 octets
        uint8_t nested;

    public:
        Tag4();
        Tag4(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        Tag4 * clone();

        uint8_t get_type();
        uint8_t get_hash();
        uint8_t get_pka();
        std::string get_keyid();
        uint8_t get_nested();

        void set_type(const uint8_t t);
        void set_hash(const uint8_t h);
        void set_pka(const uint8_t p);
        void set_keyid(const std::string & k);
        void set_nested(const uint8_t n);
};
#endif
