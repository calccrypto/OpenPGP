// Revocation Key
#ifndef __TAG2SUB12__
#define __TAG2SUB12__

#include "subpacket.h"

class Tag2Sub12 : public Subpacket{
    private:
        uint8_t _class;
        uint8_t pka;
        std::string fingerprint; // 20 octets

    public:
        typedef std::shared_ptr<Tag2Sub12> Ptr;

        Tag2Sub12();
        Tag2Sub12(std::string & data);
        void read(std::string & data);
        std::string show() const;
        std::string raw() const;

        uint8_t get_class() const;
        uint8_t get_pka() const;
        std::string get_fingerprint() const;

        void set_class(const uint8_t c);
        void set_pka(const uint8_t p);
        void set_fingerprint(const std::string & f);

        Subpacket::Ptr clone() const;
};
#endif
