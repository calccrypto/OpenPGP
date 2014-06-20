// Secret-Key Packet
#ifndef __TAG5__
#define __TAG5__

#include "Tag6.h"
#include "s2k.h"

class Tag5 : public Tag6{
    protected:
        uint8_t s2k_con;
        uint8_t sym;
        S2K::Ptr s2k;
        std::string IV;
        std::string secret;

        void read_s2k(std::string & data);
        std::string show_common();

        Tag5(uint8_t tag);

    public:
        typedef std::shared_ptr<Tag5> Ptr;

        Tag5();
        Tag5(const Tag5 & copy);
        Tag5(std::string & data);
        virtual ~Tag5();
        void read(std::string & data);
        std::string show();
        std::string raw();

        uint8_t get_s2k_con();
        uint8_t get_sym();
        S2K::Ptr get_s2k();
        S2K::Ptr get_s2k_clone();
        std::string get_IV();
        std::string get_secret();

        Tag6 get_public_obj();      // extract public key from private key
        Tag6::Ptr get_public_ptr();    // extract public key from private key into a pointer

        void set_s2k_con(const uint8_t c);
        void set_sym(const uint8_t s);
        void set_s2k(S2K::Ptr s);
        void set_IV(const std::string & iv);
        void set_secret(const std::string & s);

        Packet::Ptr clone() const;
        Tag5 & operator =(const Tag5 & copy);
};
#endif
