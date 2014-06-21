// Symmetric-Key Encrypted Session Key Packet
#ifndef __TAG3__
#define __TAG3__

#include "../cfb.h"
#include "packet.h"
#include "s2k.h"

class Tag3 : public Packet{
    private:
        uint8_t sym;
        S2K::Ptr s2k;
        std::shared_ptr<std::string> esk; // encrypted session key

    public:
        typedef std::shared_ptr<Tag3> Ptr;

        Tag3();
        Tag3(const Tag3 & tag3);
        Tag3(std::string & data);
        ~Tag3();
        void read(std::string & data);
        std::string show() const;
        std::string raw() const;

        uint8_t get_sym() const;
        S2K::Ptr get_s2k() const;
        S2K::Ptr get_s2k_clone() const;
        std::shared_ptr<std::string> get_esk() const;
        std::shared_ptr<std::string> get_esk_clone() const;
        std::string get_key(std::string pass) const;

        void set_sym(const uint8_t s);
        void set_s2k(S2K::Ptr s);
        void set_esk(std::string * s);
        void set_key(std::string pass, std::string sk = "");

        Packet::Ptr clone() const;
        Tag3 & operator=(const Tag3 & tag3);
};
#endif
