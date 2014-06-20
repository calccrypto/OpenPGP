// Public-Key Encrypted Session Key Packet
#ifndef __TAG1__
#define __TAG1__

#include "packet.h"
class Tag1 : public Packet{
    private:
        std::string keyid;                // 8 octets
        uint8_t pka;
        std::vector <mpz_class> mpi;      // algorithm specific fields

    public:
        typedef std::shared_ptr<Tag1> Ptr;

        Tag1();
        Tag1(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        std::string get_keyid();
        uint8_t get_pka();
        std::vector <mpz_class> get_mpi();

        void set_keyid(const std::string & k);
        void set_pka(const uint8_t p);
        void set_mpi(const std::vector <mpz_class> & m);

        Packet::Ptr clone();
};
#endif
