// Public-Key Encrypted Session Key Packet
#include "packet.h"

#ifndef __TAG1__
#define __TAG1__
class Tag1 : public Packet{
    private:
        std::string keyid;              // 8 octets
        uint8_t pka;
        std::vector <mpz_class> mpi;      // algorithm specific fields

    public:
        Tag1();
        Tag1(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        Tag1 * clone();

        std::string get_keyid();
        uint8_t get_pka();
        std::vector <mpz_class> get_mpi();

        void set_keyid(std::string k);
        void set_pka(uint8_t p);
        void set_mpi(std::vector <mpz_class> m);
};
#endif
