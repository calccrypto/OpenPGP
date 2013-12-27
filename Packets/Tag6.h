// Public-Key Packet
#include "packet.h"

#ifndef __TAG6__
#define __TAG6__
class Tag6 : public Key{
    protected:
        time_t time;
        uint8_t pka;
        std::vector <mpz_class> mpi;

        // version 3
        uint32_t expire;

        void read_tag6(std::string & data);
        std::string show_tag6();
        std::string raw_tag6();

    public:
        Tag6();
        Tag6(std::string & data);
        virtual void read(std::string & data);
        virtual std::string show();
        virtual std::string raw();

        Tag6 * clone();

        time_t get_time();
        uint8_t get_pka();
        std::vector <mpz_class> get_mpi();

        void set_time(const time_t t);
        void set_pka(const uint8_t p);
        void set_mpi(const std::vector <mpz_class> & m);

        std::string get_fingerprint();
        std::string get_keyid();
};
#endif
