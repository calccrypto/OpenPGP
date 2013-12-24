// Signature Packet
#include "../Subpackets/subpackets.h"
#include "packet.h"
#include "Tag6.h"

#ifndef __TAG2__
#define __TAG2__
class Tag2 : public Packet{
    private:
        // common
        uint8_t type = 0;
        uint8_t pka = 0;
        uint8_t hash = 0;
        std::vector <mpz_class> mpi;
        std::string left16 = "";        // 2 octets

        // version 3 stuff
        uint32_t time = 0;
        std::string keyid = "";

        // version 4 stuff
        std::vector <Subpacket *> hashed_subpackets;
        std::vector <Subpacket *> unhashed_subpackets;

        // Function to read subpackets
        std::string read_subpacket(std::string & data);

    public:
        Tag2();
        Tag2(std::string & data);
        ~Tag2();
        void read(std::string & data);
        std::string show();
        std::string raw();

        Tag2 * clone();

        uint8_t get_type();
        uint8_t get_pka();
        uint8_t get_hash();
        std::string get_left16();// whatever is stored, not calculated
        std::vector <mpz_class> get_mpi();

        // special functions: works differently depending on version
        uint32_t get_time();
        std::string get_keyid();

        std::vector <Subpacket *> get_hashed_subpackets_pointers();
        std::vector <Subpacket *> get_hashed_subpackets_copy();
        std::vector <Subpacket *> get_unhashed_subpackets_pointers();
        std::vector <Subpacket *> get_unhashed_subpackets_copy();
        std::string get_up_to_hashed();             // used for signature trailer
        std::string get_without_unhashed();         // used for signature type 0x50

        void set_pka(uint8_t p);
        void set_type(uint8_t t);
        void set_hash(uint8_t h);
        void set_left16(std::string l);
        void set_mpi(std::vector <mpz_class> m);

        // special functions: works differently depending on version
        void set_time(uint32_t t);
        void set_keyid(std::string k);

        void set_hashed_subpackets(std::vector <Subpacket *> h);
        void set_unhashed_subpackets(std::vector <Subpacket *> u);
};
#endif
