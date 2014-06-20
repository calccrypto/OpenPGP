// Signature Packet
#include "../Subpackets/subpackets.h"

#ifndef __TAG2__
#define __TAG2__

#include "packet.h"

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
        std::vector <Subpacket::Ptr> hashed_subpackets;
        std::vector <Subpacket::Ptr> unhashed_subpackets;

        // Function to read subpacket headers
        std::string read_subpacket(std::string & data);

        // Function to parse all subpackets
        std::vector <Subpacket::Ptr> read_subpackets(std::string & data);

    public:
        typedef std::shared_ptr<Tag2> Ptr;

        Tag2();
        Tag2(const Tag2 & tag2);
        Tag2(std::string & data);
        ~Tag2();
        void read(std::string & data);
        std::string show();
        std::string raw();

        uint8_t get_type();
        uint8_t get_pka();
        uint8_t get_hash();
        std::string get_left16();// whatever is stored, not calculated
        std::vector <mpz_class> get_mpi();

        // special functions: works differently depending on version
        uint32_t get_time();
        std::string get_keyid();

        std::vector <Subpacket::Ptr> get_hashed_subpackets();
        std::vector <Subpacket::Ptr> get_hashed_subpackets_clone();
        std::vector <Subpacket::Ptr> get_unhashed_subpackets();
        std::vector <Subpacket::Ptr> get_unhashed_subpackets_clone();
        std::string get_up_to_hashed();             // used for signature trailer
        std::string get_without_unhashed();         // used for signature type 0x50

        void set_pka(const uint8_t p);
        void set_type(const uint8_t t);
        void set_hash(const uint8_t h);
        void set_left16(const std::string & l);
        void set_mpi(const std::vector <mpz_class> & m);

        // special functions: works differently depending on version
        void set_time(const uint32_t t);
        void set_keyid(const std::string & k);

        // Do not use pointers from get_*_pointers(). Use pointers from get_*_clone()
        void set_hashed_subpackets(const std::vector <Subpacket::Ptr> & h);
        void set_unhashed_subpackets(const std::vector <Subpacket::Ptr> & u);

        Packet::Ptr clone();
        Tag2 operator=(const Tag2 & tag2);
};
#endif
