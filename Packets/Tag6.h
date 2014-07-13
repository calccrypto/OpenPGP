// Public-Key Packet
#ifndef __TAG6__
#define __TAG6__

#include "../Hashes/Hashes.h"
#include "packet.h"

class Tag6 : public Key{
    protected:
        time_t time;
        uint8_t pka;
        std::vector <PGPMPI> mpi;

        // version 3
        uint32_t expire;

        void read_tag6(std::string & data);
        std::string show_tag6() const;
        std::string raw_tag6() const;

        Tag6(uint8_t tag);

    public:
        typedef std::shared_ptr<Tag6> Ptr;

        Tag6();
        Tag6(std::string & data);
        virtual ~Tag6();

        virtual void read(std::string & data);
        virtual std::string show() const;
        virtual std::string raw() const;

        time_t get_time() const;
        uint8_t get_pka() const;
        std::vector <PGPMPI> get_mpi() const;

        void set_time(const time_t t);
        void set_pka(const uint8_t p);
        void set_mpi(const std::vector <PGPMPI> & m);

        std::string get_fingerprint() const;                      // binary
        std::string get_keyid() const;                            // binary

        Packet::Ptr clone() const;

        Tag6(const Tag6 & copy);
        Tag6& operator=(const Tag6 & copy);

};
#endif
