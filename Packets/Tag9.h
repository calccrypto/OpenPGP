// Symmetrically Encrypted Data Packet
#ifndef __TAG9__
#define __TAG9__

#include "packet.h"

class Tag9 : public Packet{
    private:
        std::string encrypted_data;

    public:
        typedef std::shared_ptr<Tag9> Ptr;

        Tag9();
        Tag9(std::string & data);
        void read(std::string & data);
        std::string show() const;
        std::string raw() const;

        Packet::Ptr clone() const;

        std::string get_encrypted_data() const;

        void set_encrypted_data(const std::string & e);
};
#endif
