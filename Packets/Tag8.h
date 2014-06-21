// Compressed Data Packet
#ifndef __TAG8__
#define __TAG8__

#include "packet.h"

class Tag8 : public Packet{
    private:
        uint8_t comp;
        std::string compressed_data;

        std::string compress(std::string data);
        std::string decompress(std::string data);

    public:
        typedef std::shared_ptr<Tag8> Ptr;

        Tag8();
        Tag8(std::string & data);
        void read(std::string & data);
        std::string show() const;
        std::string raw() const;

        uint8_t get_comp() const;
        std::string get_data() const;
        std::string get_compressed_data() const;

        void set_comp(const uint8_t c);
        void set_data(const std::string & data);
        void set_compressed_data(const std::string & data);

        Packet::Ptr clone() const;
};
#endif
