// Compressed Data Packet
#include "../Compression/pgpcompress.h"
#include "packet.h"

#ifndef __TAG8__
#define __TAG8__
class Tag8 : public Packet{
    private:
        uint8_t comp;
        std::string compressed_data;

        std::string compress(std::string data);
        std::string decompress(std::string data);

    public:
        Tag8();
        Tag8(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        uint8_t get_comp();
        std::string get_data();
        std::string get_compressed_data();

        void set_comp(const uint8_t c);
        void set_data(const std::string & data);
        void set_compressed_data(const std::string & data);

        Tag8 * clone();
};
#endif
