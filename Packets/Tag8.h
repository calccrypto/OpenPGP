// Compressed Data Packet
#ifndef __TAG8__
#define __TAG8__

#include "../Compress/Compress.h"
#include "packet.h"

class Tag8 : public Packet{
    private:

        /*
        Compression Algorithm values:
            0 - uncompressed (default)
            1 - ZIP
            2 - ZLIB
            3 - BZip2
        */

        uint8_t comp;
        std::string compressed_data;

        std::string compress(const std::string & data);
        std::string decompress(const std::string & data);

    public:
        typedef std::shared_ptr<Tag8> Ptr;

        Tag8();
        Tag8(std::string & data);
        void read(std::string & data);
        std::string show() const;
        std::string raw() const;

        uint8_t get_comp() const;                           // get compression algorithm
        std::string get_data() const;                       // get uncompressed data
        std::string get_compressed_data() const;            // get compressed data

        void set_comp(const uint8_t c);                     // set compression algorithm
        void set_data(const std::string & data);            // set uncompressed data
        void set_compressed_data(const std::string & data); // set compressed data

        Packet::Ptr clone() const;
};
#endif
