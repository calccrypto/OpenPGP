// Literal Data Packet
#ifndef __TAG11__
#define __TAG11__

#include <fstream>

#include "packet.h"

class Tag11 : public Packet{
    private:
        uint8_t format;
        std::string filename;
        uint32_t time;
        std::string literal;

    public:
        typedef std::shared_ptr<Tag11> Ptr;

        Tag11();
        Tag11(std::string & data);
        void read(std::string & data);
        std::string show() const;
        std::string raw() const;

        uint8_t get_format() const;
        std::string get_filename() const;
        uint32_t get_time() const;
        std::string get_literal() const;
        bool out(); // write data to file

        void set_format(const uint8_t f);
        void set_filename(const std::string & f);
        void set_time(const uint32_t t);
        void set_literal(const std::string & l);

        Packet::Ptr clone() const;
};
#endif
