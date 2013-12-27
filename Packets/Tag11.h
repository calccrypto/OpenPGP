// Literal Data Packet
#include "packet.h"

#ifndef __TAG11__
#define __TAG11__
class Tag11 : public Packet{
    private:
        uint8_t format;
        std::string filename;
        uint32_t time;
        std::string literal;

    public:
        Tag11();
        Tag11(std::string & data);
        std::string show();
        void read(std::string & data);
        std::string raw();

        Tag11 * clone();

        uint8_t get_format();
        std::string get_filename();
        uint32_t get_time();
        std::string get_literal();

        void set_format(const uint8_t f);
        void set_filename(const std::string & f);
        void set_time(const uint32_t t);
        void set_literal(const std::string & l);
};
#endif
