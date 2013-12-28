// Secret-Key Packet
#include "Tag6.h"
#include "s2k.h"

#ifndef __TAG5__
#define __TAG5__
class Tag5 : public Tag6{
    protected:
        uint8_t s2k_con;
        uint8_t sym;
        S2K * s2k;
        std::string IV;
        std::string secret;

        S2K * read_s2k(std::string & data);
        std::string show_common();

    public:
        Tag5();
        Tag5(const Tag5 & tag5);
        Tag5(std::string & data);
        ~Tag5();
        void read(std::string & data);
        std::string show();
        std::string raw();

        uint8_t get_s2k_con();
        uint8_t get_sym();
        S2K * get_s2k();
        S2K * get_s2k_clone();
        std::string get_IV();
        std::string get_secret();

        void set_s2k_con(const uint8_t c);
        void set_sym(const uint8_t s);
        void set_s2k(S2K * s);
        void set_IV(const std::string & iv);
        void set_secret(const std::string & s);

        Tag5 * clone();
        Tag5 operator=(const Tag5 & tag5);
};
#endif
