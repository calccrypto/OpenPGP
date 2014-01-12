// Preferred Hash Algorithms
#ifndef __TAG2SUB21__
#define __TAG2SUB21__

#include "subpacket.h"

class Tag2Sub21 : public Subpacket{
    private:
        std::string pha;

    public:
        Tag2Sub21();
        Tag2Sub21(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        std::string get_pha();  // returns string of preferred hash algorithms (ex: "\x01\x02\x03")

        void set_pha(const std::string & p);

        Tag2Sub21 * clone();
};
#endif
