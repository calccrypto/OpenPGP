// Image Attribute
#include "subpacket.h"

#ifndef __TAG17SUB1__
#define __TAG17SUB1__
class Tag17Sub1 : public Subpacket{
    private:
        uint8_t version;
        uint8_t encoding;
        std::string image;

        static unsigned int count;

    public:
        Tag17Sub1();
        Tag17Sub1(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        Tag17Sub1 * clone();

        std::string get_image();

        void set_image(const std::string & i);
};
#endif
