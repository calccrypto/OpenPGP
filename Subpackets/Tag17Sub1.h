// Image Attribute
#ifndef __TAG17SUB1__
#define __TAG17SUB1__

#include "subpacket.h"

class Tag17Sub1 : public Subpacket{
    private:
        uint8_t version;
        uint8_t encoding;
        std::string image;

        static unsigned int count;

    public:
        typedef std::shared_ptr<Tag17Sub1> Ptr;

        Tag17Sub1();
        Tag17Sub1(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        std::string get_image();

        void set_image(const std::string & i);

        Subpacket::Ptr clone() const;
};
#endif
