// Preferred Compression Algorithms
#ifndef __TAG2SUB22__
#define __TAG2SUB22__

#include "subpacket.h"

class Tag2Sub22 : public Subpacket{
    private:
        std::string pca;

    public:
        typedef std::shared_ptr<Tag2Sub22> Ptr;

        Tag2Sub22();
        Tag2Sub22(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        std::string get_pca();

        void set_pca(const std::string & c);

        Subpacket::Ptr clone() const;
};
#endif
