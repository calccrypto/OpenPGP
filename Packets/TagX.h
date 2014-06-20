// partial length packet?
#ifndef __TAGX__
#define __TAGX__

#include "packet.h"

class TagX : public Packet{
    private:
        std::string stream;

    public:
        typedef std::shared_ptr<TagX> Ptr;

        TagX();
        TagX(const std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        std::string get_stream();

        void set_stream(const std::string & data);

        Packet::Ptr clone();
};
#endif
