// User ID Packet
#include "packet.h"

#ifndef __TAG13__
#define __TAG13__
class Tag13 : public ID{
    private:
        std::string name;
        std::string comment;
        std::string email;

    public:
        Tag13();
        Tag13(std::string & data);
        void read(std::string & data);
        std::string show();
        std::string raw();

        Tag13 * clone();

        std::string get_name();
        std::string get_comment();
        std::string get_email();

        void set_name(std::string n);
        void set_comment(std::string c);
        void set_email(std::string e);
};
#endif
