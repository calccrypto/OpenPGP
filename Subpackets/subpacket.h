#ifndef __SUBPACKET__
#define __SUBPACKET__

#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>

#include "../common/includes.h"
#include "../consts.h"
#include "../pgptime.h"

class Subpacket{
    protected:
        uint8_t type = 0;
        unsigned int size = 0; // only used for displaying. recalculated when writing

        std::string write_subpacket(const std::string & data);

    public:
        typedef std::shared_ptr<Subpacket> Ptr;

        virtual ~Subpacket();
        virtual void read(std::string & data) = 0;
        virtual std::string show() = 0;
        virtual std::string raw() = 0; // returns raw subpacket data, with no header
        std::string write();

        uint8_t get_type();
        unsigned int get_size();

        void set_type(uint8_t t);
        void set_size(unsigned int s);

        virtual Ptr clone() = 0;
};
#endif
