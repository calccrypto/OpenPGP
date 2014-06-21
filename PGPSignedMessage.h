/*
PGPSignedMessage.h
Data structure for PGP message + signature

Copyright (c) 2013 Jason Lee

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifndef __PGP_SIGNED_MESSSAGE_BLOCK__
#define __PGP_SIGNED_MESSSAGE_BLOCK__

#include "PGP.h"

class PGPSignedMessage{
    private:
        uint8_t ASCII_Armor;
        std::vector <std::pair <std::string, std::string> > Armor_Header;
        std::string message;
        PGP key;

    public:
        typedef std::shared_ptr<PGPSignedMessage> Ptr;

        PGPSignedMessage();
        PGPSignedMessage(const PGPSignedMessage & copy);
        PGPSignedMessage(std::string & data);
        PGPSignedMessage(std::ifstream & f);

        void read(std::string & data);
        void read(std::ifstream & file);
        std::string show() const;
        std::string write(uint8_t header = 0) const;

        uint8_t get_ASCII_Armor() const;
        std::vector <std::pair <std::string, std::string> > get_Armor_Header() const;
        std::string get_message() const;
        PGP get_key() const;

        void set_ASCII_Armor(const uint8_t a);
        void set_Armor_Header(const std::vector <std::pair <std::string, std::string> > & a);
        void set_message(const std::string & data);
        void set_key(const PGP & k);

        Ptr clone() const;
        PGPSignedMessage & operator=(const PGPSignedMessage & copy);
};
#endif
