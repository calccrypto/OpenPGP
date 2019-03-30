/*
Sub1.h
Image Attribute

Copyright (c) 2013 - 2019 Jason Lee @ calccrypto at gmail.com

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

#ifndef __TAG17_SUB1__
#define __TAG17_SUB1__

#include "Subpacket.h"

namespace OpenPGP {
    namespace Subpacket {
        namespace Tag17 {

            // 5.12.1. The Image Attribute Subpacket
            //    The Image Attribute Subpacket is used to encode an image, presumably
            //    (but not required to be) that of the key owner.
            //
            //    The Image Attribute Subpacket begins with an image header. The first
            //    two octets of the image header contain the length of the image
            //    header. Note that unlike other multi-octet numerical values in this
            //    document, due to a historical accident this value is encoded as a
            //    little-endian number. The image header length is followed by a
            //    single octet for the image header version. The only currently
            //    defined version of the image header is 1, which is a 16-octet image
            //    header. The first three octets of a version 1 image header are thus
            //    0x10, 0x00, 0x01.
            //
            //    The fourth octet of a version 1 image header designates the encoding
            //    format of the image. The only currently defined encoding format is
            //    the value 1 to indicate JPEG. Image format types 100 through 110 are
            //    reserved for private or experimental use. The rest of the version 1
            //    image header is made up of 12 reserved octets, all of which MUST be
            //    set to 0.
            //
            //    The rest of the image Subpacket contains the image itself. As the
            //    only currently defined image type is JPEG, the image is encoded in
            //    the JPEG File Interchange Format (JFIF), a standard file format for
            //    JPEG images [JFIF].
            //
            //    An implementation MAY try to determine the type of an image by
            //    examination of the image data if it is unable to handle a particular
            //    version of the image header or if a specified encoding format value
            //    is not recognized.

            namespace Image_Attributes {
                constexpr uint8_t JPEG = 1;

                const std::map <uint8_t, std::string> NAME = {
                    std::make_pair(JPEG, "JPEG"),
                    std::make_pair(100,  "Reserved for private/experimental use"),
                    std::make_pair(101,  "Reserved for private/experimental use"),
                    std::make_pair(102,  "Reserved for private/experimental use"),
                    std::make_pair(103,  "Reserved for private/experimental use"),
                    std::make_pair(104,  "Reserved for private/experimental use"),
                    std::make_pair(105,  "Reserved for private/experimental use"),
                    std::make_pair(106,  "Reserved for private/experimental use"),
                    std::make_pair(107,  "Reserved for private/experimental use"),
                    std::make_pair(108,  "Reserved for private/experimental use"),
                    std::make_pair(109,  "Reserved for private/experimental use"),
                    std::make_pair(110,  "Reserved for private/experimental use"),
                };
            }

            class Sub1 : public Sub {
                private:
                    uint8_t version;
                    uint8_t encoding;
                    std::string image;

                    static unsigned int count;  // count of all images found; incremented by creating new instances of Sub1
                    unsigned int current;       // which image this instance is

                    void actual_read(const std::string & data);
                    void show_contents(HumanReadable & hr) const;
                    Status actual_valid(const bool check_mpi) const;

                public:
                    typedef std::shared_ptr <Sub1> Ptr;

                    Sub1();
                    Sub1(const std::string & data);
                    std::string raw() const;

                    uint8_t get_version() const;
                    uint8_t get_encoding() const;
                    std::string get_image() const;

                    void set_version(const uint8_t & v);
                    void set_encoding(const uint8_t & enc);
                    void set_image(const std::string & i);

                    Sub::Ptr clone() const;
            };
        }
    }
}

#endif
