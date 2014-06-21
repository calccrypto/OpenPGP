// Secret-Subkey Packet
#ifndef __TAG7__
#define __TAG7__

#include "Tag5.h"
#include "Tag14.h"

class Tag7 : public Tag5{
    public:
        typedef std::shared_ptr<Tag7> Ptr;

        Tag7();
        Tag7(const Tag7 & tag7);
        Tag7(std::string & data);
        ~Tag7();

        Tag14 get_public_obj() const;      // extract public subkey from private key
        Tag14::Ptr get_public_ptr() const; // extract public subkey from private key into a pointer

        Packet::Ptr clone() const;
        Tag7 & operator=(const Tag7 & copy);
};
#endif
