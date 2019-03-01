#ifndef __EXTRACT_DECRYPTED__
#define __EXTRACT_DECRYPTED__

#include "Message.h"

std::string extract_decrypted(const OpenPGP::Message & decrypted) {
    std::string message = "";
    for(OpenPGP::Packet::Tag::Ptr const & p : decrypted.get_packets()){
        switch (p -> get_tag()) {
            case OpenPGP::Packet::COMPRESSED_DATA:
                message += extract_decrypted(std::static_pointer_cast <OpenPGP::Packet::Tag8> (p) -> get_body());
                break;
            case OpenPGP::Packet::LITERAL_DATA:
                message += std::static_pointer_cast <OpenPGP::Packet::Tag11> (p) -> out(false);
                break;
            default:
                continue;
        }

        message += "\n";
    }

    if (message.size()) {
        message.pop_back();
    }

    return message;
}

#endif
