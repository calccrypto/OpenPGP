#include "Message.h"

namespace OpenPGP {

// OpenPGP Message :- Encrypted Message | Signed Message | Compressed Message | Literal Message.
bool Message::OpenMessage(std::list <Token>::iterator it, std::list <Token> & s){
    if ((*it == ENCRYPTEDMESSAGE) || (*it == SIGNEDMESSAGE) || (*it == COMPRESSEDMESSAGE) || (*it == LITERALMESSAGE)){
        *it = OPENMessage;
        return true;
    }
    return false;
}

// Compressed Message :- Compressed Data Packet.
bool Message::CompressedMessage(std::list <Token>::iterator it, std::list <Token> & s){
    if (*it == CDP){
        *it = COMPRESSEDMESSAGE;
        return true;
    }
    return false;
}

// Literal Message :- Literal Data Packet.
bool Message::LiteralMessage(std::list <Token>::iterator it, std::list <Token> & s){
    if (*it == LDP){
        *it = LITERALMESSAGE;
        return true;
    }
    return false;
}

// ESK :- Public-Key Encrypted Session Key Packet | Symmetric-Key Encrypted Session Key Packet.
bool Message::EncryptedSessionKey(std::list <Token>::iterator it, std::list <Token> & s){
    if ((*it == PKESKP) || (*it == SKESKP)){
        *it = ESK;
        return true;
    }
    return false;
}

// ESK Sequence :- ESK | ESK Sequence, ESK.
bool Message::ESKSequence(std::list <Token>::iterator it, std::list <Token> & s){
    if (*it == ESK){
        *it = ESKSEQUENCE;
        return true;
    }
    else if (*it == ESKSEQUENCE){
        std::list <Token>::iterator it2 = it; it2++;
        if (*it2 == ESK){
            s.erase(it2);
            *it = ESKSEQUENCE;
            return true;
        }
    }
    return false;
}

// Encrypted Data :- Symmetrically Encrypted Data Packet | Symmetrically Encrypted Integrity Protected Data Packet
bool Message::EncryptedData(std::list <Token>::iterator it, std::list <Token> & s){
    if ((*it == SEDP) || (*it == SEIPDP)){
        *it = ENCRYPTEDDATA;
        return true;
    }
    return false;
}

// Encrypted Message :- Encrypted Data | ESK Sequence, Encrypted Data.
bool Message::EncryptedMessage(std::list <Token>::iterator it, std::list <Token> & s){
    if (*it == ENCRYPTEDDATA){
        *it = ENCRYPTEDMESSAGE;
        return true;
    }
    else if (*it == ESKSEQUENCE){
        std::list <Token>::iterator it2 = it; it2++;
        if (*it2 == ENCRYPTEDDATA){
            *it = ENCRYPTEDMESSAGE;
            s.erase(it2);
            return true;
        }
    }
    return false;
}

// One-Pass Signed Message :- One-Pass Signature Packet, OpenPGP Message, Corresponding Signature Packet.
bool Message::OnePassSignedMessage(std::list <Token>::iterator it, std::list <Token> & s){
    std::list <Token>::iterator it2 = it; it2++;
    std::list <Token>::iterator it3 = it2; it3++;
    if ((*it == OPSP) && (*it2 == OPENMessage) && (*it3 == SP)){
        *it = ONEPASSSIGNEDMESSAGE;
        s.erase(it2);
        s.erase(it3);
        return true;
    }
    return false;
}

// Signed Message :- Signature Packet, OpenPGP Message | One-Pass Signed Message.
bool Message::SignedMessage(std::list <Token>::iterator it, std::list <Token> & s){
    if (*it == ONEPASSSIGNEDMESSAGE){
        *it = SIGNEDMESSAGE;
        return true;
    }
    else if (*it == SP){
        std::list <Token>::iterator it2 = it; it2++;
        if (*it2 == OPENMessage){
            *it = SIGNEDMESSAGE;
            s.erase(it2);
            return true;
        }
    }
    return false;
}

bool Message::decompress() {
    comp.reset();

    // check if compressed
    if ((packets.size() == 1) && (packets[0] -> get_tag() == Packet::COMPRESSED_DATA)){
        comp = std::static_pointer_cast <Packet::Tag8> (packets[0]);
        const std::string compressed = comp -> get_data();
        comp -> set_data("");
        comp -> set_partial(packets[0] -> get_partial());
        packets.clear();
        read(compressed);

        type = MESSAGE;

        // warn if decompressed packet sequence is not meaningful
        if (!meaningful()){
            // "Error: Decompression failure.\n";
            return false;
        }
    }

    return true;
}

Message::Message()
    : PGP(),
      comp(nullptr)
{
    type = MESSAGE;
}

Message::Message(const PGP & copy)
    : PGP(copy),
      comp(nullptr)
{
    type = MESSAGE;
    if (!decompress()){
        throw std::runtime_error("Error: Failed to decompress data");
    }
}

Message::Message(const Message & copy)
    : PGP(copy),
      comp(copy.comp)
{
    if (comp){
        comp = std::static_pointer_cast <Packet::Tag8> (comp);
    }
}

Message::Message(const std::string & data)
    : PGP(data),
      comp(nullptr)
{
    type = MESSAGE;

    // throw if decompressed packet sequence is not meaningful
    if (!meaningful()){
        throw std::runtime_error("Error: Data does not form a meaningful PGP Message");
    }

    if (!decompress()){
        throw std::runtime_error("Error: Failed to decompress data");
    }
}

Message::Message(std::istream & stream)
    : PGP(stream),
      comp(nullptr)
{
    type = MESSAGE;

    // throw if packet sequence is not meaningful
    if (!meaningful()){
        throw std::runtime_error("Error: Data does not form a meaningful PGP Message");
    }

    if (!decompress()){
        throw std::runtime_error("Error: Failed to decompress data");
    }
}

Message::~Message(){}

std::string Message::show(const std::size_t indents, const std::size_t indent_size) const{
    std::stringstream out;
    if (comp){                  // if compression was used, add a header
        out << comp -> show(indents, indent_size);
    }
    out << PGP::show(indents + static_cast <bool> (comp), indent_size);
    return out.str();
}

std::string Message::raw(const Packet::Tag::Format header) const{
    std::string out = PGP::raw(header);
    if (comp){                  // if compression was used; compress data
        comp -> set_data(out);
        out = comp -> write(header);
        comp -> set_data("");   // hold compressed data for as little time as possible
    }
    return out;
}

std::string Message::write(const PGP::Armored armor, const Packet::Tag::Format header) const{
    std::string packet_string = raw(header);

    // put data into a Compressed Data Packet if compression is used
    if (comp){
        comp -> set_data(packet_string);
        packet_string = comp -> write(header);
    }

    if ((armor == Armored::NO)                   || // no armor
        ((armor == Armored::DEFAULT) && !armored)){ // or use stored value, and stored value is no
        return packet_string;
    }

    std::string out = "-----BEGIN PGP MESSAGE-----\n";
    for(Armor_Key const & key : keys){
        out += key.first + ": " + key.second + "\n";
    }
    out += "\n";
    return out + format_string(ascii2radix64(packet_string), MAX_LINE_LENGTH) + "=" + ascii2radix64(unhexlify(makehex(crc24(packet_string), 6))) +  "\n-----END PGP MESSAGE-----\n";
}

uint8_t Message::get_comp() const{
    if (comp){
        return comp -> get_comp();
    }
    return Compression::ID::UNCOMPRESSED;
}

void Message::set_comp(const uint8_t c){
    comp.reset();   // free comp / set it to nullptr
    if (c){         // if not uncompressed
        comp = std::make_shared <Packet::Tag8> ();
        comp -> set_comp(c);
    }
}

bool Message::match(const PGP & pgp, const Message::Token & token){
    if (pgp.get_type() != MESSAGE){
        // "Error: ASCII Armor type is not MESSAGE.\n";
        return false;
    }

    if (!pgp.get_packets().size()){
        // "Error: No packets found.\n";
        return false;
    }

    if ((token != OPENMessage)       &&
        (token != ENCRYPTEDMESSAGE)     &&
        (token != SIGNEDMESSAGE)        &&
        // (token != ONEPASSSIGNEDMESSAGE) &&  // special case of Signed Message
        (token != COMPRESSEDMESSAGE)    &&
        (token != LITERALMESSAGE)){
        // "Error: Invalid Token to match.\n";
        return false;
    }

    // get list of packets and convert them to Token
    std::list <Token> s;
    for(Packet::Tag::Ptr const & p : pgp.get_packets()){
        Token push;
        if (p -> get_tag() == Packet::COMPRESSED_DATA){
            push = CDP;
        }
        else if (p -> get_tag() == Packet::LITERAL_DATA){
            push = LDP;
        }
        else if (p -> get_tag() == Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY){
            push = PKESKP;
        }
        else if (p -> get_tag() == Packet::SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY){
            push = SKESKP;
        }
        else if (p -> get_tag() == Packet::SYMMETRICALLY_ENCRYPTED_DATA){
            push = SEDP;
        }
        else if (p -> get_tag() == Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA){
            push = SEIPDP;
        }
        else if (p -> get_tag() == Packet::ONE_PASS_SIGNATURE){
            push = OPSP;
        }
        else if (p -> get_tag() == Packet::SIGNATURE){
            push = SP;
        }
        else{
            // "Error: Non-Message packet found.\n";
            return false;
        }

        s.push_back(push);
    }

    while ((*(s.begin()) != token) || (s.size() != 1)){ // while the sentence has not been fully parsed, or has been fully parse but not correctly
        bool reduced = false;
        for(std::list <Token>::iterator it = s.begin(); it != s.end(); it++){ // for each token
            // make sure the sentence continues to fit at least one of the rules at least once per loop over the sentence
            if (OpenMessage       (it, s) ||
                CompressedMessage    (it, s) ||
                LiteralMessage       (it, s) ||
                EncryptedSessionKey  (it, s) ||
                ESKSequence          (it, s) ||
                EncryptedData        (it, s) ||
                EncryptedMessage     (it, s) ||
                OnePassSignedMessage (it, s) ||
                SignedMessage        (it, s)){
                reduced = true;
                break;
            }
        }
        if (!reduced){
            // "Error: Failed to reduce tokens.\n";
            return false;
        }
    }

    return true;
}

bool Message::match(const Message::Token & token) const{
    return match(*this, token);
}

bool Message::meaningful(const PGP & pgp){
    return match(pgp, OPENMessage);
}

bool Message::meaningful() const{
    return match(OPENMessage);
}

PGP::Ptr Message::clone() const{
    return std::make_shared <Message> (*this);
}

}
