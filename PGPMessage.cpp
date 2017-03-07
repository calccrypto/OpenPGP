#include "PGPMessage.h"

// OpenPGP Message :- Encrypted Message | Signed Message | Compressed Message | Literal Message.
bool PGPMessage::OpenPGPMessage(std::list <Token>::iterator it, std::list <Token> & s){
    if ((*it == ENCRYPTEDMESSAGE) || (*it == SIGNEDMESSAGE) || (*it == COMPRESSEDMESSAGE) || (*it == LITERALMESSAGE)){
        *it = OPENPGPMESSAGE;
        return true;
    }
    return false;
}

// Compressed Message :- Compressed Data Packet.
bool PGPMessage::CompressedMessage(std::list <Token>::iterator it, std::list <Token> & s){
    if (*it == CDP){
        *it = COMPRESSEDMESSAGE;
        return true;
    }
    return false;
}

// Literal Message :- Literal Data Packet.
bool PGPMessage::LiteralMessage(std::list <Token>::iterator it, std::list <Token> & s){
    if (*it == LDP){
        *it = LITERALMESSAGE;
        return true;
    }
    return false;
}

// ESK :- Public-Key Encrypted Session Key Packet | Symmetric-Key Encrypted Session Key Packet.
bool PGPMessage::EncryptedSessionKey(std::list <Token>::iterator it, std::list <Token> & s){
    if ((*it == PKESKP) || (*it == SKESKP)){
        *it = ESK;
        return true;
    }
    return false;
}

// ESK Sequence :- ESK | ESK Sequence, ESK.
bool PGPMessage::ESKSequence(std::list <Token>::iterator it, std::list <Token> & s){
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
bool PGPMessage::EncryptedData(std::list <Token>::iterator it, std::list <Token> & s){
    if ((*it == SEDP) || (*it == SEIPDP)){
        *it = ENCRYPTEDDATA;
        return true;
    }
    return false;
}

// Encrypted Message :- Encrypted Data | ESK Sequence, Encrypted Data.
bool PGPMessage::EncryptedMessage(std::list <Token>::iterator it, std::list <Token> & s){
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
bool PGPMessage::OnePassSignedMessage(std::list <Token>::iterator it, std::list <Token> & s){
    std::list <Token>::iterator it2 = it; it2++;
    std::list <Token>::iterator it3 = it2; it3++;
    if ((*it == OPSP) && (*it2 == OPENPGPMESSAGE) && (*it3 == SP)){
        *it = ONEPASSSIGNEDMESSAGE;
        s.erase(it2);
        s.erase(it3);
        return true;
    }
    return false;
}

// Signed Message :- Signature Packet, OpenPGP Message | One-Pass Signed Message.
bool PGPMessage::SignedMessage(std::list <Token>::iterator it, std::list <Token> & s){
    if (*it == ONEPASSSIGNEDMESSAGE){
        *it = SIGNEDMESSAGE;
        return true;
    }
    else if (*it == SP){
        std::list <Token>::iterator it2 = it; it2++;
        if (*it2 == OPENPGPMESSAGE){
            *it = SIGNEDMESSAGE;
            s.erase(it2);
            return true;
        }
    }
    return false;
}

void PGPMessage::decompress() {
    comp.reset();

    // check if compressed
    if ((packets.size() == 1) && (packets[0] -> get_tag() == Packet::ID::Compressed_Data)){
        comp = std::make_shared <Tag8> (packets[0] -> raw());
        const std::string compressed = comp -> get_data();
        comp -> set_data("");
        comp -> set_partial(packets[0] -> get_partial());
        packets.clear();
        read(compressed);
    }
}

PGPMessage::PGPMessage()
    : PGP(),
      comp(nullptr)
{
    type = PGP::Type::MESSAGE;
}

PGPMessage::PGPMessage(const PGP & copy)
    : PGP(copy),
      comp(nullptr)
{
    decompress();
}

PGPMessage::PGPMessage(const PGPMessage & copy)
    : PGP(copy),
      comp(copy.comp)
{
    if (comp){
        comp = std::make_shared <Tag8> (comp -> raw());
    }
}

PGPMessage::PGPMessage(const std::string & data)
    : PGP(data),
      comp(nullptr)
{
    decompress();
}

PGPMessage::PGPMessage(std::istream & stream)
    : PGP(stream),
      comp(nullptr)
{
    decompress();
}

PGPMessage::~PGPMessage(){}

std::string PGPMessage::show(const uint8_t indents, const uint8_t indent_size) const{
    std::stringstream out;
    if (comp){ // if compression was used, add a header
        out << comp -> show(indents, indent_size);
    }
    out << PGP::show(indents + static_cast <bool> (comp), indent_size);
    return out.str();
}

std::string PGPMessage::raw(const uint8_t header) const{
    std::string out = PGP::raw(header);
    if (comp){ // if compression was used; compress data
        comp -> set_data(out);
        out = comp -> write(header);
        comp -> set_data(""); // hold compressed data for as little time as possible
    }
    return out;
}

std::string PGPMessage::write(const uint8_t armor, const uint8_t header) const{
    std::string packet_string = raw(header);

    // put data into a Compressed Data Packet if compression is used
    if (comp){
        comp -> set_data(packet_string);
        packet_string = comp -> write(header);
    }

    if ((armor == 1) || (!armor && !armored)){ // if no armor or if default, and not armored
        return packet_string;                  // return raw data
    }
    std::string out = "-----BEGIN PGP MESSAGE-----\n";
    for(PGP::Armor_Key const & key : keys){
        out += key.first + ": " + key.second + "\n";
    }
    out += "\n";
    return out + format_string(ascii2radix64(packet_string), MAX_LINE_LENGTH) + "=" + ascii2radix64(unhexlify(makehex(crc24(packet_string), 6))) +  "\n-----END PGP MESSAGE-----\n";
}

uint8_t PGPMessage::get_comp() const{
    if (comp){
        return comp -> get_comp();
    }
    return Compression::Algorithm::UNCOMPRESSED;
}

void PGPMessage::set_comp(const uint8_t c){
    comp.reset();   // free comp / set it to nullptr
    if (c){         // if not uncompressed
        comp = std::make_shared <Tag8> ();
        comp -> set_comp(c);
    }
}

bool PGPMessage::match(const PGP & pgp, const PGPMessage::Token & token, std::string & error){
    if (pgp.get_type() != PGP::Type::MESSAGE){
        error = "Error: PGP Type is set to " + PGP::ASCII_Armor_Header[pgp.get_type()];
        return false;
    }

    if (!pgp.get_packets().size()){
        error = "Error: No packets found";
        return false;
    }

    if ((token != PGPMessage::OPENPGPMESSAGE)    &&
        (token != PGPMessage::ENCRYPTEDMESSAGE)  &&
        (token != PGPMessage::SIGNEDMESSAGE)     &&
        (token != PGPMessage::COMPRESSEDMESSAGE) &&
        (token != PGPMessage::LITERALMESSAGE)){
        error = "Error: Invalid Token to match.";
        return false;
    }

    // get list of packets and convert them to Token
    std::list <PGPMessage::Token> s;
    for(Packet::Ptr const & p : pgp.get_packets()){
        PGPMessage::Token push;
        switch(p -> get_tag()){
            case 8:
                push = PGPMessage::CDP;
                break;
            case 11:
                push = PGPMessage::LDP;
                break;
            case 1:
                push = PGPMessage::PKESKP;
                break;
            case 3:
                push = PGPMessage::SKESKP;
                break;
            case 9:
                push = PGPMessage::SEDP;
                break;
            case 18:
                push = PGPMessage::SEIPDP;
                break;
            case 4:
                push = PGPMessage::OPSP;
                break;
            case 2:
                push = PGPMessage::SP;
                break;
            default:
                error = "Error: Non-Message packet found.";
                return false;
                break;
        }
        s.push_back(push);
    }

    while ((*(s.begin()) != token) || (s.size() != 1)){ // while the sentence has not been fully parsed, or has been fully parse but not correctly
        bool reduced = false;
        for(std::list <PGPMessage::Token>::iterator it = s.begin(); it != s.end(); it++){ // for each token
            // make sure the sentence continues to fit at least one of the rules at least once per loop over the sentence
            if (PGPMessage::OpenPGPMessage       (it, s) ||
                PGPMessage::CompressedMessage    (it, s) ||
                PGPMessage::LiteralMessage       (it, s) ||
                PGPMessage::EncryptedSessionKey  (it, s) ||
                PGPMessage::ESKSequence          (it, s) ||
                PGPMessage::EncryptedData        (it, s) ||
                PGPMessage::EncryptedMessage     (it, s) ||
                PGPMessage::OnePassSignedMessage (it, s) ||
                PGPMessage::SignedMessage        (it, s)){
                reduced = true;
                break;
            }
        }
        if (!reduced){
            error = "Error: Failed to reduce tokens.";
            return false;
        }
    }

    return true;
}

bool PGPMessage::match(const PGP & pgp, const PGPMessage::Token & token){
    std::string error;
    return match(pgp, token, error);
}

bool PGPMessage::match(const PGPMessage::Token & token, std::string & error) const{
    return match(*this, token, error);
}

bool PGPMessage::match(const PGPMessage::Token & token) const{
    std::string error;
    return match(*this, token, error);
}

bool PGPMessage::meaningful(const PGP & pgp, std::string & error){
    return match(pgp, PGPMessage::OPENPGPMESSAGE, error);
}

bool PGPMessage::meaningful(const PGP & pgp){
    std::string error;
    return meaningful(pgp, error);
}

bool PGPMessage::meaningful(std::string & error) const{
    return match(PGPMessage::OPENPGPMESSAGE, error);
}

bool PGPMessage::meaningful() const{
    std::string error;
    return meaningful(error);
}

PGP::Ptr PGPMessage::clone() const{
    return std::make_shared <PGPMessage> (*this);
}