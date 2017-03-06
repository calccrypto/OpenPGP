#include "PGP.h"

const PGP::Type_t PGP::Type::UNKNOWN           = 0; // Default value
const PGP::Type_t PGP::Type::MESSAGE           = 1; // Used for signed, encrypted, or compressed files.
const PGP::Type_t PGP::Type::PUBLIC_KEY_BLOCK  = 2; // Used for armoring public keys.
const PGP::Type_t PGP::Type::PRIVATE_KEY_BLOCK = 3; // Used for armoring private keys.
const PGP::Type_t PGP::Type::MESSAGE_PART_XY   = 4; // Used for multi-part messages, where the armor is split amongst Y parts, and this is the Xth part out of Y.
const PGP::Type_t PGP::Type::MESSAGE_PART_X    = 5; // Used for multi-part messages, where this is the Xth part of an unspecified number of parts. Requires the MESSAGE-ID Armor Header to be used.
const PGP::Type_t PGP::Type::SIGNATURE         = 6; // Used for detached signatures, OpenPGP/MIME signatures, and cleartext signatures. Note that PGP 2.x uses BEGIN PGP MESSAGE for detached signatures.
const PGP::Type_t PGP::Type::SIGNED_MESSAGE    = 7; // Used for cleartext signatures; header not really part of RFC 4880.
const PGP::Type_t PGP::Type::KEY_BLOCK         = 8; // Used to check if type is PUBLIC_KEY_BLOCK or PRIVATE_KEY_BLOCK

const std::string PGP::ASCII_Armor_Header[] = {
   "",                  // unknown type
   "MESSAGE",           // Used for signed, encrypted, or compressed files.
   "PUBLIC KEY BLOCK",  // Used for armoring public keys.
   "PRIVATE KEY BLOCK", // Used for armoring private keys.
   "MESSAGE, PART X/Y", // Used for multi-part messages, where the armor is split amongst Y parts, and this is the Xth part out of Y.
   "MESSAGE, PART X",   // Used for multi-part messages, where this is the Xth part of an unspecified number of parts. Requires the MESSAGE-ID Armor Header to be used.
   "SIGNATURE",         // Used for detached signatures, OpenPGP/MIME signatures, and cleartext signatures. Note that PGP 2.x uses BEGIN PGP MESSAGE for detached signatures.
   "SIGNED MESSAGE",    // Used for cleartext signatures; header not really part of RFC 4880.
};

// ASCII descriptor of OpenPGP packet
const std::string PGP::ASCII_Armor_Key[] = {
    "Version",          // which states the OpenPGP implementation and version used to encode the message.

    "Comment",          // a user-defined comment. OpenPGP defines all text to be in UTF-8. A comment may be any UTF-8 string. However, the whole point of armoring is to provide seven-bit-clean data.
                        // Consequently, if a comment has characters that are outside the US-ASCII range of UTF, they may very well not survive transport.

    "MessageID",        // a 32-character string of printable characters. The string must be the same for all parts of a multi-part message that uses the "PART X" Armor Header. MessageID strings should be
                        // unique enough that the recipient of the mail can associate all the parts of a message with each other. A good checksum or cryptographic hash function is sufficient.
                        // The MessageID SHOULD NOT appear unless it is in a multi-part message. If it appears at all, it MUST be computed from the finished (encrypted, signed, etc.) message in a deterministic
                        // fashion, rather than contain a purely random value. This is to allow the legitimate recipient to determine that the MessageID cannot serve as a covert means of leaking cryptographic key
                        // information.

    "Hash",             // a comma-separated list of hash algorithms used in this message. This is used only in cleartext signed messages.

    "Charset",          // a description of the character set that the plaintext is in. Please note that OpenPGP defines text to be in UTF-8. An implementation will get best results by translating into and out
};

unsigned int PGP::partialBodyLen(uint8_t first_octet) const{
    return 1 << (first_octet & 0x1f);
}

uint8_t PGP::read_packet_header(const std::string & data, std::string::size_type & pos, std::string::size_type & length, uint8_t & tag, bool & format, uint8_t & partial) const{
    uint8_t ctb = data[pos];                                        // Name "ctb" came from Version 2 [RFC 1991]
    format = ctb & 0x40;                                            // get packet length type (OLD = false; NEW = true)
    length = 0;
    tag = 0;                                                        // default value (error)

    if (!partial){                                                  // if partial continue packets have not been found
        if (!(ctb & 0x80)){
           throw std::runtime_error("Error: First bit of packet header MUST be 1.");
        }

        if (!format){                                               // Old length type RFC4880 sec 4.2.1
            tag = (ctb >> 2) & 15;                                  // get tag value
            if ((ctb & 3) == 0){                                    // 0 - The packet has a one-octet length. The header is 2 octets long.
                length = static_cast <uint8_t> (data[pos + 1]);
                pos += 2;
            }
            else if ((ctb & 3) == 1){                               // 1 - The packet has a two-octet length. The header is 3 octets long.
                length = toint(data.substr(pos + 1, 2), 256);
                pos += 3;
            }
            else if ((ctb & 3) == 2){                               // 2 - The packet has a four-octet length. The header is 5 octets long.
                length = toint(data.substr(pos + 2, 4), 256);
                pos += 5;
            }
            else if ((ctb & 3) == 3){                               // The packet is of indeterminate length. The header is 1 octet long, and the implementation must determine how long the packet is.
                partial = 1;                                        // set to partial start
                length = data.size() - pos - 1;                     // header is one octet long
                pos += 1;
            }
        }
        else{                                                       // New length type RFC4880 sec 4.2.2
            tag = ctb & 63;                                         // get tag value
            const uint8_t first_octet = static_cast <unsigned char> (data[pos + 1]);
            if (first_octet < 192){                                 // 0 - 191; A one-octet Body Length header encodes packet lengths of up to 191 octets.
                length = first_octet;
                pos += 2;
            }
            else if ((192 <= first_octet) & (first_octet < 223)){   // 192 - 8383; A two-octet Body Length header encodes packet lengths of 192 to 8383 octets.
                length = toint(data.substr(pos + 1, 2), 256) - (192 << 8) + 192;
                pos += 3;
            }
            else if (first_octet == 255){                           // 8384 - 4294967295; A five-octet Body Length header encodes packet lengths of up to 4,294,967,295 (0xFFFFFFFF) octets in length.
                length = toint(data.substr(pos + 2, 4), 256);
                pos += 5;
            }
            else if (224 <= first_octet){                           // unknown; When the length of the packet body is not known in advance by the issuer, Partial Body Length headers encode a packet of indeterminate length, effectively making it a stream.
                partial = 1;                                        // set to partial start
                length = partialBodyLen(first_octet);
                pos += 1;
            }
        }
    }
    else{ // partial continue
        partial = 2;                                                // set to partial continue
        tag = 254;                                                  // set to partial body tag

        if (!format){                                               // Old length type RFC4880 sec 4.2.1
            length = data.size() - pos - 1;                         // header is one octet long
        }
        else{                                                       // New length type RFC4880 sec 4.2.2
            length = partialBodyLen(data[pos + 1]);
        }

        pos += 1;                                                   // header is one octet long
    }

    return tag;
}

Packet::Ptr PGP::read_packet_raw(const bool format, const uint8_t tag, uint8_t & partial, const std::string & data, std::string::size_type & pos, const std::string::size_type & length) const{
    Packet::Ptr out;
    if (partial > 1){
        out = std::make_shared <Partial> ();
    }
    else{
        switch (tag){
            case 0:
                throw std::runtime_error("Error: Tag number MUST NOT be 0.");
                break;
            case 1:
                out = std::make_shared <Tag1> ();
                break;
            case 2:
                out = std::make_shared <Tag2> ();
                break;
            case 3:
                out = std::make_shared <Tag3> ();
                break;
            case 4:
                out = std::make_shared <Tag4> ();
                break;
            case 5:
                out = std::make_shared <Tag5> ();
                break;
            case 6:
                out = std::make_shared <Tag6> ();
                break;
            case 7:
                out = std::make_shared <Tag7> ();
                break;
            case 8:
                out = std::make_shared <Tag8> ();
                break;
            case 9:
                out = std::make_shared <Tag9> ();
                break;
            case 10:
                out = std::make_shared <Tag10> ();
                break;
            case 11:
                out = std::make_shared <Tag11> ();
                break;
            case 12:
                out = std::make_shared <Tag12> ();
                break;
            case 13:
                out = std::make_shared <Tag13> ();
                break;
            case 14:
                out = std::make_shared <Tag14> ();
                break;
            case 17:
                out = std::make_shared <Tag17> ();
                break;
            case 18:
                out = std::make_shared <Tag18> ();
                break;
            case 19:
                out = std::make_shared <Tag19> ();
                break;
            case 60:
                out = std::make_shared <Tag60> ();
                break;
            case 61:
                out = std::make_shared <Tag61> ();
                break;
            case 62:
                out = std::make_shared <Tag62> ();
                break;
            case 63:
                out = std::make_shared <Tag63> ();
                break;
            default:
                throw std::runtime_error("Error: Tag not defined.");
                break;
        }
    }

    // fill in data
    out -> set_tag(tag);
    out -> set_format(format);
    out -> set_partial(partial);
    out -> set_size(length);
    out -> read(data.substr(pos, length));

    // update position to end of packet
    pos += length;

    if (partial){
        partial = 2;
    }

    return out;
}

Packet::Ptr PGP::read_packet(const std::string & data, std::string::size_type & pos, uint8_t & partial) const{
    if (pos >= data.size()){
        return nullptr;
    }

    // set in read_packet_header, used in read_packet_raw
    bool format;
    uint8_t tag = 0;
    std::string::size_type length;

    read_packet_header(data, pos, length, tag, format, partial);    // pos is moved past header
    return read_packet_raw(format, tag, partial, data, pos, length);
}

std::string PGP::format_string(std::string data, uint8_t line_length) const{
    std::string out = "";
    for(unsigned int i = 0; i < data.size(); i += line_length){
        out += data.substr(i, line_length) + "\n";
    }
    return out;
}

PGP::PGP()
    : armored(true),
      type(PGP::Type::UNKNOWN),
      keys(),
      packets()
{}

PGP::PGP(const PGP & copy)
    : armored(copy.armored),
      type(copy.type),
      keys(copy.keys),
      packets(copy.get_packets_clone())
{}

PGP::PGP(const std::string & data)
    : PGP()
{
    read(data);
}

PGP::PGP(std::istream & stream)
    : PGP()
{
    read(stream);
}

PGP::~PGP(){
    packets.clear();
}

void PGP::read(const std::string & data){
    std::stringstream s(data);
    read(s);
}

void PGP::read(std::istream & stream){
    // find armor header
    //
    // 6.2. Forming ASCII Armor
    //     ...
    //     Note that all these Armor Header Lines are to consist of a complete
    //     line. That is to say, there is always a line ending preceding the
    //     starting five dashes, and following the ending five dashes. The
    //     header lines, therefore, MUST start at the beginning of a line, and
    //     MUST NOT have text other than whitespace following them on the same
    //     line. These line endings are considered a part of the Armor Header
    //     Line for the purposes of determining the content they delimit.
    std::string line;
    while (std::getline(stream, line) && line.substr(0, 15) != "-----BEGIN PGP ");

    // if no armor header found, assume entire stream is key
    if (!stream){
        stream.clear();
        stream.seekg(stream.beg);

        // parse entire stream
        read_raw(stream);

        armored = false;
        type = PGP::Type::UNKNOWN;
    }
    else{
        // parse armor header
        Type_t new_type;
        for(new_type = PGP::Type::MESSAGE; new_type != PGP::Type::SIGNED_MESSAGE; new_type++){
            if (("-----BEGIN PGP " + ASCII_Armor_Header[new_type] + "-----") == line){
                break;
            }
        }

        // Cleartext Signature Framework
        if (new_type == PGP::Type::SIGNED_MESSAGE){
            throw std::runtime_error("Error: Data contains message section. Use PGPCleartextSignature to parse this data.");
        }

        // if ASCII Armor was set before calling read()
        if (type != PGP::Type::UNKNOWN){
            if (type != new_type){
                std::cerr << "Warning: ASCII Armor does not match data type: " << std::to_string(new_type) << std::endl;
            }
        }

        type = new_type;

        // read Armor Key(s)
        while (std::getline(stream, line) && line.size()){
            std::stringstream s(line);
            std::string key, value;

            if (!(std::getline(s, key, ':') && std::getline(s, value))){
                std::cerr << "Warning: Discarding bad Armor Header: " << line << std::endl;
                continue;
            }

            bool found = false;
            for(std::string const & header_key : ASCII_Armor_Key){
                if (header_key == key){
                    found = true;
                    break;
                }
            }

            if (!found){
                std::cerr << "Warning: Unknown ASCII Armor Header Key \"" << key << "\"." << std::endl;
            }

            keys.push_back(Armor_Key(key, value));
        }

        // read up to tail
        std::string body;
        while (std::getline(stream, line) && (line.substr(0, 13) != "-----END PGP ")){
            body += line;
        }

        // check for a checksum
        if (body[body.size() - 5] == '='){
            uint32_t checksum = toint(radix642ascii(body.substr(body.size() - 4, 4)), 256);
            body = radix642ascii(body.substr(0, body.size() - 5));
            // check if the checksum is correct
            if (crc24(body) != checksum){
                std::cerr << "Warning: Given checksum does not match calculated value." << std::endl;
            }
        }
        else{
            body = radix642ascii(body);
            std::cerr << "Warning: No checksum found." << std::endl;
        }

        // parse data
        read_raw(body);

        armored = true;

        // warn if packet sequence is not meaningful
        std::string error;
        if (!meaningful(error)){
            std::cerr << error << std::endl;
        }
    }
}

void PGP::read_raw(const std::string & data){
    // read each packet
    uint8_t partial = 0;
    std::string::size_type pos = 0;
    while (pos < data.size()){
        Packet::Ptr packet = read_packet(data, pos, partial);
        if (packet){
            packets.push_back(packet);
        }
    }

    if (packets.size()){
        if (partial){                         // last packet must have been a partial packet
            packets.back() -> set_partial(3); // set last partial packet to partial end
        }
    }

    armored = false;                          // assume data was not armored, since it was submitted through this function
}

void PGP::read_raw(std::istream & stream){
    read_raw(std::string(std::istreambuf_iterator <char> (stream), {}));
}

std::string PGP::show(const uint8_t indents, const uint8_t indent_size) const{
    std::stringstream out;
    for(Packet::Ptr const & p : packets){
        out << p -> show(indents, indent_size) << "\n";
    }
    return out.str();
}

std::string PGP::raw(const uint8_t header) const{
    std::string out = "";
    for(Packet::Ptr const & p : packets){
        out += p -> write(header);
    }
    return out;
}

std::string PGP::write(const uint8_t armor, const uint8_t header) const{
    std::string packet_string = raw(header);   // raw PGP data = binary, no ASCII headers
    if ((armor == 1) || (!armor && !armored)){ // if no armor or if default, and not armored
        return packet_string;                  // return raw data
    }
    std::string out = "-----BEGIN PGP " + ASCII_Armor_Header[type] + "-----\n";
    for(PGP::Armor_Key const & key : keys){
        out += key.first + ": " + key.second + "\n";
    }
    out += "\n";
    return out + format_string(ascii2radix64(packet_string), MAX_LINE_LENGTH) + "=" + ascii2radix64(unhexlify(makehex(crc24(packet_string), 6))) +  "\n-----END PGP " + ASCII_Armor_Header[type] + "-----\n";
}

bool PGP::get_armored() const{
    return armored;
}

PGP::Type_t PGP::get_type() const{
    return type;
}

const PGP::Armor_Keys & PGP::get_keys() const{
    return keys;
}

const PGP::Packets & PGP::get_packets() const{
    return packets;
}

PGP::Packets PGP::get_packets_clone() const{
    std::vector <Packet::Ptr> out;
    for(Packet::Ptr const & p : packets){
        out.push_back(p -> clone());
    }
    return out;
}

void PGP::set_armored(const bool a){
    armored = a;
}

void PGP::set_type(const PGP::Type_t header){
    type = header;
}

void PGP::set_keys(const PGP::Armor_Keys & k){
    keys = k;
}

void PGP::set_packets(const PGP::Packets & p){
    packets.clear();
    for(Packet::Ptr const & t : p){
        packets.push_back(t -> clone());
    }
}

// OpenPGP Message :- Encrypted Message | Signed Message | Compressed Message | Literal Message.
bool PGP::Message::OpenPGPMessage(std::list <Token>::iterator it, std::list <Token> & s){
    if ((*it == ENCRYPTEDMESSAGE) || (*it == SIGNEDMESSAGE) || (*it == COMPRESSEDMESSAGE) || (*it == LITERALMESSAGE)){
        *it = OPENPGPMESSAGE;
        return true;
    }
    return false;
}

// Compressed Message :- Compressed Data Packet.
bool PGP::Message::CompressedMessage(std::list <Token>::iterator it, std::list <Token> & s){
    if (*it == CDP){
        *it = COMPRESSEDMESSAGE;
        return true;
    }
    return false;
}

// Literal Message :- Literal Data Packet.
bool PGP::Message::LiteralMessage(std::list <Token>::iterator it, std::list <Token> & s){
    if (*it == LDP){
        *it = LITERALMESSAGE;
        return true;
    }
    return false;
}

// ESK :- Public-Key Encrypted Session Key Packet | Symmetric-Key Encrypted Session Key Packet.
bool PGP::Message::EncryptedSessionKey(std::list <Token>::iterator it, std::list <Token> & s){
    if ((*it == PKESKP) || (*it == SKESKP)){
        *it = ESK;
        return true;
    }
    return false;
}

// ESK Sequence :- ESK | ESK Sequence, ESK.
bool PGP::Message::ESKSequence(std::list <Token>::iterator it, std::list <Token> & s){
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
bool PGP::Message::EncryptedData(std::list <Token>::iterator it, std::list <Token> & s){
    if ((*it == SEDP) || (*it == SEIPDP)){
        *it = ENCRYPTEDDATA;
        return true;
    }
    return false;
}

// Encrypted Message :- Encrypted Data | ESK Sequence, Encrypted Data.
bool PGP::Message::EncryptedMessage(std::list <Token>::iterator it, std::list <Token> & s){
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
bool PGP::Message::OnePassSignedMessage(std::list <Token>::iterator it, std::list <Token> & s){
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
bool PGP::Message::SignedMessage(std::list <Token>::iterator it, std::list <Token> & s){
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

bool PGP::meaningful_MESSAGE(const PGP::Message::Token & token, std::string & error) const{
    if (!packets.size()){
        error = "Error: No packets found";
        return false;
    }

    if ((token != PGP::Message::OPENPGPMESSAGE)    &&
        (token != PGP::Message::ENCRYPTEDMESSAGE)  &&
        (token != PGP::Message::SIGNEDMESSAGE)     &&
        (token != PGP::Message::COMPRESSEDMESSAGE) &&
        (token != PGP::Message::LITERALMESSAGE)){
        error = "Error: Invalid Token to match.";
        return false;
    }

    // get list of packets and convert them to Token
    std::list <PGP::Message::Token> s;
    for(Packet::Ptr const & p : packets){
        PGP::Message::Token push;
        switch(p -> get_tag()){
            case 8:
                push = PGP::Message::CDP;
                break;
            case 11:
                push = PGP::Message::LDP;
                break;
            case 1:
                push = PGP::Message::PKESKP;
                break;
            case 3:
                push = PGP::Message::SKESKP;
                break;
            case 9:
                push = PGP::Message::SEDP;
                break;
            case 18:
                push = PGP::Message::SEIPDP;
                break;
            case 4:
                push = PGP::Message::OPSP;
                break;
            case 2:
                push = PGP::Message::SP;
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
        for(std::list <PGP::Message::Token>::iterator it = s.begin(); it != s.end(); it++){ // for each token
            // make sure the sentence continues to fit at least one of the rules at least once per loop over the sentence
            if (PGP::Message::OpenPGPMessage(it, s)       ||
                PGP::Message::CompressedMessage(it, s)    ||
                PGP::Message::LiteralMessage(it, s)       ||
                PGP::Message::EncryptedSessionKey(it, s)  ||
                PGP::Message::ESKSequence(it, s)          ||
                PGP::Message::EncryptedData(it, s)        ||
                PGP::Message::EncryptedMessage(it, s)     ||
                PGP::Message::OnePassSignedMessage(it, s) ||
                PGP::Message::SignedMessage(it, s)){
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

bool PGP::meaningful_KEY_BLOCK(const PGP::Type_t & t, std::string & error) const{
    // public or private key packets to look for
    uint8_t key, subkey;
    if (t == PGP::Type::PUBLIC_KEY_BLOCK){
           key = Packet::ID::Public_Key;
        subkey = Packet::ID::Public_Subkey;
    }
    else if (t == PGP::Type::PRIVATE_KEY_BLOCK){
           key = Packet::ID::Secret_Key;
        subkey = Packet::ID::Secret_Subkey;
    }
    else{
        error = "Error: Not a key type.";
        return false;
    }

    // revocation certificates are placed in PUBLIC KEY BLOCKs
    // and have only one signature packet???
    if ((packets.size() == 1)                                                                 &&
        (packets[0] -> get_tag() == Packet::ID::Signature)                                    &&
        (Tag2(packets[0] -> raw()).get_type() == Signature_Type::ID::Key_revocation_signature)){
        return true;
    }
    // minimum 2 packets: Primary Key + User ID
    else if (packets.size() < 2){
        error = "Error: Not enough packets (minimum 2).";
        return false;
    }

    //   - One Public/Secret-Key packet
    if (packets[0] -> get_tag() != key){
        error = "Error: First packet is not a " + Packet::Name.at(key) + ".";
        return false;
    }

    // get version of primary key
    uint8_t primary_key_version = Tag6(packets[0] -> raw()).get_version();

    //   - Zero or more revocation signatures
    unsigned int i = 1;
    while ((i < packets.size()) && (packets[i] -> get_tag() == Packet::ID::Signature)){
        if (Tag2(packets[i] -> raw()).get_type() == Signature_Type::ID::Key_revocation_signature){
            i++;
        }
        else{
            error = "Error: Packet " + std::to_string(i) + " following " + Packet::Name.at(key) + " is not a key revocation signature.";
            return false;
        }
    }

    //   - One or more User ID packets
    //
    //   - After each User ID packet, zero or more Signature packets
    //     (certifications)
    //
    //   - Zero or more User Attribute packets
    //
    //   - After each User Attribute packet, zero or more Signature packets
    //     (certifications)
    //
    //   ...
    //
    // User Attribute packets and User ID packets may be freely intermixed
    // in this section, so long as the signatures that follow them are
    // maintained on the proper User Attribute or User ID packet.
    std::size_t user_id_count = 0;
    do{
        // make sure there is a User packet
        if ((packets[i] -> get_tag() != Packet::ID::User_ID) &&
            (packets[i] -> get_tag() != Packet::ID::User_Attribute)){
            error = "Error: Packet is not a User ID or User Attribute Packet.";
            return false;
        }

        // need at least one User ID packet
        user_id_count += (packets[i] -> get_tag() == Packet::ID::User_ID);

        // go to next packet
        i++;

        // Immediately following each User ID packet, there are zero or more
        // Signature packets. Each Signature packet is calculated on the
        // immediately preceding User ID packet and the initial Public-Key
        // packet. The signature serves to certify the corresponding public key
        // and User ID. In effect, the signer is testifying to his or her
        // belief that this public key belongs to the user identified by this
        // User ID.
        //
        // Within the same section as the User ID packets, there are zero or
        // more User Attribute packets. Like the User ID packets, a User
        // Attribute packet is followed by zero or more Signature packets
        // calculated on the immediately preceding User Attribute packet and the
        // initial Public-Key packet.
        while ((i < packets.size()) && (packets[i] -> get_tag() == Packet::ID::Signature)){
            // make sure the signature type is a certification
            if (!Signature_Type::is_certification(Tag2(packets[i] -> raw()).get_type())){
                error = "Error: Signature type is not a certification packet.";
                return false;
            }

            // TODO: make sure signature matches the User packet
            if (packets[i - 1] -> get_tag() == Packet::ID::User_ID){

            }
            else if (packets[i - 1] -> get_tag() == Packet::ID::User_Attribute){

            }
            // else{}

            i++;
        }
    } while ((i < packets.size()) &&
             (Packet::is_user(packets[i] -> get_tag())));

    // need at least one User ID packet
    if (!user_id_count){
        error = "Error: Need at least one " + Packet::Name.at(Packet::ID::User_ID) + ".";
        return false;
    }

    //    - Zero or more Subkey packets
    while (((i + 1) < packets.size()) && (packets[i] -> get_tag() == subkey)){
        if (primary_key_version == 3){
            error = "Error: Version 3 keys MUST NOT have subkeys.";
            return false;
        }

        i++;

        //    - After each Subkey packet, one Signature packet, plus optionally a revocation
        if ((i >= packets.size())                             ||
            (packets[i] -> get_tag() != Packet::ID::Signature)){
            error = "Error: Signature packet not following subkey packet.";
            return false;
        }

        // check that the Signature packet is a Subkey binding signature
        if (Tag2(packets[i] -> raw()).get_type() != Signature_Type::ID::Subkey_Binding_Signature){
            error = "Error: Signature packet following subpacket is not of type " + Signature_Type::Name.at(Signature_Type::ID::Subkey_Binding_Signature) + ".";
            return false;
        }

        // TODO: make sure signature matches the signature packet

        i++;

        // if there are no more packets to check, stop checking
        if (i >= packets.size()){
            break;
        }

        // optionally a revocation
        if (packets[i] -> get_tag() == Packet::ID::Signature){
            if (Tag2(packets[i] -> raw()).get_type() == Signature_Type::ID::Key_revocation_signature){
                i++;
            }
            else{
                error = "Error: Signature packet following subkey signature is not a " + Signature_Type::Name.at(Signature_Type::ID::Key_revocation_signature) + ".";
                return false;
            }
        }
    }

    // the index should be at the end of the packets

    return (i == packets.size());
}

bool PGP::meaningful_PUBLIC_KEY_BLOCK(std::string & error) const{
    return meaningful_KEY_BLOCK(PGP::Type::PUBLIC_KEY_BLOCK, error);
}

bool PGP::meaningful_PRIVATE_KEY_BLOCK(std::string & error) const{
    return meaningful_KEY_BLOCK(PGP::Type::PRIVATE_KEY_BLOCK, error);
}

bool PGP::meaningful_MESSAGE_PART_XY(std::string & error) const{
    return false;
}

bool PGP::meaningful_MESSAGE_PART_X(std::string & error) const{
    return false;
}

bool PGP::meaningful_SIGNATURE(std::string & error) const{
    if (packets.size() != 1){
        error = "Warning: Too many packets";
        return false;
    }

    if (packets[0] -> get_tag() != Packet::ID::Signature){
        error = "Warning: Packet is not a signature packet";
        return false;
    }

    return true;
}

bool PGP::meaningful(const PGP::Type_t & t, std::string & error) const{
    bool rc = false;
    switch (t){
        case PGP::Type::MESSAGE:
            rc = meaningful_MESSAGE(PGP::Message::OPENPGPMESSAGE, error);
            break;
        case PGP::Type::PUBLIC_KEY_BLOCK:
            rc = meaningful_PUBLIC_KEY_BLOCK(error);
            break;
        case PGP::Type::PRIVATE_KEY_BLOCK:
            rc = meaningful_PRIVATE_KEY_BLOCK(error);
            break;
        case PGP::Type::KEY_BLOCK:
            rc = meaningful_PUBLIC_KEY_BLOCK(error) || meaningful_PRIVATE_KEY_BLOCK(error);
            break;
        case PGP::Type::MESSAGE_PART_XY:
            rc = meaningful_MESSAGE_PART_XY(error);
            break;
        case PGP::Type::MESSAGE_PART_X:
            rc = meaningful_MESSAGE_PART_XY(error);
            break;
        case PGP::Type::SIGNATURE:
            rc = meaningful_MESSAGE_PART_XY(error);
            break;
    }

    return rc;
}

bool PGP::meaningful(const PGP::Type_t & t) const{
    std::string error;
    return meaningful(t, error);
}

bool PGP::meaningful(std::string & error) const{
    return ((type != PGP::Type::UNKNOWN) && meaningful(type, error));
}

bool PGP::meaningful() const{
    std::string error;
    return meaningful(error);
}

PGP & PGP::operator=(const PGP & copy){
    armored = copy.armored;
    type = copy.type;
    keys = copy.keys;
    packets = copy.get_packets_clone();
    return *this;
}

PGP::Ptr PGP::clone() const{
    return std::make_shared <PGP> (*this);
}