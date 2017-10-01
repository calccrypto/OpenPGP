#include "PGP.h"

namespace OpenPGP {

const PGP::Type_t PGP::UNKNOWN           = 0; // Default value
const PGP::Type_t PGP::MESSAGE           = 1; // Used for signed, encrypted, or compressed files.
const PGP::Type_t PGP::PUBLIC_KEY_BLOCK  = 2; // Used for armoring public keys.
const PGP::Type_t PGP::PRIVATE_KEY_BLOCK = 3; // Used for armoring private keys.
const PGP::Type_t PGP::MESSAGE_PART_XY   = 4; // Used for multi-part messages, where the armor is split amongst Y parts, and this is the Xth part out of Y.
const PGP::Type_t PGP::MESSAGE_PART_X    = 5; // Used for multi-part messages, where this is the Xth part of an unspecified number of parts. Requires the MESSAGE-ID Armor Header to be used.
const PGP::Type_t PGP::SIGNATURE         = 6; // Used for detached signatures, OpenPGP/MIME signatures, and cleartext signatures. Note that PGP 2.x uses BEGIN PGP MESSAGE for detached signatures.
const PGP::Type_t PGP::SIGNED_MESSAGE    = 7; // Used for cleartext signatures; header not really part of RFC 4880.

const std::string PGP::ASCII_Armor_Header[] = {
   "",                  // Unknown type
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
                pos += 6;
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
                pos += 6;
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

Packet::Tag::Ptr PGP::read_packet_raw(const bool format, const uint8_t tag, uint8_t & partial, const std::string & data, std::string::size_type & pos, const std::string::size_type & length) const{
    Packet::Tag::Ptr out;
    if (partial > 1){
        out = std::make_shared <Packet::Partial> ();
    }
    else{
        if (tag == Packet::RESERVED){
            throw std::runtime_error("Error: Tag number MUST NOT be 0.");
        }
        else if (tag == Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY){
            out = std::make_shared <Packet::Tag1> ();
        }
        else if (tag == Packet::SIGNATURE){
            out = std::make_shared <Packet::Tag2> ();
        }
        else if (tag == Packet::SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY){
            out = std::make_shared <Packet::Tag3> ();
        }
        else if (tag == Packet::ONE_PASS_SIGNATURE){
            out = std::make_shared <Packet::Tag4> ();
        }
        else if (tag == Packet::SECRET_KEY){
            out = std::make_shared <Packet::Tag5> ();
        }
        else if (tag == Packet::PUBLIC_KEY){
            out = std::make_shared <Packet::Tag6> ();
        }
        else if (tag == Packet::SECRET_SUBKEY){
            out = std::make_shared <Packet::Tag7> ();
        }
        else if (tag == Packet::COMPRESSED_DATA){
            out = std::make_shared <Packet::Tag8> ();
        }
        else if (tag == Packet::SYMMETRICALLY_ENCRYPTED_DATA){
            out = std::make_shared <Packet::Tag9> ();
        }
        else if (tag == Packet::MARKER_PACKET){
            out = std::make_shared <Packet::Tag10> ();
        }
        else if (tag == Packet::LITERAL_DATA){
            out = std::make_shared <Packet::Tag11> ();
        }
        else if (tag == Packet::TRUST){
            out = std::make_shared <Packet::Tag12> ();
        }
        else if (tag == Packet::USER_ID){
            out = std::make_shared <Packet::Tag13> ();
        }
        else if (tag == Packet::PUBLIC_SUBKEY){
            out = std::make_shared <Packet::Tag14> ();
        }
        else if (tag == Packet::USER_ATTRIBUTE){
            out = std::make_shared <Packet::Tag17> ();
        }
        else if (tag == Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA){
            out = std::make_shared <Packet::Tag18> ();
        }
        else if (tag == Packet::MODIFICATION_DETECTION_CODE){
            out = std::make_shared <Packet::Tag19> ();
        }
        else if (tag == 60){
            out = std::make_shared <Packet::Tag60> ();
        }
        else if (tag == 61){
            out = std::make_shared <Packet::Tag61> ();
        }
        else if (tag == 62){
            out = std::make_shared <Packet::Tag62> ();
        }
        else if (tag == 63){
            out = std::make_shared <Packet::Tag63> ();
        }
        else{
            throw std::runtime_error("Error: Tag not defined: " + std::to_string(tag) + ".");
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

Packet::Tag::Ptr PGP::read_packet(const std::string & data, std::string::size_type & pos, uint8_t & partial) const{
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
    : armored(Armored::YES),
      type(UNKNOWN),
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

PGP::~PGP(){}

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
        type = UNKNOWN;
    }
    else{
        // parse armor header
        for(type = MESSAGE; type != SIGNED_MESSAGE; type++){
            if (("-----BEGIN PGP " + ASCII_Armor_Header[type] + "-----") == line){
                break;
            }
        }

        // Cleartext Signature Framework
        if (type == SIGNED_MESSAGE){
            throw std::runtime_error("Error: Data contains message section. Use CleartextSignature to parse this data.");
        }

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
    }
}

void PGP::read_raw(const std::string & data){
    packets.clear();

    // read each packet
    uint8_t partial = 0;
    std::string::size_type pos = 0;
    while (pos < data.size()){
        Packet::Tag::Ptr packet = read_packet(data, pos, partial);
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

std::string PGP::show(const std::size_t indents, const std::size_t indent_size) const{
    std::string out;
    for(Packet::Tag::Ptr const & p : packets){
        out += p -> show(indents, indent_size) + "\n";
    }
    return out;
}

std::string PGP::raw(const Packet::Tag::Format header) const{
    std::string out = "";
    for(Packet::Tag::Ptr const & p : packets){
        out += p -> write(header);
    }
    return out;
}

std::string PGP::write(const PGP::Armored armor, const Packet::Tag::Format header) const{
    const std::string packet_string = raw(header);  // raw PGP data = binary, no ASCII headers

    if ((armor == Armored::NO)                   || // no armor
        ((armor == Armored::DEFAULT) && !armored)){ // or use stored value, and stored value is no
        return packet_string;
    }

    std::string out = "-----BEGIN PGP " + ASCII_Armor_Header[type] + "-----\n";
    for(Armor_Key const & key : keys){
        out += key.first + ": " + key.second + "\n";
    }

    return out + "\n" + format_string(ascii2radix64(packet_string), MAX_LINE_LENGTH) + "=" + ascii2radix64(unhexlify(makehex(crc24(packet_string), 6))) +  "\n-----END PGP " + ASCII_Armor_Header[type] + "-----\n";
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
    Packets out = packets;
    for(Packet::Tag::Ptr & p : out){
        p = p -> clone();
    }
    return out;
}

void PGP::set_armored(const bool a){
    armored = a;
}

void PGP::set_type(const PGP::Type_t t){
    type = t;
}

void PGP::set_keys(const PGP::Armor_Keys & k){
    keys = k;
}

void PGP::set_packets(const PGP::Packets & p){
    packets = p;
}

void PGP::set_packets_clone(const PGP::Packets & p){
    packets = p;
    for(Packet::Tag::Ptr & p : packets){
        p = p -> clone();
    }
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

}
