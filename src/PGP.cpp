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

// 4.2.2.1. One-Octet Lengths
//     A one-octet Body Length header encodes a length of 0 to 191 octets.
//     This type of length header is recognized because the one octet value
//     is less than 192. The body length is equal to:
//     bodyLen = 1st_octet;
//
static std::size_t one_octet_lengths(const std::string & data, std::string::size_type & pos, std::size_t &length) {
    length = static_cast <uint8_t> (data[pos]);
    pos += 1;
    return 1;
}

// 4.2.2.2. Two-Octet Lengths
//
//     A two-octet Body Length header encodes a length of 192 to 8383
//     octets. It is recognized because its first octet is in the range 192
//     to 223. The body length is equal to:
//
//         bodyLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192
//
static std::size_t two_octet_lengths(const std::string & data, std::string::size_type & pos, std::size_t &length) {
    length = toint(data.substr(pos, 2), 256);
    pos += 2;
    return 2;
}
// 4.2.2.3. Five-Octet Lengths
//
//     A five-octet Body Length header consists of a single octet holding
//     the value 255, followed by a four-octet scalar. The body length is
//     equal to:
//
//         bodyLen = (2nd_octet << 24) | (3rd_octet << 16) |
//                   (4th_octet << 8) | 5th_octet
//
//     This basic set of one, two, and five-octet lengths is also used
//     internally to some packets.
//
static std::size_t five_octet_lengths(const std::string & data, std::string::size_type & pos, std::size_t &length) {
    length = toint(data.substr(pos + 1, 4), 256);
    pos += 5;
    return 5;
}

// 4.2.2.4. Partial Body Lengths
//
//     A Partial Body Length header is one octet long and encodes the length
//     of only part of the data packet. This length is a power of 2, from 1
//     to 1,073,741,824 (2 to the 30th power). It is recognized by its one
//     octet value that is greater than or equal to 224, and less than 255.
//     The Partial Body Length is equal to:
//
//         partialBodyLen = 1 << (1st_octet & 0x1F);
//
//     Each Partial Body Length header is followed by a portion of the
//     packet body data. The Partial Body Length header specifies this
//     portion’s length. Another length header (one octet, two-octet,
//     five-octet, or partial) follows that portion. The last length header
//     in the packet MUST NOT be a Partial Body Length header. Partial Body
//     Length headers may only be used for the non-final parts of the
//     packet.
//
//     Note also that the last Body Length header can be a zero-length
//     header.
//
//     An implementation MAY use Partial Body Lengths for data packets, be
//     they literal, compressed, or encrypted. The first partial length
//     MUST be at least 512 octets long. Partial Body Lengths MUST NOT be
//     used for any other packet types.
//
static std::size_t partialBodyLen(uint8_t first_octet){
    return 1ULL << (first_octet & 0x1fU);
}

// Read just the packet length of the current packet
// pos should be on the first octet of the packet header length
// tag should have been set to a valid packet type
// format should have been set to OLD or NEW
// returns length of length section
std::size_t PGP::read_packet_unformatted(const std::string & src, const uint8_t ctb, std::string::size_type & pos, const bool format, std::string & packet_data, Packet::PartialBodyLength & partial) const{
    std::size_t hl = 0;
    std::size_t length = 0;
    if (!format){                                                           // Old length type RFC4880 sec 4.2.1
        if ((ctb & 3) == 0){                                                // 0 - The packet has a one-octet length. The header is 2 octets long.
            hl = one_octet_lengths(src, pos, length);
            partial = Packet::NOT_PARTIAL;
        }
        else if ((ctb & 3) == 1){                                           // 1 - The packet has a two-octet length. The header is 3 octets long.
            hl = two_octet_lengths(src, pos, length);
            partial = Packet::NOT_PARTIAL;
        }
        else if ((ctb & 3) == 2){                                           // 2 - The packet has a four-octet length. The header is 5 octets long.
            hl = five_octet_lengths(src, pos, length);
            partial = Packet::NOT_PARTIAL;
        }
        else if ((ctb & 3) == 3){                                           // The packet is of indeterminate length. The header is 1 octet long, and the implementation must determine how long the packet is.
            length = src.size() - pos;                                      // header is one octet long
            hl = 0;
            pos += hl;
            partial = Packet::PARTIAL;
        }
        packet_data = src.substr(pos, length);
        pos += length;
    }
    else{                                                                   // New length type RFC4880 sec 4.2.2
        const uint8_t first_octet = static_cast <unsigned char> (src[pos]);
        if (first_octet < 192){                                             // 0 - 191; A one-octet Body Length header encodes packet lengths of up to 191 octets.
            hl = one_octet_lengths(src, pos, length);
            packet_data = src.substr(pos, length);
            pos += length;
            partial = Packet::NOT_PARTIAL;
        }
        else if ((192 <= first_octet) & (first_octet < 223)){               // 192 - 8383; A two-octet Body Length header encodes packet lengths of 192 to 8383 octets.
            hl = two_octet_lengths(src, pos, length);
            packet_data = src.substr(pos, length);
            pos += length;
            partial = Packet::NOT_PARTIAL;
        }
        else if (first_octet == 255){                                       // 8384 - 4294967295; A five-octet Body Length header encodes packet lengths of up to 4,294,967,295 (0xFFFFFFFF) octets in length.
            hl = five_octet_lengths(src, pos, length);
            packet_data = src.substr(pos, length);
            pos += length;
            partial = Packet::NOT_PARTIAL;
        }
        else if (Packet::PARTIAL_BODY_LENGTH_START <= first_octet){        // unknown; When the length of the packet body is not known in advance by the issuer, Partial Body Length headers encode a packet of indeterminate length, effectively making it a stream.
            length = partialBodyLen(first_octet);

            // warn if RFC 4880 sec 4.2.2.4 is not followed
            if (length < 512) {
                std::cerr << "Warning: The first partial length MUST be at least 512 octets long (Got " << length << ")" << std::endl;
            }

            hl = 1;
            pos += hl;
            packet_data = src.substr(pos, length);
            pos += length;

            // don't recurse
            if (partial == Packet::PARTIAL) {
                return hl;
            }

            partial = Packet::PARTIAL;

            // keep reading until it hits a non partial packet length
            Packet::PartialBodyLength curr = Packet::PARTIAL;
            while ((pos < src.size()) &&
                   (curr == Packet::PARTIAL)) {
                std::string piece;
                read_packet_unformatted(src, ctb, pos, format, piece, curr);
                packet_data += piece;
            }

            if (curr == Packet::PARTIAL) {
                std::cerr << "Warning: Reached end of data, but did not complete partial packet sequence" << std::endl;
            }
        }
    }

    return hl;
}

uint8_t PGP::read_packet_header(const std::string & data, std::string::size_type & pos, uint8_t & ctb, bool & format, uint8_t & tag) const{
    ctb = data[pos];               // Name "ctb" came from Version 2 [RFC 1991]
    format = ctb & 0x40;           // get packet length type (OLD = false; NEW = true)
    tag = Packet::RESERVED;        // default value (error)

    if (!(ctb & 0x80)){
       throw std::runtime_error("Error: First bit of packet header MUST be 1 (octet " + std::to_string(pos) + ": 0x" + makehex(ctb, 2) + ").");
    }

    if (!format){                  // Old length type RFC4880 sec 4.2.1
        tag = (ctb >> 2) & 0xf;    // get tag value
    }
    else{                          // New length type RFC4880 sec 4.2.2
        tag = ctb & 0x3f;          // get tag value
    }

    pos++;                         // move the position to the length section of the header

    return tag;
}

Packet::Tag::Ptr PGP::read_packet_raw(const std::string & data, const uint8_t tag, const bool format, Packet::PartialBodyLength & partial) const{
    if ((partial == Packet::PARTIAL)                              &&
        ((tag != Packet::LITERAL_DATA)                            &&
         (tag != Packet::COMPRESSED_DATA)                         &&
         (tag != Packet::SYMMETRICALLY_ENCRYPTED_DATA)            &&
         (tag != Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA))) {
            throw std::runtime_error("An implementation MAY use Partial Body Lengths for data packets, be "
                                     "they literal, compressed, or encrypted. ... Partial Body Lengths MUST NOT be "
                                     "used for any other packet types.");
    }

    Packet::Tag::Ptr out = nullptr;
    switch (tag) {
        case Packet::RESERVED:
            throw std::runtime_error("Error: Tag number MUST NOT be 0.");
        case Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY:
            out = std::make_shared <Packet::Tag1> ();
            break;
        case Packet::SIGNATURE:
            out = std::make_shared <Packet::Tag2> ();
            break;
        case Packet::SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY:
            out = std::make_shared <Packet::Tag3> ();
            break;
        case Packet::ONE_PASS_SIGNATURE:
            out = std::make_shared <Packet::Tag4> ();
            break;
        case Packet::SECRET_KEY:
            out = std::make_shared <Packet::Tag5> ();
            break;
        case Packet::PUBLIC_KEY:
            out = std::make_shared <Packet::Tag6> ();
            break;
        case Packet::SECRET_SUBKEY:
            out = std::make_shared <Packet::Tag7> ();
            break;
        case Packet::COMPRESSED_DATA:
            out = std::make_shared <Packet::Tag8> (partial);
            break;
        case Packet::SYMMETRICALLY_ENCRYPTED_DATA:
            out = std::make_shared <Packet::Tag9> (partial);
            break;
        case Packet::MARKER_PACKET:
            out = std::make_shared <Packet::Tag10> ();
            break;
        case Packet::LITERAL_DATA:
            out = std::make_shared <Packet::Tag11> (partial);
            break;
        case Packet::TRUST:
            out = std::make_shared <Packet::Tag12> ();
            break;
        case Packet::USER_ID:
            out = std::make_shared <Packet::Tag13> ();
            break;
        case Packet::PUBLIC_SUBKEY:
            out = std::make_shared <Packet::Tag14> ();
            break;
        case Packet::USER_ATTRIBUTE:
            out = std::make_shared <Packet::Tag17> ();
            break;
        case Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA:
            out = std::make_shared <Packet::Tag18> (partial);
            break;
        case Packet::MODIFICATION_DETECTION_CODE:
            out = std::make_shared <Packet::Tag19> ();
            break;
        case 60:
            out = std::make_shared <Packet::Tag60> ();
            break;
        case 61:
            out = std::make_shared <Packet::Tag61> ();
            break;
        case 62:
            out = std::make_shared <Packet::Tag62> ();
            break;
        case 63:
            out = std::make_shared <Packet::Tag63> ();
            break;
        default:
            throw std::runtime_error("Error: Tag not defined: " + std::to_string(tag) + ".");
            break;
    }

    // fill in data
    out -> set_tag(tag);
    out -> set_format(format);
    out -> set_size(data.size());
    out -> read(data);

    return out;
}

Packet::Tag::Ptr PGP::read_packet(const std::string & data, std::string::size_type & pos) const{
    if (pos >= data.size()){
        return nullptr;
    }

    // get the header data
    uint8_t ctb = 0;
    bool format = false;
    uint8_t tag = Packet::RESERVED;
    read_packet_header(data, pos, ctb, format, tag);

    // read out the packet data
    std::string packet_data;
    Packet::PartialBodyLength partial = Packet::NOT_PARTIAL;
    read_packet_unformatted(data, ctb, pos, format, packet_data, partial);

    // convert the packet data into an object
    return read_packet_raw(packet_data, tag, format, partial);
}

std::string PGP::format_string(std::string data, uint8_t line_length) const{
    std::string out;
    const std::div_t res = div(data.size(), line_length);
    out.reserve(res.quot + static_cast <bool> (res.rem));
    out.clear();
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

    // if no armor header found, assume entire stream is binary data
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
            const uint32_t checksum = toint(radix642ascii(body.substr(body.size() - 4, 4)), 256);
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
    std::string::size_type pos = 0;
    while (pos < data.size()){
        Packet::Tag::Ptr packet = read_packet(data, pos);
        if (packet){
            packets.push_back(packet);
        }
    }

    // assume data was not armored, since it was submitted through this function
    armored = false;
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

std::ostream & operator<<(std::ostream & stream, const PGP & pgp){
    return stream << pgp.show();
}

}
