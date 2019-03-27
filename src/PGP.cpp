#include "PGP.h"

#include <iostream>
#include <sstream>
#include <stdexcept>

#include "Misc/CRC-24.h"
#include "Misc/Length.h"
#include "Packets/Packets.h"
#include "common/includes.h"

namespace OpenPGP {

const PGP::Type_t PGP::UNKNOWN              = 0; // Default value
const PGP::Type_t PGP::MESSAGE              = 1; // Used for signed, encrypted, or compressed files.
const PGP::Type_t PGP::PUBLIC_KEY_BLOCK     = 2; // Used for armoring public keys.
const PGP::Type_t PGP::PRIVATE_KEY_BLOCK    = 3; // Used for armoring private keys.
const PGP::Type_t PGP::MESSAGE_PART_XY      = 4; // Used for multi-part messages, where the armor is split amongst Y parts, and this is the Xth part out of Y.
const PGP::Type_t PGP::MESSAGE_PART_X       = 5; // Used for multi-part messages, where this is the Xth part of an unspecified number of parts. Requires the MESSAGE-ID Armor Header to be used.
const PGP::Type_t PGP::SIGNATURE            = 6; // Used for detached signatures, OpenPGP/MIME signatures, and cleartext signatures. Note that PGP 2.x uses BEGIN PGP MESSAGE for detached signatures.
const PGP::Type_t PGP::SIGNED_MESSAGE       = 7; // Used for cleartext signatures; header not really part of RFC 4880.

const std::string PGP::ASCII_Armor_5_Dashes = "-----";
const std::string PGP::ASCII_Armor_Begin    = PGP::ASCII_Armor_5_Dashes + "BEGIN PGP ";
const std::string PGP::ASCII_Armor_Header[] = {
   "",                                           // Unknown type
   "MESSAGE",                                    // Used for signed, encrypted, or compressed files.
   "PUBLIC KEY BLOCK",                           // Used for armoring public keys.
   "PRIVATE KEY BLOCK",                          // Used for armoring private keys.
   "MESSAGE, PART X/Y",                          // Used for multi-part messages, where the armor is split amongst Y parts, and this is the Xth part out of Y.
   "MESSAGE, PART X",                            // Used for multi-part messages, where this is the Xth part of an unspecified number of parts. Requires the MESSAGE-ID Armor Header to be used.
   "SIGNATURE",                                  // Used for detached signatures, OpenPGP/MIME signatures, and cleartext signatures. Note that PGP 2.x uses BEGIN PGP MESSAGE for detached signatures.
   "SIGNED MESSAGE",                             // Used for cleartext signatures; header not really part of RFC 4880.
};

// ASCII descriptor of OpenPGP packet
const std::string PGP::ASCII_Armor_Key[]    = {
    "Version",                                   // which states the OpenPGP implementation and version used to encode the message.

    "Comment",                                   // a user-defined comment. OpenPGP defines all text to be in UTF-8. A comment may be any UTF-8 string. However, the whole point of armoring is to provide seven-bit-clean data.
                                                 // Consequently, if a comment has characters that are outside the US-ASCII range of UTF, they may very well not survive transport.

    "MessageID",                                 // a 32-character string of printable characters. The string must be the same for all parts of a multi-part message that uses the "PART X" Armor Header. MessageID strings should be
                                                 // unique enough that the recipient of the mail can associate all the parts of a message with each other. A good checksum or cryptographic hash function is sufficient.
                                                 // The MessageID SHOULD NOT appear unless it is in a multi-part message. If it appears at all, it MUST be computed from the finished (encrypted, signed, etc.) message in a deterministic
                                                 // fashion, rather than contain a purely random value. This is to allow the legitimate recipient to determine that the MessageID cannot serve as a covert means of leaking cryptographic key
                                                 // information.

    "Hash",                                      // a comma-separated list of hash algorithms used in this message. This is used only in cleartext signed messages.

    "Charset",                                   // a description of the character set that the plaintext is in. Please note that OpenPGP defines text to be in UTF-8. An implementation will get best results by translating into and out
};

const std::string PGP::ASCII_Armor_End      = PGP::ASCII_Armor_5_Dashes + "END PGP ";

uint8_t PGP::read_packet_header(const std::string & data, std::string::size_type & pos, uint8_t & ctb, Packet::HeaderFormat & format, uint8_t & tag) const {
    ctb = data[pos];        // Name "ctb" came from Version 2 [RFC 1991]

    if (!(ctb & 0x80)) {
       throw std::runtime_error("Error: First bit of packet header MUST be 1 (octet " + std::to_string(pos) + ": 0x" + makehex(ctb, 2) + ").");
    }

    if (ctb & 0x40) {       // New length type RFC4880 sec 4.2.2
        format = Packet::HeaderFormat::NEW;
        tag = ctb & 0x3f;
    }
    else{                   // Old length type RFC4880 sec 4.2.1
        format = Packet::HeaderFormat::OLD;
        tag = (ctb >> 2) & 0xf;
    }

    pos++;                  // move the position to the length section of the header

    return tag;
}

// reads the length of the packet data and extracts the start and length of the packet data
// if partial returns Packet::PARTIAL, the partial_data variable should be used instead of data
// format should have been set to OLD or NEW
// pos should be on the first octet of the packet header length
Packet::PartialBodyLength PGP::read_packet_unformatted(const Packet::HeaderFormat format,
                                                       const uint8_t ctb,
                                                       const std::string & data,
                                                       std::string::size_type & pos,
                                                       std::string::size_type & packet_start,
                                                       std::string::size_type & packet_length,
                                                       std::string & partial_data) const {
    std::size_t hl = 0;
    Packet::PartialBodyLength partial = Packet::NOT_PARTIAL;
    if (format == Packet::HeaderFormat::OLD) {                               // Old length type RFC4880 sec 4.2.1
        if ((ctb & 3) == 0) {                                                // 0 - The packet has a one-octet length. The header is 2 octets long.
            hl = read_one_octet_lengths(data, pos, packet_length, format);
            packet_start = pos;
            pos += packet_length;
        }
        else if ((ctb & 3) == 1) {                                           // 1 - The packet has a two-octet length. The header is 3 octets long.
            hl = read_two_octet_lengths(data, pos, packet_length, format);
            packet_start = pos;
            pos += packet_length;
        }
        else if ((ctb & 3) == 2) {                                           // 2 - The packet has a four-octet length. The header is 5 octets long.
            hl = read_five_octet_lengths(data, pos, packet_length, format);
            packet_start = pos;
            pos += packet_length;
        }
        else if ((ctb & 3) == 3) {                                           // The packet is of indeterminate length. The header is 1 octet long, and the implementation must determine how long the packet is.
            packet_length = data.size() - pos;                                // header is one octet long
            hl = 0;
            pos += hl;
            partial_data = data.substr(pos, packet_length);
            pos += packet_length;
            partial = Packet::PARTIAL;
        }
    }
    else{                                                                    // New length type RFC4880 sec 4.2.2
        const uint8_t first_octet = static_cast <unsigned char> (data[pos]);

        if (first_octet < 192) {                                             // 0 - 191; A one-octet Body Length header encodes packet lengths of up to 191 octets.
            hl = read_one_octet_lengths(data, pos, packet_length, format);
            packet_start = pos;
            pos += packet_length;
        }
        else if ((192 <= first_octet) & (first_octet < 223)) {               // 192 - 8383; A two-octet Body Length header encodes packet lengths of 192 to 8383 octets.
            hl = read_two_octet_lengths(data, pos, packet_length, format);
            packet_start = pos;
            pos += packet_length;
        }
        else if (first_octet == 255) {                                       // 8384 - 4294967295; A five-octet Body Length header encodes packet lengths of up to 4,294,967,295 (0xFFFFFFFF) octets in length.
            hl = read_five_octet_lengths(data, pos, packet_length, format);
            packet_start = pos;
            pos += packet_length;
        }
        else if (Packet::PARTIAL_BODY_LENGTH_START <= first_octet) {         // unknown; When the length of the packet body is not known in advance by the issuer, Partial Body Length headers encode a packet of indeterminate length, effectively making it a stream.
            // get the first partial body length
            packet_length = read_partialBodyLen(first_octet, format);

            // warn if RFC 4880 sec 4.2.2.4 is not followed
            if (packet_length < 512) {
                std::cerr << "Warning: The first partial length MUST be at least 512 octets long (Got " << packet_length << ")" << std::endl;
            }

            hl = 1;
            pos += hl;
            partial_data = data.substr(pos, packet_length);
            pos += packet_length;

            // get the rest of them
            while ((Packet::PARTIAL_BODY_LENGTH_START <= (uint8_t) data[pos]) &&
                   ((uint8_t) data[pos] <= Packet::PARTIAL_BODY_LENGTH_END)) {
                packet_length = read_partialBodyLen(data[pos], format);
                pos += hl;
                partial_data += data.substr(pos, packet_length);
                pos += packet_length;
            }

            // 4.2.2.4.  Partial Body Lengths
            //
            //     The last length header in the packet MUST NOT be a Partial Body Length header.
            std::string::size_type final_start = 0;
            std::string::size_type final_length = 0;
            std::string not_used;
            if (read_packet_unformatted(format, ctb, data, pos, final_start, final_length, not_used) == Packet::PARTIAL) {
                std::cerr << "Warning: Reached end of data, but did not complete partial packet sequence" << std::endl;
            }
            else {
                // add the final piece
                partial_data += data.substr(final_start, final_length);
                pos += final_length;
            }

            packet_start = 0;
            packet_length = partial_data.size();
            partial = Packet::PARTIAL;
        }
    }

    return partial;
}

Packet::Tag::Ptr PGP::read_packet_raw(const std::string & data, std::string::size_type & pos, const std::string::size_type & length, const uint8_t tag, const Packet::HeaderFormat format, const Packet::PartialBodyLength & partial) const {
    if ((partial == Packet::PARTIAL) &&
        !Packet::can_have_partial_length(tag)) {
        throw std::runtime_error("An implementation MAY use Partial Body Lengths for data packets, be "
                                 "they literal, compressed, or encrypted. ... Partial Body Lengths MUST NOT be "
                                 "used for any other packet types.");
    }

    Packet::Tag::Ptr out = nullptr;
    switch (tag) {
        case Packet::RESERVED:
            out = std::make_shared <Packet::Tag0> ();
            break;
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
    out -> set_header_format(format);
    out -> read(data, pos, length);

    return out;
}

Packet::Tag::Ptr PGP::read_packet(const std::string & data, std::string::size_type & pos) const {
    if ((pos >= data.size())) {
        return nullptr;
    }

    // get the header data
    uint8_t ctb = 0;
    Packet::HeaderFormat format = Packet::HeaderFormat::NEW;
    uint8_t tag = Packet::RESERVED;
    read_packet_header(data, pos, ctb, format, tag);

    // read out the packet data
    std::string::size_type packet_start = 0;
    std::string::size_type packet_size = 0;
    std::string partial_data;
    return (read_packet_unformatted(format, ctb, data, pos, packet_start, packet_size, partial_data) == Packet::NOT_PARTIAL)?
        // convert the packet data into an object
        read_packet_raw(data,         packet_start, packet_size, tag, format, Packet::NOT_PARTIAL):
        read_packet_raw(partial_data, packet_start, packet_size, tag, format, Packet::PARTIAL);
}

std::string PGP::format_string(const std::string & data, const uint8_t line_length) const {
    std::string out;
    const std::div_t res = div(data.size(), line_length);
    out.reserve((res.quot + static_cast <bool> (res.rem)) * (line_length + 1));
    for(unsigned int i = 0; i < data.size(); i += line_length) {
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

PGP::~PGP() {}

void PGP::read(const std::string & data) {
    std::stringstream s(data);
    read(s);
}

void PGP::read(std::istream & stream) {

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
    //
    // 6.6. Example of an ASCII Armored Message
    //
    //    -----BEGIN PGP MESSAGE-----
    //    Version: OpenPrivacy 0.99
    //
    //    yDgBO22WxBHv7O8X7O/jygAEzol56iUKiXmV+XmpCtmpqQUKiQrFqclFqUDBovzS
    //    vBSFjNSiVHsuAA==
    //    =njUN
    //    -----END PGP MESSAGE-----
    //
    //    Note that this example has extra indenting; an actual armored message
    //    would have no leading whitespace.
    //

    std::string line;
    while (std::getline(stream, line)) {
        // get rid of trailing whitespace
        line = trim_whitespace(line, false, true);

        if (line.substr(0, ASCII_Armor_Begin.size()) == ASCII_Armor_Begin) {
            break;
        }
    }

    // if no armor header found, assume entire stream is binary data
    if (!stream) {
        stream.clear();
        stream.seekg(stream.beg);

        // parse entire stream
        read_raw(stream);

        armored = false;
        type = UNKNOWN;
    }
    else{
        // parse armor header
        for(type = MESSAGE; type != SIGNED_MESSAGE; type++) {
            if ((ASCII_Armor_Begin + ASCII_Armor_Header[type] + ASCII_Armor_5_Dashes) == line) {
                break;
            }
        }

        // Cleartext Signature Framework
        if (type == SIGNED_MESSAGE) {
            throw std::runtime_error("Error: Data contains message section. Use CleartextSignature to parse this data.");
        }

        // read Armor Key(s)
        while (std::getline(stream, line) && line.size()) {
            // get rid of trailing whitespace
            line = trim_whitespace(line, false, true);

            // if now there is nothing, stop
            if (!line.size()) {
                break;
            }

            std::stringstream s(line);
            std::string key, value;

            if (!(std::getline(s, key, ':') && std::getline(s, value))) {
                std::cerr << "Warning: Discarding bad Armor Header: " << line << std::endl;
                continue;
            }

            bool found = false;
            for(std::string const & header_key : ASCII_Armor_Key) {
                if (header_key == key) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                std::cerr << "Warning: Unknown ASCII Armor Header Key \"" << key << "\"." << std::endl;
            }

            keys.push_back(Armor_Key(key, trim_whitespace(value, true, true)));
        }

        // read up to tail
        std::string body = "";
        while (std::getline(stream, line)) {
            // get rid of trailing whitespace
            line = trim_whitespace(line, false, true);

            if (line.substr(0, ASCII_Armor_End.size()) == ASCII_Armor_End) {
                break;
            }

            body += line;
        }

        // check for a checksum
        if (body[body.size() - 5] == '=') {
            const uint32_t checksum = toint(radix642ascii(body.substr(body.size() - 4, 4)), 256);
            body = radix642ascii(body.substr(0, body.size() - 5));
            // check if the checksum is correct
            if (crc24(body) != checksum) {
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

void PGP::read_raw(const std::string & data) {
    packets.clear();

    // read each packet
    std::string::size_type pos = 0;
    while (pos < data.size()) {
        Packet::Tag::Ptr packet = read_packet(data, pos);
        if (packet) {
            packets.push_back(packet);
        }
    }

    // assume data was not armored, since it was submitted through this function
    armored = false;
}

void PGP::read_raw(std::istream & stream) {
    read_raw(std::string(std::istreambuf_iterator <char> (stream), {}));
}

std::string PGP::show(const std::size_t indents, const std::size_t indent_size) const {
    HumanReadable hr(indent_size, indents);
    show(hr);
    return hr.get();
}

void PGP::show(HumanReadable & hr) const {
    for(Packet::Tag::Ptr const & p : packets) {
        p -> show(hr);
    }
}

std::string PGP::raw() const {
    std::string out = "";
    for(Packet::Tag::Ptr const & p : packets) {
        out += p -> write();
    }
    return out;
}

std::string PGP::write(const PGP::Armored armor) const {
    const std::string packet_string = raw();         // raw PGP data = binary, no ASCII headers

    if ((armor == Armored::NO)                   ||  // no armor
        ((armor == Armored::DEFAULT) && !armored)) { // or use stored value, and stored value is no
        return packet_string;
    }

    std::string out = PGP::ASCII_Armor_Begin + ASCII_Armor_Header[type] + PGP::ASCII_Armor_5_Dashes + "\n";
    for(Armor_Key const & key : keys) {
        out += key.first + ": " + key.second + "\n";
    }

    return out + "\n" + format_string(ascii2radix64(packet_string), MAX_LINE_LENGTH) + "=" + ascii2radix64(unhexlify(makehex(crc24(packet_string), 6))) + "\n" + PGP::ASCII_Armor_End + ASCII_Armor_Header[type] + PGP::ASCII_Armor_5_Dashes;
}

bool PGP::get_armored() const {
    return armored;
}

PGP::Type_t PGP::get_type() const {
    return type;
}

const PGP::Armor_Keys & PGP::get_keys() const {
    return keys;
}

const PGP::Packets & PGP::get_packets() const {
    return packets;
}

PGP::Packets PGP::get_packets_clone() const {
    Packets out = packets;
    for(Packet::Tag::Ptr & p : out) {
        p = p -> clone();
    }
    return out;
}

void PGP::set_armored(const bool a) {
    armored = a;
}

void PGP::set_type(const PGP::Type_t t) {
    type = t;
}

void PGP::set_keys(const PGP::Armor_Keys & k) {
    keys = k;
}

void PGP::set_packets(const PGP::Packets & p) {
    packets = p;
}

void PGP::set_packets_clone(const PGP::Packets & p) {
    packets = p;
    for(Packet::Tag::Ptr & p : packets) {
        p = p -> clone();
    }
}

PGP & PGP::operator=(const PGP & copy) {
    armored = copy.armored;
    type = copy.type;
    keys = copy.keys;
    packets = copy.get_packets_clone();
    return *this;
}

PGP::Ptr PGP::clone() const {
    return std::make_shared <PGP> (*this);
}

std::ostream & operator<<(std::ostream & stream, const PGP & pgp) {
    return stream << pgp.show();
}

}
