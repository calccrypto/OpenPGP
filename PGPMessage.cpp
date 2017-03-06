#include "PGPMessage.h"

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

bool PGPMessage::match(const PGP::Message::Token & token, std::string & error) const{
    return ((type == PGP::Type::MESSAGE) && PGP::meaningful_MESSAGE(token, error));
}

bool PGPMessage::match(const PGP::Message::Token & token) const{
    std::string error;
    return ((type == PGP::Type::MESSAGE) && PGP::meaningful_MESSAGE(token, error));
}

bool PGPMessage::meaningful(std::string & error) const{
    return ((type == PGP::Type::MESSAGE) && PGP::meaningful_MESSAGE(PGP::Message::OPENPGPMESSAGE, error));
}

PGP::Ptr PGPMessage::clone() const{
    return std::make_shared <PGPMessage> (*this);
}