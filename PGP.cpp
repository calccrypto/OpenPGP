#include "PGP.h"

std::string PGP::format_string(std::string data, uint8_t line_length) const{
    std::string out = "";
    for(unsigned int i = 0; i < data.size(); i += line_length){
        out += data.substr(i, line_length) + "\n";
    }
    return out;
}

PGP::PGP()
    : armored(true),
      ASCII_Armor(static_cast <uint8_t> (-1)),
      Armor_Header(),
      packets()
{}

PGP::PGP(const PGP & copy)
    : armored(copy.armored),
      ASCII_Armor(copy.ASCII_Armor),
      Armor_Header(copy.Armor_Header),
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
    //
    std::string line;
    while (std::getline(stream, line) && line.substr(0, 15) != "-----BEGIN PGP ");

    // if no armor header found, assume entire stream is key
    if (!stream){
        stream.clear();
        stream.seekg(stream.beg);

        // parse entire stream
        read_raw(stream);

        armored = false;
    }
    else{
        // parse armor header
        uint8_t new_ASCII_Armor;
        for(new_ASCII_Armor = 0; new_ASCII_Armor < 7; new_ASCII_Armor++){
            if (("-----BEGIN PGP " + ASCII_Armor_Header[new_ASCII_Armor] + "-----") == line){
                break;
            }
        }

        // Cleartext Signature Framework
        if (new_ASCII_Armor == 6){
            throw std::runtime_error("Error: Data contains message section. Use PGPCleartextSignature to parse this data.");
        }

        // if ASCII Armor was set before calling read()
        if (ASCII_Armor != static_cast <uint8_t> (-1)){
            if (ASCII_Armor != new_ASCII_Armor){
                std::cerr << "Warning: ASCII Armor does not match data type: " << (int) new_ASCII_Armor << std::endl;
            }
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

            Armor_Header.push_back(std::make_pair(key, value));
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
    std::string out = "-----BEGIN PGP " + ASCII_Armor_Header[ASCII_Armor] + "-----\n";
    for(std::pair <std::string, std::string> const & key : Armor_Header){
        out += key.first + ": " + key.second + "\n";
    }
    out += "\n";
    return out + format_string(ascii2radix64(packet_string), MAX_LINE_LENGTH) + "=" + ascii2radix64(unhexlify(makehex(crc24(packet_string), 6))) +  "\n-----END PGP " + ASCII_Armor_Header[ASCII_Armor] + "-----\n";
}

bool PGP::get_armored() const{
    return armored;
}

uint8_t PGP::get_ASCII_Armor() const{
    return ASCII_Armor;
}

PGP::Armor_Header_T PGP::get_Armor_Header() const{
    return Armor_Header;
}

PGP::Packet_T PGP::get_packets() const{
    return packets;
}

PGP::Packet_T PGP::get_packets_clone() const{
    std::vector <Packet::Ptr> out;
    for(Packet::Ptr const & p : packets){
        out.push_back(p -> clone());
    }
    return out;
}

void PGP::set_armored(const bool a){
    armored = a;
}

void PGP::set_ASCII_Armor(const uint8_t armor){
    ASCII_Armor = armor;
    armored = true;
}

void PGP::set_Armor_Header(const PGP::Armor_Header_T & header){
    Armor_Header = header;
}

void PGP::set_packets(const PGP::Packet_T & p){
    packets.clear();
    for(Packet::Ptr const & t : p){
        packets.push_back(t -> clone());
    }
}

PGP & PGP::operator=(const PGP & copy){
    armored = copy.armored;
    ASCII_Armor = copy.ASCII_Armor;
    Armor_Header = copy.Armor_Header;
    packets = copy.get_packets_clone();
    return *this;
}