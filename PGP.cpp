#include "PGP.h"

std::string PGP::format_string(std::string data, uint8_t line_length){
    std::string out = "";
    for(unsigned int i = 0; i < data.size(); i += line_length){
        out += data.substr(i, line_length) + "\n";
    }
    return out;
}

PGP::PGP(){
    armored = true;
}

PGP::PGP(const PGP & pgp){
    armored = pgp.armored;
    ASCII_Armor = pgp.ASCII_Armor;
    Armor_Header = pgp.Armor_Header;
    for(Packet::Ptr const & p : pgp.packets){
        packets.push_back(p -> clone());
    }
}

PGP::PGP(std::string & data){
    armored = true;
    read(data);
}

PGP::PGP(std::ifstream & f){
    armored = true;
    read(f);
}

PGP::~PGP(){
    packets.clear();
}

void PGP::read(std::string & data){
    std::string ori = data;

    // remove extra data and parse unsecured data
    unsigned int x = 0;

    // find and remove header
    while ((x < data.size()) && (data.substr(x, 15) != "-----BEGIN PGP ")){
        x++;
    }
    data = data.substr(x, data.size() - x);

    // remove carriage returns
    unsigned int y = 0;
    while (y < data.size()){
        if (data[y] == '\r'){
            data.replace(y, 1, "");
        }
        else{
            y++;
        }
    }

    // find type of PGP block
    for(x = 0; x < 7; x++){
        std::string match = "-----BEGIN PGP " + ASCII_Armor_Header[x] + "-----";
        if (match == data.substr(0, match.size())){
            break;
        }
    }

    // no ASCII Armor header found
    if (x == 7){
        std::cerr << "Warning: Beginning of Armor Header Line not found. Will attempt to read raw file data." << std::endl;
        read_raw(ori);
        return;
    }

    // Signed message
    if (x == 6){
        throw std::runtime_error("Error: Data contains message section. Use PGPMessage to parse this data.");
    }

    ASCII_Armor = x;

    // remove newline after header
    x = 0;
    while ((x < data.size()) && data.substr(x, 1) != "\n"){
        x++;
    }
    if (x == data.size()){
        throw std::runtime_error("Error: End to Armor Header Line not found.");
            }

    data = data.substr(x + 1, data.size() - x - 1);

    // find header keys
    x = 0;
    while ((x < data.size()) && (data.substr(x, 2) != "\n\n")){
        x++;
    }

    std::string header_keys = data.substr(0, (++x)++);

    // remove header keys + empty line
    data = data.substr(x, data.size() - x);

    // parse Armor Key
    while (header_keys.size()){
        x = 6;
        while ((x < header_keys.size()) && (header_keys[x] != '\n')){
            x++;
        }

        // find colon ':'
        unsigned int y = 0;
        while (header_keys[y] != ':') y++;
        std::string header = header_keys.substr(0, y);

        Armor_Header.push_back(std::pair <std::string, std::string>(header, header_keys.substr(y + 1, x - y - 1)));

        bool found = false;
        for(unsigned int i = 0; i < 5; i++){
            if (header == ASCII_Armor_Key[i]){
                found = true;
                break;
            }
        }

        if (!found){
            std::cerr << "Warning: Unknown ASCII Armor Header Key \x22" << header << "\x22." << std::endl;
        }

        x++;
        header_keys = header_keys.substr(x, header_keys.size() - x);
    }

    // remove tail
    x = 0;
    while ((x < data.size()) && (data.substr(x, 13) != "-----END PGP ")){
        x++;
    }
    data = data.substr(0, x);

    // remove newlines
    y = 0;
    while (y < data.size()){
        if (data[y] == '\n'){
            data.replace(y, 1, "");
        }
        else{
            y++;
        }
    }

    // check for a checksum
    if (data[data.size() - 5] == '='){
        uint32_t checksum = toint(radix642ascii(data.substr(data.size() - 4, 4)), 256);
        data = radix642ascii(data.substr(0, data.size() - 5));
        // check if the checksum is correct
        if (crc24(data) != checksum){
            std::cerr << "Warning: Given checksum does not match calculated value." << std::endl;
        }
    }
    else{
        data = radix642ascii(data);
        std::cerr << "Warning: No checksum found." << std::endl;
    }
    // //////////////////////////////////////////////////////////////////////////////////////////
    read_raw(data);
    armored = true;
}

void PGP::read(std::ifstream & file){
    std::stringstream s;
    s << file.rdbuf();
    std::string data = s.str();
    read(data);
}

void PGP::read_raw(std::string & data){
    while (data.size()){
        Packet::Ptr temp = read_packet(data);
        packets.push_back(temp);
    }
    armored = false;
}

std::string PGP::show(){
    std::stringstream out;
    for(Packet::Ptr & p : packets){
        out << (p -> get_format()?"New":"Old")  << ": ";
        try{// defined packets have name and tag number
            out << Packet_Tags.at(p -> get_tag()) << " (Tag " << static_cast <int> (p -> get_tag()) << ")";
        }
        catch (const std::out_of_range & e){}// catch out of range error for const std::map
        out << "(" << p -> get_size() << " octets)\n" + p -> show() << "\n";
    }
    return out.str();
}

std::string PGP::raw(uint8_t header){
    std::string out = "";
    for(Packet::Ptr & p : packets){
        out += p -> write(header);
    }
    return out;
}

std::string PGP::write(uint8_t header){
    std::string packet_string = raw(header);
    if (!armored){
        return packet_string;
    }
    std::string out = "-----BEGIN PGP " + ASCII_Armor_Header[ASCII_Armor] + "-----\n";
    for(std::pair <std::string, std::string> & key : Armor_Header){
        out += key.first + ": " + key.second + "\n";
    }
    out += "\n";
    return out + format_string(ascii2radix64(packet_string), MAX_LINE_LENGTH) + "=" + ascii2radix64(unhexlify(makehex(crc24(packet_string), 6))) +  "\n-----END PGP " + ASCII_Armor_Header[ASCII_Armor] + "-----\n";
}

bool PGP::get_armored(){
    return armored;
}

uint8_t PGP::get_ASCII_Armor(){
    return ASCII_Armor;
}

std::vector <std::pair <std::string, std::string> > PGP::get_Armor_Header(){
    return Armor_Header;
}

std::vector <Packet::Ptr> PGP::get_packets(){
    return packets;
}

std::vector <Packet::Ptr> PGP::get_packets_clone(){
    std::vector <Packet::Ptr> out;
    for(Packet::Ptr & p : packets){
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

void PGP::set_Armor_Header(const std::vector <std::pair <std::string, std::string> > & header){
    Armor_Header = header;
}

void PGP::set_packets(const std::vector <Packet::Ptr> & p){
    packets.clear();
    for(Packet::Ptr const & t : p){
        packets.push_back(t -> clone());
    }
}

std::string PGP::keyid(){
    if ((ASCII_Armor == 1) || (ASCII_Armor == 2)){
        for(Packet::Ptr & p : packets){
            // find primary key
            if ((p -> get_tag() == 5) || (p -> get_tag() == 6)){
                std::string data = p -> raw();
                Tag6 tag6(data);
                return tag6.get_keyid();
            }
        }
        // if no primary key is found
        for(Packet::Ptr & p : packets){
            // find subkey
            if ((p -> get_tag() == 7) || (p -> get_tag() == 14)){
                std::string data = p -> raw();
                Tag6 tag6(data);
                return tag6.get_keyid();
            }
        }
    }
    else{
        throw std::runtime_error("Error: PGP block type is incorrect.");
    }
    return ""; // should never reach here; mainly just to remove compiler warnings
}

// output is copied from gpg --list-keys
std::string PGP::list_keys(){
    if ((ASCII_Armor == 1) || (ASCII_Armor == 2)){
        // scan for revoked keys
        std::map <std::string, std::string> revoked;
        for(Packet::Ptr & p : packets){
            if (p -> get_tag() == 2){
                std::string raw = p -> raw();
                Tag2 tag2(raw);
                if ((tag2.get_type() == 0x20) || (tag2.get_type() == 0x28)){
                    bool found = false;
                    for(Subpacket::Ptr & s : tag2.get_unhashed_subpackets()){
                        if (s -> get_type() == 16){
                            raw = s -> raw();
                            Tag2Sub16 tag2sub16(raw);
                            revoked[tag2sub16.get_keyid()] = show_date(tag2.get_time());
                            found = true;
                        }
                    }
                    if (!found){
                        for(Subpacket::Ptr & s : tag2.get_hashed_subpackets()){
                            if (s -> get_type() == 16){
                                raw = s -> raw();
                                Tag2Sub16 tag2sub16(raw);
                                revoked[tag2sub16.get_keyid()] = show_date(tag2.get_time());
                                found = true;
                            }
                        }
                    }
                }
            }
        }

        std::stringstream out;
        for(Packet::Ptr & p : packets){
            std::string data = p -> raw();
            switch (p -> get_tag()){
                case 5: case 6: case 7: case 14:
                    {
                        Tag6 tag6(data);
                        std::map <std::string, std::string>::iterator r = revoked.find(tag6.get_keyid());
                        std::stringstream s;
                        s << tag6.get_mpi()[0].get_str(2).size();
                        out << Public_Key_Type.at(p -> get_tag()) << "    " << zfill(s.str(), 4, " ")
                               << Public_Key_Algorithm_Short.at(tag6.get_pka()) << "/"
                               << hexlify(tag6.get_keyid().substr(4, 4)) << " "
                               << show_date(tag6.get_time())
                               << ((r == revoked.end())?std::string(""):(std::string(" [revoked: ") + revoked[tag6.get_keyid()] + std::string("]")))
                               << "\n";
                    }
                    break;
                case 13:
                    {
                        Tag13 tag13(data);
                        out << "uid                   " << tag13.raw() << "\n";
                    }
                    break;
                case 17:
                    {
                        Tag17 tag17(data);
                        std::vector <Subpacket::Ptr> subpackets = tag17.get_attributes();
                        for(Subpacket::Ptr s : subpackets){
                            // since only subpacket type 1 is defined
                            data = s -> raw();
                            Tag17Sub1 sub1(data);
                            out << "att                   [jpeg image of size " << sub1.get_image().size() << "]\n";
                        }
                    }
                    break;
                case 2: default:
                    break;
            }
        }
        return out.str();
    }
    else{
        throw std::runtime_error("Error: Not a PGP Key. Cannot Display.");
    }
}

PGP::Ptr PGP::clone(){
    PGP::Ptr out(new PGP);
    out -> ASCII_Armor = ASCII_Armor;
    out -> Armor_Header = Armor_Header;
    out -> packets = get_packets_clone();
    return out;
}

PGP PGP::operator=(const PGP & pgp){
    ASCII_Armor = pgp.ASCII_Armor;
    Armor_Header = pgp.Armor_Header;
    for(Packet::Ptr const & p : pgp.packets){
        packets.push_back(p -> clone());
    }
    return *this;
}

std::ostream & operator<<(std::ostream & stream, PGP & pgp){
    stream << hexlify(pgp.keyid());
    return stream;
}
