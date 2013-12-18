#include "OpenPGP.h"

std::string PGP::format_string(std::string data, uint8_t line_length){
    std::string out = "";
    for(unsigned int i = 0; i < data.size(); i += line_length){
        out += data.substr(i, line_length) + "\n";
    }
    return out;
}

PGP::PGP(){
    armored = false;
}

PGP::PGP(std::string & data){
    armored = true;
    read(data);
}

PGP::PGP(std::ifstream & f){
    armored = true;
    read(f);
}

PGP::PGP(const PGP & pgp){
    ASCII_Armor = pgp.ASCII_Armor;
    Armor_Header = pgp.Armor_Header;
    for(Packet * p : pgp.packets){
        packets.push_back(p -> clone());
    }
}

PGP::~PGP(){
    for(Packet *& p : packets){
        delete p;
    }
}

void PGP::read(std::string & data){
    std::string copy = data;

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

    for(x = 0; x < 7; x++){
        std::string match = "-----BEGIN PGP " + ASCII_Armor_Header[x] + "-----";
        if (match == data.substr(0, match.size())){
            break;
        }
    }

    if (x == 7){
        std::cerr << "Warning: Beginning of Armor Header Line not found. Will attempt to read raw data" << std::endl;
        read_raw(copy);
        return;
    }

    if (x == 6){
        std::cerr << "Error: Data contains message section. Use PGPMessage to parse this data" << std::endl;
        exit(1);
    }

    ASCII_Armor = x;

    // remove newline after header
    x = 0;
    while ((x < data.size()) && data.substr(x, 1) != "\n"){
        x++;
    }
    if (x == data.size()){
        std::cerr << "Error: End to Armor Header Line not found" << std::endl;
        exit(1);
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
            std::cout << "Warning: Unknown ASCII Armor Header Key \x22" << header << "\x22" << std::endl;
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
            std::cout << "Warning: Given checksum does not match calculated value" << std::endl;
        }
    }
    else
        data = radix642ascii(data);
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
    uint8_t tag;
    bool format;
    while (data.size()){
        std::string packet_data = read_packet_header(data, tag, format);
        Packet * temp = read_packet(tag, packet_data);
        temp -> set_format(format);
        packets.push_back(temp);
    }
    armored = false;
}

std::string PGP::show(){
    std::stringstream out;
    for(Packet *& p : packets){
        out << (p -> get_format()?"New":"Old")  << ": " << Packet_Tags.at(p -> get_tag()) << " (Tag " << (int) p -> get_tag() << ") (" << p -> get_size() << " bytes)\n" + p -> show() << "\n";
    }
    return out.str();
}

std::string PGP::raw(){
    std::string out = "";
    for(Packet *& p : packets){
        out += p -> write();
    }
    return out;
}

std::string PGP::write(){
    std::string out = "-----BEGIN PGP " + ASCII_Armor_Header[ASCII_Armor] + "-----\n";
    for(std::pair <std::string, std::string> & key : Armor_Header){
        out += key.first + ": " + key.second + "\n";
    }
    out += "\n";
    std::string packet_string = raw();
    return out + format_string(ascii2radix64(packet_string), MAX_LINE_LENGTH) + "=" + ascii2radix64(unhexlify(makehex(crc24(packet_string), 6))) +  "\n-----END PGP " + ASCII_Armor_Header[ASCII_Armor] + "-----\n";
}

PGP PGP::copy(){
    PGP out;
    out.ASCII_Armor = ASCII_Armor;
    out.Armor_Header = Armor_Header;
    out.packets = get_packets_copy();
    return out;
}

PGP * PGP::clone(){
    PGP * out = new PGP;
    out -> ASCII_Armor = ASCII_Armor;
    out -> Armor_Header = Armor_Header;
    out -> packets = get_packets_copy();
    return out;
}

uint8_t PGP::get_ASCII_Armor(){
    return ASCII_Armor;
}

std::vector <std::pair <std::string, std::string> > PGP::get_Armor_Header(){
    return Armor_Header;
}

std::vector <Packet *> PGP::get_packets_pointers(){
    return packets;
}

std::vector <Packet *> PGP::get_packets_copy(){
    std::vector <Packet *> out;
    for(Packet *& p : packets){
        out.push_back(p -> clone());
    }
    return out;
}

void PGP::set_ASCII_Armor(uint8_t armor){
    ASCII_Armor = armor;
    armored = true;
}

void PGP::set_Armor_Header(const std::vector <std::pair <std::string, std::string> > header){
    Armor_Header = header;
}

void PGP::set_packets(std::vector <Packet *> p){
    for(Packet *& t : packets){
        delete t;
    }
    packets.clear();
    for(Packet *& t : p){
        packets.push_back(t -> clone());
    }
}

std::string PGP::keyid(){
    if ((ASCII_Armor == 1) ||
        (ASCII_Armor == 2)){
        for(Packet *& p : packets){
            // find primary key
            if ((p -> get_tag() == 5) || (p -> get_tag() == 6)){
                std::string data = p -> raw();
                Tag6 tag6(data);
                return tag6.get_keyid();
            }
        }
        // if no primary key is found
        for(Packet *& p : packets){
            // find subkey
            if ((p -> get_tag() == 7) || (p -> get_tag() == 14)){
                std::string data = p -> raw();
                Tag6 tag6(data);
                return tag6.get_keyid();
            }
        }
    }
    return "";
}

// output is copied from gpg --list-keys
std::string PGP::list_keys(){
    if ((ASCII_Armor == 1) ||
        (ASCII_Armor == 2)){
        std::stringstream out;
        for(Packet *& p : packets){
            std::string data = p -> raw();
            switch (p -> get_tag()){
                case 5: case 6: case 7: case 14:
                    {
                        Tag6 tag6(data);
                        std::stringstream size;
                        size << makebin(tag6.get_mpi()[0]).size();
                        out << Public_Key_Type.at(p -> get_tag()) << "    " << zfill(size.str(), 4, " ")
                               << Public_Key_Algorithm_Short.at(tag6.get_pka()) << "/"
                               << hexlify(tag6.get_keyid().substr(4, 4)) << " "
                               << show_date(tag6.get_time()) << "\n";
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
                        std::vector <Subpacket *> subpackets = tag17.get_attributes_pointers();
                        for(Subpacket * s : subpackets){
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
        std::cerr << "Error: Not a PGP Key. Cannot Display" << std::endl;
        exit(1);
    }
}

PGPMessage::PGPMessage(){}

PGPMessage::PGPMessage(std::string & data){
    read(data);
}

PGPMessage::PGPMessage(std::ifstream & f){
    read(f);
}

PGPMessage::~PGPMessage(){}

void PGPMessage::read(std::string & data){
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

    if (data.substr(0, 34) != "-----BEGIN PGP SIGNED MESSAGE-----"){
        std::cerr << "Error: Data does not contain message section. Use PGP to parse this data" << std::endl;
        exit(1);
    }

    ASCII_Armor = 6;

    // remove newline after header
    x = 0;
    while ((x < data.size()) && data.substr(x, 1) != "\n"){
        x++;
    }
    if (x == data.size()){
        std::cerr << "Error: End to Armor Header Line not found" << std::endl;
        exit(1);
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
            std::cout << "Warning: Unknown ASCII Armor Header Key \x22" << header << "\x22" << std::endl;
        }

        x++;
        header_keys = header_keys.substr(x, header_keys.size() - x);
    }

    x = 0;
    while ((x < data.size()) && (data.substr(x, 15) != "-----BEGIN PGP ")){
        x++;
    }

    message = data.substr(0, x - 1); // get rid of last newline after text
    data = data.substr(x, data.size() - x);

    key.read(data);
}

void PGPMessage::read(std::ifstream & file){
    std::stringstream s;
    s << file.rdbuf();
    std::string data = s.str();
    read(data);
}

std::string PGPMessage::show(){
    return "Message:\n" + message + "\n\n" + key.show();
}

std::string PGPMessage::write(){
    std::string out = "-----BEGIN PGP " + ASCII_Armor_Header[ASCII_Armor] + "-----\n";
    for(std::pair <std::string, std::string> & k : Armor_Header){
        out += k.first + ":" + k.second + "\n";
    }
    return out + "\n" + message + key.write();
}

uint8_t PGPMessage::get_ASCII_Armor(){
    return ASCII_Armor;
}

std::vector <std::pair <std::string, std::string> > PGPMessage::get_Armor_Header(){
    return Armor_Header;
}

std::string PGPMessage::get_message(){
    return message;
}

PGP PGPMessage::get_key(){
    return key.copy();
}

void PGPMessage::set_ASCII_Armor(uint8_t a){
    ASCII_Armor = a;
}

void PGPMessage::set_Armor_Heder(std::vector <std::pair <std::string, std::string> > & a){
    Armor_Header = a;
}

void PGPMessage::set_message(std::string & data){
    message = data;
}

void PGPMessage::set_key(PGP & k){
    key = k;
}

std::ostream & operator<<(std::ostream & stream, PGP & pgp){
    stream << hexlify(pgp.keyid());
    return stream;
}
