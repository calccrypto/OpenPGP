#include "PGPSignedMessage.h"
PGPSignedMessage::PGPSignedMessage() :
    ASCII_Armor(),
    Armor_Header(),
    message(),
    key()
{
}

PGPSignedMessage::PGPSignedMessage(const PGPSignedMessage & copy) :
    ASCII_Armor(copy.ASCII_Armor),
    Armor_Header(copy.Armor_Header),
    message(copy.message),
    key(copy.key)
{
    key.set_armored(true);
}

PGPSignedMessage::PGPSignedMessage(std::string & data) :
    PGPSignedMessage()
{
    read(data);
}

PGPSignedMessage::PGPSignedMessage(std::ifstream & f) :
    PGPSignedMessage()
{
    read(f);
}

void PGPSignedMessage::read(std::string & data){
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
        throw std::runtime_error("Error: Data does not contain message section. Use PGP to parse this data.");
    }

    ASCII_Armor = 6;

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
            std::cerr << "Warning: Unknown ASCII Armor Header Key \x22" << header << "\x22" << std::endl;
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

void PGPSignedMessage::read(std::ifstream & file){
    std::stringstream s;
    s << file.rdbuf();
    std::string data = s.str();
    read(data);
}

std::string PGPSignedMessage::show() const{
    return "Message:\n" + message + "\n\n" + key.show();
}

std::string PGPSignedMessage::write(uint8_t header) const{
    std::string out = "-----BEGIN PGP " + ASCII_Armor_Header[ASCII_Armor] + "-----\n";
    for(std::pair <std::string, std::string> const & k : Armor_Header){
        out += k.first + ":" + k.second + "\n";
    }
    return out + "\n" + message + "\n" + key.write(header);
}

uint8_t PGPSignedMessage::get_ASCII_Armor() const{
    return ASCII_Armor;
}

std::vector <std::pair <std::string, std::string> > PGPSignedMessage::get_Armor_Header() const{
    return Armor_Header;
}

std::string PGPSignedMessage::get_message() const{
    return message;
}

PGP PGPSignedMessage::get_key() const{
    return key;
}

void PGPSignedMessage::set_ASCII_Armor(const uint8_t a){
    ASCII_Armor = a;
}

void PGPSignedMessage::set_Armor_Header(const std::vector <std::pair <std::string, std::string> > & a){
    Armor_Header = a;
}

void PGPSignedMessage::set_message(const std::string & data){
    message = data;
}

void PGPSignedMessage::set_key(const PGP & k){
    key = k;
    key.set_armored(true);
}

PGPSignedMessage::Ptr PGPSignedMessage::clone() const{
    Ptr out(new PGPSignedMessage);
    out -> ASCII_Armor = ASCII_Armor;
    out -> Armor_Header = Armor_Header;
    out -> message = message;
    out -> key = key;
    return out;
}

PGPSignedMessage & PGPSignedMessage::operator=(const PGPSignedMessage & copy){
    ASCII_Armor = copy.ASCII_Armor;
    Armor_Header = copy.Armor_Header;
    message = copy.message;
    key = copy.key;
    return *this;
}
