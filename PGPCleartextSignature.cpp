#include "PGPCleartextSignature.h"
PGPCleartextSignature::PGPCleartextSignature():
    Armor_Header(),
    message(),
    sig()
{}

PGPCleartextSignature::PGPCleartextSignature(const PGPCleartextSignature & copy):
    Armor_Header(copy.Armor_Header),
    message(copy.message),
    sig(copy.sig)
{
    sig.set_armored(true);
}

PGPCleartextSignature::PGPCleartextSignature(std::string & data):
    PGPCleartextSignature()
{
    read(data);
}

PGPCleartextSignature::PGPCleartextSignature(std::ifstream & f):
    PGPCleartextSignature()
{
    read(f);
}

void PGPCleartextSignature::read(std::string & data){
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
            std::cerr << "Warning: Unknown ASCII Armor Header Key \"" << header << "\"" << std::endl;
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

    sig.read(data);
}

void PGPCleartextSignature::read(std::ifstream & file){
    std::stringstream s;
    s << file.rdbuf();
    std::string data = s.str();
    read(data);
}

std::string PGPCleartextSignature::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    return std::string(tab, ' ') + "Message:\n" + message + "\n\n" + std::string(tab, ' ') + sig.show(indents, indent_size);
}

std::string PGPCleartextSignature::write(uint8_t header) const{
    std::string out = "-----BEGIN PGP SIGNED MESSAGE-----\n";
    for(std::pair <std::string, std::string> const & k : Armor_Header){
        out += k.first + ": " + k.second + "\n";
    }
    return out + "\n" + message + "\n" + sig.write(header);
}

std::vector <std::pair <std::string, std::string> > PGPCleartextSignature::get_Armor_Header() const{
    return Armor_Header;
}

std::string PGPCleartextSignature::get_message() const{
    return message;
}

PGPDetachedSignature PGPCleartextSignature::get_sig() const{
    return sig;
}

void PGPCleartextSignature::set_Armor_Header(const std::vector <std::pair <std::string, std::string> > & a){
    Armor_Header = a;
}

void PGPCleartextSignature::set_message(const std::string & data){
    message = data;
}

void PGPCleartextSignature::set_sig(const PGPDetachedSignature & s){
    sig = s;
    sig.set_armored(true);
}

PGPCleartextSignature::Ptr PGPCleartextSignature::clone() const{
    PGPCleartextSignature::Ptr out(new PGPCleartextSignature);
    out -> Armor_Header = Armor_Header;
    out -> message = message;
    out -> sig = sig;
    return out;
}

PGPCleartextSignature & PGPCleartextSignature::operator=(const PGPCleartextSignature & copy){
    Armor_Header = copy.Armor_Header;
    message = copy.message;
    sig = copy.sig;
    return *this;
}
