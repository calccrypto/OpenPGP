#include "PGPCleartextSignature.h"
PGPCleartextSignature::PGPCleartextSignature()
    : Hash_Armor_Header(),
      message(),
      sig()
{}

PGPCleartextSignature::PGPCleartextSignature(const PGPCleartextSignature & copy)
    : Hash_Armor_Header(copy.Hash_Armor_Header),
      message(copy.message),
      sig(copy.sig)
{
    sig.set_armored(true);
}

PGPCleartextSignature::PGPCleartextSignature(const std::string & data)
    : PGPCleartextSignature()
{
    read(data);
}

PGPCleartextSignature::PGPCleartextSignature(std::istream & stream)
    : PGPCleartextSignature()
{
    read(stream);
}

void PGPCleartextSignature::read(const std::string & data){
    std::stringstream s(data);
    read(s);
}

void PGPCleartextSignature::read(std::istream & stream){
    // find cleartext header
    //     - The cleartext header ’-----BEGIN PGP SIGNED MESSAGE-----’ on a
    //       single line,
    std::string line;
    while (std::getline(stream, line) && (line != "-----BEGIN PGP SIGNED MESSAGE-----"));

    if (!stream){
        throw std::runtime_error("Error: Data does not contain message section. Use PGP to parse this data.");
    }

    // read hash armor header(s)
    //     - One or more "Hash" Armor Headers,
    //     - Exactly one empty line not included into the message digest,
    while (std::getline(stream, line) && line.size()){
        std::stringstream s(line);
        std::string key, value;

        if (!(std::getline(s, key, ':') && std::getline(s, value))){
            std::cerr << "Warning: Discarding bad Armor Header: " << line << std::endl;
            continue;
        }

        if (key != "Hash"){
            std::cerr << "Warning: Hash Armor Header Key is not \"HASH\": \"" << key << "\"." << std::endl;
        }

        Hash_Armor_Header.push_back(std::make_pair(key, value));
    }

    // read message
    //     - The dash-escaped cleartext that is included into the message
    //       digest,
    //
    // 7.1. Dash-Escaped Text
    //     The cleartext content of the message must also be dash-escaped.
    //
    //     Dash-escaped cleartext is the ordinary cleartext where every line
    //     starting with a dash ’-’ (0x2D) is prefixed by the sequence dash ’-’
    //     (0x2D) and space ’ ’ (0x20). This prevents the parser from
    //     recognizing armor headers of the cleartext itself. An implementation
    //     MAY dash-escape any line, SHOULD dash-escape lines commencing "From"
    //     followed by a space, and MUST dash-escape any line commencing in a
    //     dash. The message digest is computed using the cleartext itself, not
    //     the dash-escaped form.
    //
    //     As with binary signatures on text documents, a cleartext signature is
    //     calculated on the text using canonical <CR><LF> line endings. The
    //     line ending (i.e., the <CR><LF>) before the ’-----BEGIN PGP
    //     SIGNATURE-----’ line that terminates the signed text is not
    //     considered part of the signed text.
    //
    //     When reversing dash-escaping, an implementation MUST strip the string
    //     "- " if it occurs at the beginning of a line, and SHOULD warn on "-"
    //     and any character other than a space at the beginning of a line.
    //     Also, any trailing whitespace -- spaces (0x20) and tabs (0x09) -- at
    //     the end of any line is removed when the cleartext signature is
    //     generated.
    //
    while (std::getline(stream, line) && (line.substr(0, 29) != "-----BEGIN PGP SIGNATURE-----")){
        if (line[0] == '-'){
            if (line[1] == ' '){
                line = line.substr(2, line.size() - 2);
            }
            else{
                std::cerr << "Warning: \"-" << line[1] << "\" found at the beginning of a line." << std::endl;
            }
        }

        message.push_back(line);
    }

    // read signature into string
    //     - The ASCII armored signature(s) including the ’-----BEGIN PGP
    //       SIGNATURE-----’ Armor Header and Armor Tail Lines.
    std::string ASCII_signature = line + "\n";
    while (std::getline(stream, line) && (line.substr(0, 27) != "-----END PGP SIGNATURE-----")){
        ASCII_signature += line + "\n";
    }
    ASCII_signature += line;

    // parse signature
    sig.read(ASCII_signature);
}

std::string PGPCleartextSignature::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string tab(indents * indent_size, ' ');
    std::string out = tab + "Message:\n";
    for(std::string const & line : message){
        if (line[0] == '-'){
            out += "- ";
        }
        out += line;
    }
    return out + "\n\n" + tab + sig.show(indents, indent_size);
}

std::string PGPCleartextSignature::write(uint8_t header) const{
    std::string out = "-----BEGIN PGP SIGNED MESSAGE-----\n";

    // write Armor Header
    for(std::pair <std::string, std::string> const & k : Hash_Armor_Header){
        out += k.first + ": " + k.second + "\n";
    }

    // one empty line
    out += "\n";

    // dash escaped text
    for(std::string const & line : message){
        if (line[0] == '-'){
           out += "- ";
        }
        out += line + "\n";
    }

    return out + "\n" + sig.write(header);
}

std::vector <std::pair <std::string, std::string> > PGPCleartextSignature::get_Hash_Armor_Header() const{
    return Hash_Armor_Header;
}

std::vector <std::string> PGPCleartextSignature::get_message() const{
    return message;
}

std::string PGPCleartextSignature::get_canonical_message() const{
    std::string out = "";
    for(std::string const & line : message){
        // find trailing whitespace
        std::string::size_type i = line.size();
        while ((i > 0) && std::isspace(line[i - 1])){
            i--;
        }

        // remove trailing whitespace and append <CR><LF>
        out += line.substr(0, i) + "\r\n";
    }

    return out.substr(0, out.size() - 2);   // remove extra trailing <CR><LF>
}

PGPDetachedSignature PGPCleartextSignature::get_sig() const{
    return sig;
}

void PGPCleartextSignature::set_Hash_Armor_Header(const std::vector <std::pair <std::string, std::string> > & a){
    Hash_Armor_Header = a;
}

void PGPCleartextSignature::set_message(const std::vector <std::string> & data){
    message = data;
}

void PGPCleartextSignature::set_message(const std::string & data){
    message.clear();

    std::stringstream s(data);
    std::string line;
    while (std::getline(s, line)){
        message.push_back(line);
    }
}

void PGPCleartextSignature::set_sig(const PGPDetachedSignature & s){
    sig = s;
    sig.set_armored(true);
}

PGPCleartextSignature::Ptr PGPCleartextSignature::clone() const{
    PGPCleartextSignature::Ptr out = std::make_shared <PGPCleartextSignature> ();
    out -> Hash_Armor_Header = Hash_Armor_Header;
    out -> message = message;
    out -> sig = sig;
    return out;
}

PGPCleartextSignature & PGPCleartextSignature::operator=(const PGPCleartextSignature & copy){
    Hash_Armor_Header = copy.Hash_Armor_Header;
    message = copy.message;
    sig = copy.sig;
    return *this;
}
