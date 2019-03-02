#include "CleartextSignature.h"

#include "Misc/sigcalc.h"
#include "common/includes.h"

namespace OpenPGP {

CleartextSignature::CleartextSignature()
    : hash_armor_header(),
      message(),
      sig()
{}

CleartextSignature::CleartextSignature(const CleartextSignature & copy)
    : hash_armor_header(copy.hash_armor_header),
      message(copy.message),
      sig(copy.sig)
{
    sig.set_armored(PGP::Armored::YES);
}

CleartextSignature::CleartextSignature(const std::string & data)
    : CleartextSignature()
{
    read(data);

    // warn if packet sequence is not meaningful
    if (!meaningful()){
        throw std::runtime_error("Error: Data does not form a meaningful PGP Cleartext Signature");
    }
}

CleartextSignature::CleartextSignature(std::istream & stream)
    : CleartextSignature()
{
    read(stream);

    // warn if packet sequence is not meaningful
    if (!meaningful()){
        throw std::runtime_error("Error: Data does not form a meaningful PGP Cleartext Signature");
    }
}

void CleartextSignature::read(const std::string & data){
    std::stringstream s(data);
    read(s);
}

void CleartextSignature::read(std::istream & stream){
    // find cleartext header
    //     - The cleartext header ’-----BEGIN PGP SIGNED MESSAGE-----’ on a
    //       single line,
    static const std::string BEGIN_PGP_SIGNED_MESSAGE = PGP::ASCII_Armor_Begin + PGP::ASCII_Armor_Header[PGP::SIGNED_MESSAGE] + PGP::ASCII_Armor_5_Dashes;
    std::string line;
    while (std::getline(stream, line)){
        // get rid of trailing whitespace
        line = trim_whitespace(line, false, true);

        if (line.substr(0, BEGIN_PGP_SIGNED_MESSAGE.size()) == BEGIN_PGP_SIGNED_MESSAGE) {
            break;
        }
    }

    if (!stream){
        throw std::runtime_error("Error: Data does not contain message section. Use PGP to parse this data.");
    }

    // read hash armor header(s)
    //     - One or more "Hash" Armor Headers,
    //     - Exactly one empty line not included into the message digest,
    while (std::getline(stream, line) && line.size()){
        // get rid of trailing whitespace
        line = trim_whitespace(line, false, true);

        // if now there is nothing, stop
        if (!line.size()) {
            break;
        }

        std::stringstream s(line);
        std::string key, value;

        if (!(std::getline(s, key, ':') && std::getline(s, value))){
            std::cerr << "Warning: Discarding bad Armor Header: " << line << std::endl;
            continue;
        }

        if (key != "Hash"){
            std::cerr << "Warning: Hash Armor Header Key is not \"HASH\": \"" << key << "\"." << std::endl;
        }

        hash_armor_header.push_back(PGP::Armor_Key(key, value));
    }

    // read message
    //     - The dash-escaped cleartext that is included into the message
    //       digest,
    //
    static const std::string BEGIN_PGP_SIGNATURE = PGP::ASCII_Armor_Begin + PGP::ASCII_Armor_Header[PGP::SIGNATURE] + PGP::ASCII_Armor_5_Dashes;
    message = "";
    while (std::getline(stream, line)){
        // get rid of trailing whitespace
        line = trim_whitespace(line, false, true);

        if (line.substr(0, BEGIN_PGP_SIGNATURE.size()) == BEGIN_PGP_SIGNATURE){
            break;
        }

        message += line + "\n";
    }
    message = reverse_dash_escape(message.substr(0, message.size() - 1));

    // read signature into string
    //     - The ASCII armored signature(s) including the ’-----BEGIN PGP
    //       SIGNATURE-----’ Armor Header and Armor Tail Lines.
    static const std::string END_PGP_SIGNATURE = PGP::ASCII_Armor_End + PGP::ASCII_Armor_Header[PGP::SIGNATURE] + PGP::ASCII_Armor_5_Dashes;
    std::string ASCII_signature = line + "\n";
    while (std::getline(stream, line)){
        // get rid of trailing whitespace
        line = trim_whitespace(line, false, true);

        if (line.substr(0, END_PGP_SIGNATURE.size()) == END_PGP_SIGNATURE){
            break;
        }

        ASCII_signature += line + "\n";
    }
    ASCII_signature += line; // add the "-----END PGP SIGNATURE-----" back in

    // parse signature
    sig.read(ASCII_signature);
}

std::string CleartextSignature::show(const std::size_t indents, const std::size_t indent_size) const{
    return std::string(indents * indent_size, ' ') +
           "Message:\n"                            +
           dash_escape(message)                    +
           "Signature:\n"                          +
           sig.show(indents + 1, indent_size);
}

std::string CleartextSignature::write() const{
    static const std::string BEGIN_PGP_SIGNED_MESSAGE = PGP::ASCII_Armor_Begin + PGP::ASCII_Armor_Header[PGP::SIGNED_MESSAGE] + PGP::ASCII_Armor_5_Dashes;
    std::string out = BEGIN_PGP_SIGNED_MESSAGE + "\n";

    // write Armor Header
    for(PGP::Armor_Key const & k : hash_armor_header){
        out += k.first + ": " + k.second + "\n";
    }

    // one empty line
    out += "\n";

    // only add "- " to front of message
    out += dash_escape(message);

    return out + "\n" + sig.write(PGP::Armored::YES);
}

PGP::Armor_Keys CleartextSignature::get_hash_armor_header() const{
    return hash_armor_header;
}

std::string CleartextSignature::get_message() const{
    return message;
}

DetachedSignature CleartextSignature::get_sig() const{
    return sig;
}

void CleartextSignature::set_hash_armor_header(const PGP::Armor_Keys & keys){
    hash_armor_header = keys;
}

void CleartextSignature::set_message(const std::string & data){
    message = data;
}

void CleartextSignature::set_sig(const DetachedSignature & s){
    sig = s;
    sig.set_armored(PGP::Armored::YES);
}

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
std::string CleartextSignature::dash_escape(const std::string & text){
    std::string out = "";

    std::stringstream s(text);
    std::string line;
    while (std::getline(s, line)){
        if (line.size() && line[0] == '-'){
            out += "- ";
        }
        out += line + "\n";
    }

    return out.substr(0, out.size() - 1);
}

std::string CleartextSignature::reverse_dash_escape(const std::string & text){
    std::string out = "";

    std::stringstream s(text);
    std::string line;
    while (std::getline(s, line)){
        if (line.substr(0, 2) == "- "){
            out += line.substr(2, line.size() - 2);
        }
        else{
            out += line;
        }
        out += "\n";
    }

    return out.substr(0, out.size() - 1);
}

std::string CleartextSignature::data_to_text() const{
    return data_to_text(message);
}

std::string CleartextSignature::data_to_text(const std::string & text){
    std::string out = "";

    std::stringstream s(text);
    std::string line;
    while (std::getline(s, line)){
        // remove trailing whitespace
        std::string::size_type i = line.size();
        while (i && ((line[i - 1] == ' ') || (line[i - 1] == '\t'))){
            i--;
        }
        out += line.substr(0, i) + "\n";
    }

    return out.substr(0, out.size() - 1);
}

bool CleartextSignature::meaningful() const{
    return sig.meaningful();
}

CleartextSignature & CleartextSignature::operator=(const CleartextSignature & copy){
    hash_armor_header = copy.hash_armor_header;
    message = copy.message;
    sig = copy.sig;
    return *this;
}

CleartextSignature::Ptr CleartextSignature::clone() const{
    CleartextSignature::Ptr out = std::make_shared <CleartextSignature> ();
    out -> hash_armor_header = hash_armor_header;
    out -> message = message;
    out -> sig = sig;
    return out;
}

}
