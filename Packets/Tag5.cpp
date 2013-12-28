#include "Tag5.h"
Tag5::Tag5(){
    tag = 5;
    s2k_con = 0;
    sym = 0;
    s2k = NULL;
}

Tag5::Tag5(std::string & data){
    tag = 5;
    s2k_con = 0;
    sym = 0;
    s2k = NULL;
    read(data);
}

Tag5::~Tag5(){
    delete s2k;
}

S2K * Tag5::read_s2k(std::string & data){
    S2K * out = NULL;
    uint8_t length = 0;
    if (data[0] == 0){
        out = new S2K0;
        length = 2;
    }
    else if (data[0] == 1){
        out = new S2K1;
        length = 10;
    }
    else if (data[0] == 3){
        out = new S2K3;
        length = 11;
    }
    std::string s2k_str = data.substr(0, length);
    data = data.substr(length, data.size() - length);
    out -> read(s2k_str);
    return out;
}

std::string Tag5::show_common(){
    std::stringstream out;
    if (s2k_con > 253){
        out << "    String-to-Key Usage Conventions: " << (int) s2k_con << "\n"
            << "    Symmetric Key Algorithm: " << Symmetric_Algorithms.at(sym) << " (sym " << (unsigned int) sym << ")\n"
            << "    " << String2Key_Specifiers.at(s2k -> get_type()) << " (s2k " << (int) s2k -> get_type() << "):\n" << s2k -> show();
        if (s2k -> get_type()){
            out << "    IV: " << hexlify(IV) << "\n";
        }
    }

    out << "    Encrypted Data (" << secret.size() << " bytes):\n";
    if (pka < 4)
        out << "        RSA d, p, q, u";
    else if (pka == 16)
        out << "        Elgamal x";
    else if (pka == 17)
        out << "        DSA x";
    out << "\n";

    if (s2k_con == 254){
        out << "        SHA1 hash\n";
    }
    else{
        out << "        2 Octet Checksum\n";
    }

    return out.str();
}

void Tag5::read(std::string & data){
    size = data.size();
    read_tag6(data);
    s2k_con = data[0];
    data = data.substr(1, data.size() - 1);
    if (s2k_con > 253){
        sym = data[0];
        data = data.substr(1, data.size() - 1);
        s2k = read_s2k(data);
    }
    if (s2k_con){
        IV = data.substr(0, Symmetric_Algorithm_Block_Length.at(Symmetric_Algorithms.at(sym)) >> 3);
        data = data.substr(Symmetric_Algorithm_Block_Length.at(Symmetric_Algorithms.at(sym)) >> 3, data.size() - (Symmetric_Algorithm_Block_Length.at(Symmetric_Algorithms.at(sym)) >> 3));
    }
    secret = data;
}

std::string Tag5::show(){
    return show_tag6() + show_common();
}

std::string Tag5::raw(){
    std::string out = raw_tag6() + std::string(1, s2k_con);
    if (s2k_con > 253){
        out += std::string(1, sym) + s2k -> write();
    }
    if (s2k_con){
        out += IV;
    }
    return out + secret;
}

Tag5 * Tag5::clone(){
    Tag5 * out = new Tag5(*this);
    out -> s2k = s2k -> clone();
    return out;
}

uint8_t Tag5::get_s2k_con(){
    return s2k_con;
}

uint8_t Tag5::get_sym(){
    return sym;
}

S2K * Tag5::get_s2k(){
    return s2k;
}

S2K * Tag5::get_s2k_clone(){
    return s2k -> clone();
}

std::string Tag5::get_IV(){
    return IV;
}

std::string Tag5::get_secret(){
    return secret;
}

void Tag5::set_s2k_con(const uint8_t c){
    s2k_con = c;
}

void Tag5::set_sym(const uint8_t s){
    sym = s;
}

void Tag5::set_s2k(S2K * s){
    delete s2k;
    if (s -> get_type() == 0){
        s2k = new S2K0;
    }
    else if (s -> get_type() == 1){
        s2k = new S2K1;
    }
    else if (s -> get_type() == 3){
        s2k = new S2K3;
    }
    s2k = s -> clone();
}

void Tag5::set_IV(const std::string & iv){
    IV = iv;
}

void Tag5::set_secret(const std::string & s){
    secret = s;
}
