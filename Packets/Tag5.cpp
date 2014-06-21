#include "Tag5.h"

Tag5::Tag5(uint8_t tag) :
    Tag6(tag),
    s2k_con(0),
    sym(0),
    s2k(),
    IV(),
    secret()
{
}

Tag5::Tag5() :
    Tag5(5)
{
}

Tag5::Tag5(const Tag5 & copy) :
    Tag6(copy),
    s2k_con(copy.s2k_con),
    sym(copy.sym),
    s2k(copy.s2k),
    IV(copy.IV),
    secret(copy.secret)
{
}

Tag5::Tag5(std::string & data) :
    Tag5(5)
{
    read(data);
}

Tag5::~Tag5(){
}

void Tag5::read_s2k(std::string & data){
    s2k.reset();
    uint8_t length = 0;
    if (data[0] == 0){
        s2k = std::make_shared<S2K0>();
        length = 2;
    }
    else if (data[0] == 1){
        s2k = std::make_shared<S2K1>();
        length = 10;
    }
    else if (data[0] == 3){
        s2k = std::make_shared<S2K3>();
        length = 11;
    }
    std::string s2k_str = data.substr(0, length);
    data = data.substr(length, data.size() - length);
    s2k -> read(s2k_str);
}

std::string Tag5::show_common() const{
    std::stringstream out;
    if (s2k_con > 253){
        out << "    String-to-Key Usage Conventions: " << static_cast <int> (s2k_con) << "\n"
            << "    Symmetric Key Algorithm: " << Symmetric_Algorithms.at(sym) << " (sym " << static_cast <unsigned int> (sym) << ")\n"
            << "    " << String2Key_Specifiers.at(s2k -> get_type()) << " (s2k " << static_cast <int> (s2k -> get_type()) << "):\n" << s2k -> show();
        if (s2k -> get_type()){
            out << "    IV: " << hexlify(IV) << "\n";
        }
    }

    out << "    Encrypted Data (" << secret.size() << " octets):\n        ";
    if (pka < 4){
        out << "RSA d, p, q, u";
    }
    else if (pka == 16){
        out << "Elgamal x";
    }
    else if (pka == 17){
        out << "DSA x";
    }
    out << " + ";

    if (s2k_con == 254){
        out << "SHA1 hash\n";
    }
    else{
        out << "2 Octet Checksum\n";
    }
    out << "        " << hexlify(secret);
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
        read_s2k(data);
    }
    if (s2k_con){
        IV = data.substr(0, Symmetric_Algorithm_Block_Length.at(Symmetric_Algorithms.at(sym)) >> 3);
        data = data.substr(Symmetric_Algorithm_Block_Length.at(Symmetric_Algorithms.at(sym)) >> 3, data.size() - (Symmetric_Algorithm_Block_Length.at(Symmetric_Algorithms.at(sym)) >> 3));
    }
    secret = data;
}

std::string Tag5::show() const{
    return show_tag6() + show_common();
}

std::string Tag5::raw() const{
    std::string out = raw_tag6() + std::string(1, s2k_con);
    if (s2k_con > 253){
        if (!s2k){
            throw std::runtime_error("Error: S2K has not been set.");
        }
        out += std::string(1, sym) + s2k -> write();
    }
    if (s2k_con){
        out += IV;
    }
    return out + secret;
}

uint8_t Tag5::get_s2k_con() const{
    return s2k_con;
}

uint8_t Tag5::get_sym() const{
    return sym;
}

S2K::Ptr Tag5::get_s2k() const{
    return s2k;
}

S2K::Ptr Tag5::get_s2k_clone() const{
    return s2k -> clone();
}

std::string Tag5::get_IV() const{
    return IV;
}

std::string Tag5::get_secret() const{
    return secret;
}

Tag6 Tag5::get_public_obj() const{
    std::string data = raw();
    Tag6 out(data);
    return out;
}

Tag6::Ptr Tag5::get_public_ptr() const{
    std::string data = raw();
    Tag6::Ptr out(new Tag6(data));
    return out;
}

void Tag5::set_s2k_con(const uint8_t c){
    s2k_con = c;
    size = raw_tag6().size() + 1;
    if (s2k){
        size += s2k -> write().size();
    }
    if (s2k_con){
        size += IV.size();
    }
    size += secret.size();
}

void Tag5::set_sym(const uint8_t s){
    sym = s;
    size = raw_tag6().size() + 1;
    if (s2k){
        size += s2k -> write().size();
    }
    if (s2k_con){
        size += IV.size();
    }
    size += secret.size();
}

void Tag5::set_s2k(S2K::Ptr s){
    if (s -> get_type() == 0){
        s2k = std::make_shared<S2K0>();
    }
    else if (s -> get_type() == 1){
        s2k = std::make_shared<S2K1>();
    }
    else if (s -> get_type() == 3){
        s2k = std::make_shared<S2K3>();
    }
    s2k = s -> clone();
    size = raw_tag6().size() + 1;
    if (s2k){
        size += s2k -> write().size();
    }
    if (s2k_con){
        size += IV.size();
    }
    size += secret.size();
}

void Tag5::set_IV(const std::string & iv){
    IV = iv;
    size = raw_tag6().size() + 1;
    if (s2k){
        size += s2k -> write().size();
    }
    if (s2k_con){
        size += IV.size();
    }
    size += secret.size();
}

void Tag5::set_secret(const std::string & s){
    secret = s;
    size = raw_tag6().size() + 1;
    if (s2k){
        size += s2k -> write().size();
    }
    if (s2k_con){
        size += IV.size();
    }
    size += secret.size();
}

Packet::Ptr Tag5::clone() const{
    Tag5::Ptr out(new Tag5(*this));
    out -> s2k = s2k -> clone();
    return out;
}

Tag5 & Tag5::operator =(const Tag5 & copy){
    Tag6::operator =(copy);
    s2k_con = copy.s2k_con;
    sym = copy.sym;
    s2k = copy.s2k -> clone();
    IV = copy.IV;
    secret = copy.secret;
    return *this;
}
