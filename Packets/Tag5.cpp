#include "Tag5.h"

Tag5::Tag5(uint8_t tag):
    Tag6(tag),
    s2k_con(0),
    sym(0),
    s2k(),
    IV(),
    secret()
{}

Tag5::Tag5():
    Tag5(5)
{}

Tag5::Tag5(const Tag5 & copy):
    Tag6(copy),
    s2k_con(copy.s2k_con),
    sym(copy.sym),
    s2k(copy.s2k),
    IV(copy.IV),
    secret(copy.secret)
{}

Tag5::Tag5(std::string & data):
    Tag5(5)
{
    read(data);
}

Tag5::~Tag5(){}

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

std::string Tag5::show_private(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    std::stringstream out;
    if (s2k_con > 253){
        out << std::string(tab, ' ') << "    String-to-Key Usage Conventions: " << static_cast <unsigned int> (s2k_con) << "\n"
            << std::string(tab, ' ') << "    Symmetric Key Algorithm: " << Symmetric_Algorithms.at(sym) << " (sym " << static_cast <unsigned int> (sym) << ")\n"
            << std::string(tab, ' ') << s2k -> show(indents);
        if (s2k -> get_type()){
            out << std::string(tab, ' ') << "    IV: " << hexlify(IV);
        }
    }

    out << "\n" << std::string(tab, ' ') << "    Encrypted Data (" << secret.size() << " octets):\n        ";
    if (pka < 4){
        out << std::string(tab, ' ') << "RSA d, p, q, u";
    }
    else if (pka == 16){
        out << std::string(tab, ' ') << "Elgamal x";
    }
    else if (pka == 17){
        out << std::string(tab, ' ') << "DSA x";
    }
    out << std::string(tab, ' ') << " + ";

    if (s2k_con == 254){
        out << std::string(tab, ' ') << "SHA1 hash\n";
    }
    else{
        out << std::string(tab, ' ') << "2 Octet Checksum\n";
    }
    out << std::string(tab, ' ') << "        " << hexlify(secret);
    return out.str();
}

void Tag5::read(std::string & data, const uint8_t part){
    size = data.size();
    read_common(data); // read public stuff
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

std::string Tag5::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    return std::string(tab, ' ') + show_title() + "\n" + show_common(indents, indent_size) + show_private(indents, indent_size);
}

std::string Tag5::raw() const{
    std::string out = raw_common() + std::string(1, s2k_con);
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
    size = raw_common().size() + 1;
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
    size = raw_common().size() + 1;
    if (s2k){
        size += s2k -> write().size();
    }
    if (s2k_con){
        size += IV.size();
    }
    size += secret.size();
}

void Tag5::set_s2k(const S2K::Ptr & s){
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
    size = raw_common().size() + 1;
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
    size = raw_common().size() + 1;
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
    size = raw_common().size() + 1;
    if (s2k){
        size += s2k -> write().size();
    }
    if (s2k_con){
        size += IV.size();
    }
    size += secret.size();
}

Packet::Ptr Tag5::clone() const{
    Ptr out = std::make_shared <Tag5> (*this);
    out -> s2k = s2k -> clone();
    return out;
}

Tag5 & Tag5::operator =(const Tag5 & copy){
    Key::operator =(copy);
    s2k_con = copy.s2k_con;
    sym = copy.sym;
    s2k = copy.s2k -> clone();
    IV = copy.IV;
    secret = copy.secret;
    return *this;
}
