#include "Tag3.h"

Tag3::Tag3()
    : Packet(Packet::ID::Symmetric_Key_Encrypted_Session_Key, 4),
      sym(),
      s2k(),
      esk(nullptr)
{}

Tag3::Tag3(const Tag3 & copy)
    : Packet(copy),
      sym(copy.sym),
      s2k(copy.s2k -> clone()),
      esk(copy.get_esk_clone())
{}

Tag3::Tag3(const std::string & data)
    : Tag3()
{
    read(data);
}

Tag3::~Tag3(){}

void Tag3::read(const std::string & data){
    size = data.size();
    version = data[0];                  // 4
    sym = data[1];
    switch (data[2]){
        case 0:
            s2k = std::make_shared <S2K0> ();
            break;
        case 1:
            s2k = std::make_shared <S2K1> ();
            break;
        case 2:
            throw std::runtime_error("S2K with ID 2 is reserved.");
            break;
        case 3:
            s2k = std::make_shared <S2K3> ();
            break;
        default:
            throw std::runtime_error("Unknown S2K ID encountered: " + std::to_string(data[0]));
            break;
    }

    std::string::size_type pos = 2; // include S2K type
    s2k -> read(data, pos);

    if (pos < data.size()){
        esk = std::make_shared <std::string> (data.substr(pos, data.size() - pos));
    }
}

std::string Tag3::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string tab(indents * indent_size, ' ');
    std::stringstream out;
    out << tab << show_title() << "\n"
        << tab << "    Version: " << std::to_string(version) << "\n"
        << tab << "    Symmetric Key Algorithm: " << Sym::Name.at(sym) << " (sym " << std::to_string(sym) << ")\n"
        << s2k -> show(indents + 1, indent_size);
    if (esk){
        out << tab << "\n    Encrypted Session Key: " << hexlify(*esk);
    }
    return out.str();
}

std::string Tag3::raw() const{
    return std::string(1, version) + std::string(1, sym) + s2k -> write() + (esk?*esk:"");
}

uint8_t Tag3::get_sym() const{
    return sym;
}

S2K::Ptr Tag3::get_s2k() const{
    return s2k;
}

S2K::Ptr Tag3::get_s2k_clone() const{
    return s2k -> clone();
}

std::shared_ptr<std::string> Tag3::get_esk() const{
    return esk;
}

std::shared_ptr<std::string> Tag3::get_esk_clone() const{
    return std::make_shared <std::string> (*esk);
}

std::string Tag3::get_key(const std::string & pass) const{
    std::cerr << "Warning: Tag3::get_key is untested. Potentially incorrect" << std::endl;
    std::string out = s2k -> run(pass, Sym::Block_Length.at(sym) >> 3);
    if (esk){
        out = use_normal_CFB_decrypt(sym, *esk, out, std::string(Sym::Block_Length.at(sym) >> 3, 0));
    }
    else{
        out = std::string(1, sym) + out;
    }
    return out; // first octet is symmetric key algorithm. rest is session key
}

void Tag3::set_sym(const uint8_t s){
    sym = s;
    size = raw().size();
}

void Tag3::set_s2k(const S2K::Ptr & s){
    if ((s -> get_type() != 2) && (s -> get_type() != 3)){
        throw std::runtime_error("Error: S2K must have a salt value.");
    }

    s2k = s -> clone();
    size = raw().size();
}

void Tag3::set_esk(std::string * s){
    set_esk(*s);
}
void Tag3::set_esk(const std::string & s){
    esk = std::make_shared <std::string> (s);
    size = raw().size();
}

void Tag3::set_key(const std::string & pass, const std::string & sk){
    //sk should be [1 octet symmetric key algorithm] + [session key(s)]
    std::cerr << "Warning: Tag3::set_key is untested. Potentially incorrect" << std::endl;
    esk.reset();
    if (!sk.size()){
        esk = std::make_shared <std::string> (use_normal_CFB_encrypt(sk[0], sk.substr(1, sk.size() - 1), pass, std::string(Sym::Block_Length.at(sk[0]), 0)));
    }
    size = raw().size();
}

Packet::Ptr Tag3::clone() const{
    Ptr out = std::make_shared <Tag3> (*this);
    out -> sym = sym;
    out -> s2k = s2k -> clone();
    out -> esk = std::make_shared <std::string> (*esk);
    return out;
}

Tag3 & Tag3::operator=(const Tag3 & copy){
    Packet::operator=(copy);
    sym = copy.sym;
    s2k = copy.s2k -> clone();
    esk = std::make_shared <std::string> (*copy.esk);
    return *this;
}
