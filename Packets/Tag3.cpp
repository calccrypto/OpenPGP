#include "Tag3.h"

namespace OpenPGP {
namespace Packet {

Tag3::Tag3()
    : Tag(SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY, 4),
      sym(),
      s2k(nullptr),
      esk(nullptr)
{}

Tag3::Tag3(const Tag3 & copy)
    : Tag(copy),
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

    if (data[2] == S2K::ID::SIMPLE_S2K){
        s2k = std::make_shared <S2K::S2K0> ();
    }
    else if (data[2] == S2K::ID::SALTED_S2K){
        s2k = std::make_shared <S2K::S2K1> ();
    }
    else if (data[2] == 2){
        throw std::runtime_error("S2K with ID 2 is reserved.");
    }
    else if (data[2] == S2K::ID::ITERATED_AND_SALTED_S2K){
        s2k = std::make_shared <S2K::S2K3> ();
    }
    else{
        throw std::runtime_error("Unknown S2K ID encountered: " + std::to_string(data[0]));
    }

    std::string::size_type pos = 2; // include S2K type
    s2k -> read(data, pos);

    if (pos < data.size()){
        esk = std::make_shared <std::string> (data.substr(pos, data.size() - pos));
    }
}

std::string Tag3::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    const decltype(Sym::NAME)::const_iterator sym_it = Sym::NAME.find(sym);
    std::string out = indent + show_title() + "\n" +
                      indent + tab + "Version: " + std::to_string(version) + "\n" +
                      indent + tab + "Symmetric Key Algorithm: " + ((sym_it == Sym::NAME.end())?"Unknown":(sym_it -> second)) + " (sym " + std::to_string(sym) + ")\n" +
                      s2k -> show(indents, indent_size);
    if (esk){
        out += "\n" + indent + tab + "Encrypted Session Key: " + hexlify(*esk);
    }
    return out;
}

std::string Tag3::raw() const{
    return std::string(1, version) + std::string(1, sym) + (s2k?s2k -> write():"") + (esk?*esk:"");
}

uint8_t Tag3::get_sym() const{
    return sym;
}

S2K::S2K::Ptr Tag3::get_s2k() const{
    return s2k;
}

S2K::S2K::Ptr Tag3::get_s2k_clone() const{
    return s2k -> clone();
}

std::shared_ptr <std::string> Tag3::get_esk() const{
    return esk;
}

std::shared_ptr <std::string> Tag3::get_esk_clone() const{
    return esk?std::make_shared <std::string> (*esk):nullptr;
}

std::string Tag3::get_session_key(const std::string & pass) const{
    std::string out = s2k -> run(pass, Sym::KEY_LENGTH.at(sym) >> 3);
    if (esk){
        out = use_normal_CFB_decrypt(sym, *esk, out, std::string(Sym::BLOCK_LENGTH.at(sym) >> 3, 0));
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

void Tag3::set_s2k(const S2K::S2K::Ptr & s){
    if (!s){
        throw std::runtime_error("Error: No S2K provided.\n");
    }

    if ((s -> get_type() != S2K::ID::SALTED_S2K)             &&
        (s -> get_type() != S2K::ID::ITERATED_AND_SALTED_S2K)){
        throw std::runtime_error("Error: S2K must have a salt value.");
    }

    s2k = s -> clone();
    size = raw().size();
}

void Tag3::set_esk(std::string * s){
    if (s){
        set_esk(*s);
    }
}

void Tag3::set_esk(const std::string & s){
    esk = std::make_shared <std::string> (s);
    size = raw().size();
}

void Tag3::set_session_key(const std::string & pass, const std::string & sk){
    //sk should be [1 octet symmetric key algorithm] + [session key(s)]
    esk.reset();
    if (s2k && (sk.size() > 1)){
        esk = std::make_shared <std::string> (use_normal_CFB_encrypt(sym, sk, s2k -> run(pass, Sym::KEY_LENGTH.at(sym) >> 3), std::string(Sym::BLOCK_LENGTH.at(sym) >> 3, 0)));
    }
    size = raw().size();
}

Tag::Ptr Tag3::clone() const{
    Ptr out = std::make_shared <Packet::Tag3> (*this);
    out -> sym = sym;
    out -> s2k = s2k?s2k -> clone():nullptr;
    out -> esk = esk?std::make_shared <std::string> (*esk):nullptr;
    return out;
}

Tag3 & Tag3::operator=(const Tag3 & copy){
    Tag::operator=(copy);
    sym = copy.sym;
    s2k = copy.s2k -> clone();
    esk = std::make_shared <std::string> (*copy.esk);
    return *this;
}

}
}