#include "Tag3.h"

Tag3::Tag3():
    Packet(3, 4),
    sym(),
    s2k(),
    esk(nullptr)
{}

Tag3::Tag3(const Tag3 & copy):
    Packet(copy),
    sym(copy.sym),
    s2k(copy.s2k -> clone()),
    esk(copy.get_esk_clone())
{}

Tag3::Tag3(std::string & data):
    Tag3()
{
    read(data);
}

Tag3::~Tag3(){}

void Tag3::read(std::string & data, const uint8_t part){
    size = data.size();
	version = data[0];                  // 4
    sym = data[1];
    data = data.substr(2, data.size() - 2);
    if (data[0] == 0){
        s2k = std::make_shared<S2K0>();
    }
    if (data[0] == 1){
        s2k = std::make_shared<S2K1>();
    }
    if (data[0] == 3){
        s2k = std::make_shared<S2K3>();
    }
    s2k -> read(data);

    if (data.size()){
        esk = std::make_shared<std::string>(data);
    }
}

std::string Tag3::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    std::stringstream out;
    out << std::string(tab, ' ') << show_title() << "\n"
        << std::string(tab, ' ') << "    Version: " << static_cast <unsigned int> (version) << "\n"
        << std::string(tab, ' ') << "    Symmetric Key Algorithm: " << Symmetric_Algorithms.at(sym) << " (sym " << static_cast <unsigned int> (sym) << ")\n"
        << s2k -> show(indents + 1, indent_size);
    if (esk){
        out << std::string(tab, ' ') << "    Encrypted Session Key: " << hexlify(*esk);
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
    return std::make_shared<std::string>(*esk);
}

std::string Tag3::get_key(const std::string & pass) const{
    std::cerr << "Warning: Tag3::get_key is untested. Potentially incorrect" << std::endl;
    std::string out = s2k -> run(pass, Symmetric_Algorithm_Block_Length.at(Symmetric_Algorithms.at(sym)) >> 3);
    if (esk){
        out = use_normal_CFB_decrypt(sym, *esk, out, std::string(Symmetric_Algorithm_Block_Length.at(Symmetric_Algorithms.at(sym)) >> 3, 0));
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
    esk = std::make_shared<std::string>(s);
    size = raw().size();
}

void Tag3::set_key(const std::string & pass, const std::string & sk){
    //sk should be [1 octet symmetric key algorithm] + [session key(s)]
    std::cerr << "Warning: Tag3::set_key is untested. Potentially incorrect" << std::endl;
    esk.reset();
    if (!sk.size()){
        esk = std::make_shared<std::string>(use_normal_CFB_encrypt(sk[0], sk.substr(1, sk.size() - 1), pass, std::string(Symmetric_Algorithm_Block_Length.at(Symmetric_Algorithms.at(sk[0])), 0)));
    }
    size = raw().size();
}

Packet::Ptr Tag3::clone() const{
    Ptr out = std::make_shared <Tag3> (*this);
    out -> sym = sym;
    out -> s2k = s2k -> clone();
    out -> esk = std::make_shared<std::string>(*esk);
    return out;
}

Tag3 & Tag3::operator=(const Tag3 & copy){
    Packet::operator =(copy);
    sym = copy.sym;
    s2k = copy.s2k -> clone();
    esk = std::make_shared<std::string>(*copy.esk);
    return *this;
}
