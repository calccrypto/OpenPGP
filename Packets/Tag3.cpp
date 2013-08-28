#include "Tag3.h"
Tag3::Tag3(){
    tag = 3;
    version = 4;
    s2k = NULL;
    esk = NULL;
}

Tag3::Tag3(std::string & data){
    tag = 2;
    read(data);
}

Tag3::~Tag3(){
    delete s2k;
    delete esk;
}

void Tag3::read(std::string & data){
    size = data.size();
	version = data[0];                  // 4
    sym = data[1];
    data = data.substr(2, data.size() - 2);
    if (data[2] == 0){
        s2k = new S2K0;
    }
    if (data[2] == 1){
        s2k = new S2K0;
    }
    if (data[2] == 3){
        s2k = new S2K0;
    }
    s2k -> read(data);

    if (data.size()){
        esk = new std::string(data);
    }
}

std::string Tag3::show(){
    std::stringstream out;
    out << "    Version: " << (unsigned int) version << "\n"
        << "    Symmetric Key Algorithm: " << Symmetric_Algorithms.at(sym) << " (sym " << (unsigned int) sym << ")\n"
        << "    " << String2Key_Specifiers.at(s2k -> get_type()) << " (s2k " << (int) s2k -> get_type() << "):\n" << s2k -> show();
    if (esk){
        out << "    Encrypted Session Key: " << *esk << "\n";
    }
    return out.str();
}

std::string Tag3::raw(){
    return std::string(1, version) + std::string(1, sym) + s2k -> write() + *esk;
}

Tag3 * Tag3::clone(){
    Tag3 * out = new Tag3(*this);
    out -> s2k = s2k -> clone();
    out -> esk = new std::string(*esk);
    return out;
}

uint8_t Tag3::get_sym(){
    return sym;
}

S2K * Tag3::get_s2k(){
    return s2k;
}

std::string * Tag3::get_esk(){
    return esk;
}

std::string Tag3::get_key(std::string pass){
    std::cerr << "Warning: This function is untested. Potentially incorrect" << std::endl;
    std::string out = s2k -> run(pass, Symmetric_Algorithm_Key_Length.at(Symmetric_Algorithms.at(sym)));
    if (esk){
        out = use_normal_CFB_decrypt(sym, *esk, out, std::string(Symmetric_Algorithm_Block_Length.at(Symmetric_Algorithms.at(sym)), 0));
    }
    else{
        out = std::string(1, sym) + out;
    }
    return out; // first byte is symmetric key algorithm. rest is session key
}

void Tag3::set_sym(uint8_t s){
    sym = s;
}

void Tag3::set_s2k(S2K * s){
    delete s2k;
    s2k = s -> clone();
}

void Tag3::set_esk(std::string * s){
    delete esk;
    esk = new std::string(*s);
}

void Tag3::set_key(std::string pass, std::string sk){
    //sk should be 1 byte symmetric key algorithm + session key
    delete esk;
    if (sk.size()){
        esk = NULL;
    }
    else{
        esk = new std::string(use_normal_CFB_encrypt(sym, sk, pass, std::string(Symmetric_Algorithm_Block_Length.at(Symmetric_Algorithms.at(sym)), 0)));
    }
}


