#include "Tag1.h"
Tag1::Tag1(){
    tag = 1;
    version = 3;
}

Tag1::Tag1(std::string & data){
    tag = 1;
    version = 3;
    read(data);
}

void Tag1::read(std::string & data){
    size = data.size();
    version = data[0];
    keyid = data.substr(1, 8);
    pka = data[9];
    data = data.substr(10, data.size() - 10);
    while (data.size())
        mpi.push_back(read_MPI(data));
}

std::string Tag1::show(){
    std::stringstream out;
    out << "    Version: " << (unsigned int) version << "\n"
        << "    KeyID: " << hexlify(keyid) << "\n"
        << "    Public Key Algorithm: " << Public_Key_Algorithms.at(pka) << " (pka " << (unsigned int) pka << ")\n";
    if (pka < 4){           // RSA
        out << "    RSA m**e mod n (" << makebin(mpi[0]).size() << " bits): " << mpi[0].get_str(16) << "\n";
    }
    else if (pka == 16){
        out << "    Elgamal g**k mod p (" << makebin(mpi[0]).size() << " bits): " << mpi[0].get_str(16) << "\n"
            << "    Elgamal m * y**k mod p (" << makebin(mpi[1]).size() << " bits): " << mpi[1].get_str(16) << "\n";
    }
    return out.str();
}

std::string Tag1::raw(){
    std::string out = "\x03" + keyid + std::string(1, pka);
    for(unsigned int x = 0; x < mpi.size(); x++){
        out += write_MPI(mpi[x]);
    }
    return out;
}

Tag1 * Tag1::clone(){
    return new Tag1(*this);
}

std::string Tag1::get_keyid(){
    return keyid;
}

uint8_t Tag1::get_pka(){
    return pka;
}

std::vector <mpz_class> Tag1::get_mpi(){
    return mpi;
}

void Tag1::set_keyid(const std::string & k){
    if (k.size() != 8){
        std::cerr << "Error: Key ID must be 8 octets" << std::endl;
        exit(1);
    }
    keyid = k;
}

void Tag1::set_pka(const uint8_t p){
    pka = p;
}

void Tag1::set_mpi(const std::vector <mpz_class> & m){
    mpi = m;
}
