#include "Tag1.h"

Tag1::Tag1() :
    Packet(1, 3)
{
}

Tag1::Tag1(std::string & data) :
    Tag1()
{
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
        out << "    RSA m**e mod n (" << mpi[0].get_str(2).size() << " bits): " << mpi[0].get_str(16) << "\n";
    }
    else if (pka == 16){
        out << "    Elgamal g**k mod p (" << mpi[0].get_str(2).size() << " bits): " << mpi[0].get_str(16) << "\n"
            << "    Elgamal m * y**k mod p (" << mpi[1].get_str(2).size() << " bits): " << mpi[1].get_str(16) << "\n";
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
        throw std::runtime_error("Error: Key ID must be 8 octets.");
    }
    keyid = k;
    size = raw().size();
}

void Tag1::set_pka(const uint8_t p){
    pka = p;
    size = raw().size();
}

void Tag1::set_mpi(const std::vector <mpz_class> & m){
    mpi = m;
    size = raw().size();
}

Packet::Ptr Tag1::clone() const{
    return Ptr(new Tag1(*this));
}
