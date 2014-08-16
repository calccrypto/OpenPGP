#include "Tag1.h"

Tag1::Tag1():
    Packet(1, 3),
    keyid(),
    pka(),
    mpi()
{}

Tag1::Tag1(std::string & data):
    Tag1()
{
    read(data);
}

void Tag1::read(std::string & data, const uint8_t part){
    size = data.size();
    version = data[0];
    keyid = data.substr(1, 8);
    pka = data[9];
    data = data.substr(10, data.size() - 10);
    while (data.size()){
        mpi.push_back(read_MPI(data));
    }
}

std::string Tag1::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    std::stringstream out;
    out << std::string(tab, ' ') << show_title() << "\n"
        << std::string(tab, ' ') << "    Version: " << static_cast <unsigned int> (version) << "\n"
        << std::string(tab, ' ') << "    KeyID: " << hexlify(keyid) << "\n"
        << std::string(tab, ' ') << "    Public Key Algorithm: " << Public_Key_Algorithms.at(pka) << " (pka " << static_cast <unsigned int> (pka) << ")\n";
    if (pka < 4){
        out << std::string(tab, ' ') << "    RSA m**e mod n (" << bitsize(mpi[0]) << " bits): " << mpitohex(mpi[0]);
    }
    else if (pka == 16){
        out << std::string(tab, ' ') << "    Elgamal g**k mod p (" << bitsize(mpi[0]) << " bits): " << mpitohex(mpi[0]) << "\n"
            << std::string(tab, ' ') << "    Elgamal m * y**k mod p (" << bitsize(mpi[1]) << " bits): " << mpitohex(mpi[1]);
    }
    return out.str();
}

std::string Tag1::raw() const{
    std::string out = "\x03" + keyid + std::string(1, pka);
    for(unsigned int x = 0; x < mpi.size(); x++){
        out += write_MPI(mpi[x]);
    }
    return out;
}

std::string Tag1::get_keyid() const{
    return keyid;
}

uint8_t Tag1::get_pka() const{
    return pka;
}

std::vector <PGPMPI> Tag1::get_mpi() const{
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

void Tag1::set_mpi(const std::vector <PGPMPI> & m){
    mpi = m;
    size = raw().size();
}

Packet::Ptr Tag1::clone() const{
    return std::make_shared <Tag1> (*this);
}
