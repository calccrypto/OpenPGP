#include "Tag1.h"

Tag1::Tag1()
    : Packet(Packet::ID::Public_Key_Encrypted_Session_Key, 3),
      keyid(),
      pka(),
      mpi()
{}

Tag1::Tag1(const Tag1 & copy)
    : Packet(copy),
      keyid(copy.keyid),
      pka(copy.pka),
      mpi(copy.mpi)
{}

Tag1::Tag1(const std::string & data)
    : Tag1()
{
    read(data);
}

void Tag1::read(const std::string & data){
    size = data.size();
    version = data[0];
    keyid = data.substr(1, 8);
    pka = data[9];
    std::string::size_type pos = 10;
    while (pos < data.size()){
        mpi.push_back(read_MPI(data, pos));
    }
}

std::string Tag1::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string tab(indents * indent_size, ' ');
    std::stringstream out;
    out << tab << show_title() << "\n"
        << tab << "    Version: " << std::to_string(version) << "\n"
        << tab << "    KeyID: " << hexlify(keyid) << "\n"
        << tab << "    Public Key Algorithm: " << PKA::Name.at(pka) << " (pka " << std::to_string(pka) << ")\n";
    if (pka < 4){
        out << tab << "    RSA m**e mod n (" << bitsize(mpi[0]) << " bits): " << mpitohex(mpi[0]);
    }
    else if (pka == 16){
        out << tab << "    Elgamal g**k mod p (" << bitsize(mpi[0]) << " bits): " << mpitohex(mpi[0]) << "\n"
            << tab << "    Elgamal m * y**k mod p (" << bitsize(mpi[1]) << " bits): " << mpitohex(mpi[1]);
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

PKA::Values Tag1::get_mpi() const{
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

void Tag1::set_mpi(const PKA::Values & m){
    mpi = m;
    size = raw().size();
}

Packet::Ptr Tag1::clone() const{
    return std::make_shared <Tag1> (*this);
}
