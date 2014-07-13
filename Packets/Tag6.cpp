#include "Tag6.h"
void Tag6::read_tag6(std::string & data){
    size = data.size();
    version = data[0];
    time = toint(data.substr(1, 4), 256);
    if (version < 4){
        expire = (data[5] << 8) + data[6];
        pka = data[7];
        data = data.substr(8, data.size() - 8);
        mpi.push_back(read_MPI(data));              // RSA n
        mpi.push_back(read_MPI(data));              // RSA e
    }
    else if (version == 4){
        pka = data[5];
        data = data.substr(6, data.size() - 6);

        // at minimum RSA
        mpi.push_back(read_MPI(data));             // RSA n, DSA p, ElGamal p
        mpi.push_back(read_MPI(data));             // RSA e, DSA q, ElGamal g

        // DSA
        if (pka == 17){
            mpi.push_back(read_MPI(data));         // DSA g
            mpi.push_back(read_MPI(data));         // DSA y
        }
        // Elgamal
        else if (pka == 16)
            mpi.push_back(read_MPI(data));         // ElGamal y
    }
}

std::string Tag6::show_tag6() const{
    std::stringstream out;
    out << "    Version: " << static_cast <unsigned int> (version) << " - " << ((version < 4)?"Old":"New") << "\n"
        << "    Creation Time: " << show_time(time) << "\n";
    if (version < 4){
        out << "    Expiration Time (Days): " << expire;
        if (!expire){
            out << " (Never)";
        }
        out << "\n"
            << "    Public Key Algorithm: " << Public_Key_Algorithms.at(pka) << " (pka " << static_cast <unsigned int> (pka) << ")\n"
            << "    RSA n: " << mpitohex(mpi[0]) << "(" << bitsize(mpi[0]) << " bits)\n"
            << "    RSA e: " << mpitohex(mpi[1]) << "\n";
    }
    else if (version == 4){
        out << "    Public Key Algorithm: " << Public_Key_Algorithms.at(pka) << " (pka " << static_cast <unsigned int> (pka) << ")\n";

        if (pka < 4){
            out << "    RSA n (" << bitsize(mpi[0]) << " bits): " << mpitohex(mpi[0]) << "\n"
                << "    RSA e (" << bitsize(mpi[1]) << " bits): " << mpitohex(mpi[1]) << "\n";
        }
        else if (pka == 17){
            out << "    DSA p (" << bitsize(mpi[0]) << " bits): " << mpitohex(mpi[0]) << "\n"
                << "    DSA q (" << bitsize(mpi[1]) << " bits): " << mpitohex(mpi[1]) << "\n"
                << "    DSA g (" << bitsize(mpi[2]) << " bits): " << mpitohex(mpi[2]) << "\n"
                << "    DSA y (" << bitsize(mpi[3]) << " bits): " << mpitohex(mpi[3]) << "\n";
        }
        else if (pka == 16){
            out << "    Elgamal p (" << bitsize(mpi[0]) << " bits): " << mpitohex(mpi[0]) << "\n"
                << "    Elgamal g (" << bitsize(mpi[1]) << " bits): " << mpitohex(mpi[1]) << "\n"
                << "    Elgamal y (" << bitsize(mpi[2]) << " bits): " << mpitohex(mpi[2]) << "\n";
        }
    }
    return out.str();
}

std::string Tag6::raw_tag6() const{
    std::string out = std::string(1, version) + unhexlify(makehex(time, 8));
    if (version < 4){// to recreate older keys
        out += unhexlify(makehex(expire, 4));
    }
    out += std::string(1, pka);
    for(unsigned int x = 0; x < mpi.size(); x++){
        out += write_MPI(mpi[x]);
    }
    return out;
}

Tag6::Tag6(uint8_t tag) :
    Key(tag),
    time(),
    pka(),
    mpi(),
    expire()
{
}

Tag6::Tag6() :
    Tag6(6)
{
}

Tag6::Tag6(std::string & data) :
    Tag6()
{
    read(data);
}

Tag6::~Tag6(){}

void Tag6::read(std::string & data){
    read_tag6(data);
}

std::string Tag6::show() const{
    return show_tag6();
}

std::string Tag6::raw() const{
    return raw_tag6();
}

time_t Tag6::get_time() const{
    return time;
}

uint8_t Tag6::get_pka() const{
    return pka;
}

std::vector <PGPMPI> Tag6::get_mpi() const{
    return mpi;
}

void Tag6::set_time(time_t t){
    time = t;
    size = raw().size();
}

void Tag6::set_pka(uint8_t p){
    pka = p;
    size = raw().size();
}

void Tag6::set_mpi(const std::vector <PGPMPI> & m){
    mpi = m;
    size = raw().size();
}

std::string Tag6::get_fingerprint() const{
    if (version == 3){
        std::string data = "";
        for(PGPMPI const & i : mpi){
            std::string m = write_MPI(i);
            data += m.substr(2, m.size() - 2);
        }
        return MD5(data).digest();
    }
    else if (version == 4){
        std::string packet = raw_tag6();
        return SHA1("\x99" + unhexlify(makehex(packet.size(), 4)) + packet).digest();
    }
    else{
        std::stringstream s; s << static_cast <int> (version);
        throw std::runtime_error("Error: Public Key packet version " + s.str() + " not defined.");
    }
    return ""; // should never reach here; mainly just to remove compiler warnings
}

std::string Tag6::get_keyid() const{
    if (version == 3){
        std::string data = write_MPI(mpi[0]);
        return data.substr(data.size() - 8, 8);
    }
    if (version == 4){
        return get_fingerprint().substr(12, 8);
    }
    else{
        std::stringstream s; s << static_cast <int> (version);
        throw std::runtime_error("Error: Public Key packet version " + s.str() + " not defined.");
    }
    return ""; // should never reach here; mainly just to remove compiler warnings
}

Packet::Ptr Tag6::clone() const{
    return Ptr(new Tag6(*this));
}

Tag6::Tag6(const Tag6 & copy) :
    Key(copy),
    time(copy.time),
    pka(copy.pka),
    mpi(copy.mpi),
    expire(copy.expire)
{
}

Tag6 &Tag6::operator =(const Tag6 & copy)
{
    Key::operator =(copy);
    time = copy.time;
    pka = copy.pka;
    mpi = copy.mpi;
    expire = copy.expire;
    return *this;
}
