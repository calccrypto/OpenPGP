#include "Key.h"

void Key::read_common(const std::string & data, std::string::size_type & pos){
    size = data.size();
    version = data[pos];
    time = toint(data.substr(pos + 1, 4), 256);

    if (version < 4){
        expire = (data[pos + 5] << 8) + data[pos + 6];
        pka = data[pos + 7];
        pos += 8;
        mpi.push_back(read_MPI(data, pos));     // RSA n
        mpi.push_back(read_MPI(data, pos));     // RSA e
    }
    else if (version == 4){
        pka = data[pos + 5];
        pos += 6;

        // at minimum RSA
        mpi.push_back(read_MPI(data, pos));     // RSA n, DSA p, ElGamal p
        mpi.push_back(read_MPI(data, pos));     // RSA e, DSA q, ElGamal g

        // DSA
        if (pka == 17){
            mpi.push_back(read_MPI(data, pos)); // DSA g
            mpi.push_back(read_MPI(data, pos)); // DSA y
        }
        // Elgamal
        else if (pka == 16)
            mpi.push_back(read_MPI(data, pos)); // ElGamal y
    }
}

std::string Key::show_common(const uint8_t indents, const uint8_t indent_size) const{
    const std::string tab(indents * indent_size, ' ');
    std::stringstream out;
    out << tab << "    Version: " << static_cast <unsigned int> (version) << " - " << ((version < 4)?"Old":"New") << "\n"
        << tab << "    Creation Time: " << show_time(time);
    if (version < 4){
        out << "\n"
            << tab << "    Expiration Time (Days): " << expire;
        if (!expire){
            out << " (Never)";
        }
        out << "\n"
            << tab << "    Public Key Algorithm: " << Public_Key_Algorithms.at(pka) << " (pka " << static_cast <unsigned int> (pka) << ")\n"
            << tab << "    RSA n: " << mpitohex(mpi[0]) << "(" << bitsize(mpi[0]) << " bits)\n"
            << tab << "    RSA e: " << mpitohex(mpi[1]);
    }
    else if (version == 4){
        out << "\n"
            << tab << "    Public Key Algorithm: " << Public_Key_Algorithms.at(pka) << " (pka " << static_cast <unsigned int> (pka) << ")\n";
        if (pka < 4){
            out << tab << "    RSA n (" << bitsize(mpi[0]) << " bits): " << mpitohex(mpi[0]) << "\n"
                << tab << "    RSA e (" << bitsize(mpi[1]) << " bits): " << mpitohex(mpi[1]);
        }
        else if (pka == 17){
            out << tab << "    DSA p (" << bitsize(mpi[0]) << " bits): " << mpitohex(mpi[0]) << "\n"
                << tab << "    DSA q (" << bitsize(mpi[1]) << " bits): " << mpitohex(mpi[1]) << "\n"
                << tab << "    DSA g (" << bitsize(mpi[2]) << " bits): " << mpitohex(mpi[2]) << "\n"
                << tab << "    DSA y (" << bitsize(mpi[3]) << " bits): " << mpitohex(mpi[3]);
        }
        else if (pka == 16){
            out << tab << "    Elgamal p (" << bitsize(mpi[0]) << " bits): " << mpitohex(mpi[0]) << "\n"
                << tab << "    Elgamal g (" << bitsize(mpi[1]) << " bits): " << mpitohex(mpi[1]) << "\n"
                << tab << "    Elgamal y (" << bitsize(mpi[2]) << " bits): " << mpitohex(mpi[2]);
        }
    }
    return out.str();
}

std::string Key::raw_common() const{
    std::string out = std::string(1, version) + unhexlify(makehex(time, 8));
    if (version < 4){ // to recreate older keys
        out += unhexlify(makehex(expire, 4));
    }
    out += std::string(1, pka);
    for(unsigned int x = 0; x < mpi.size(); x++){
        out += write_MPI(mpi[x]);
    }
    return out;
}

Key::Key(uint8_t tag)
    : Packet(tag),
      time(),
      pka(),
      mpi(),
      expire()
{}

Key::Key()
    : Key(0)
{}

Key::Key(const Key & copy)
    : Packet(copy),
      time(copy.time),
      pka(copy.pka),
      mpi(copy.mpi),
      expire(copy.expire)
{}

Key::Key(const std::string & data)
    : Key()
{
    read(data);
}

Key::~Key(){}

void Key::read(const std::string & data){
    std::string::size_type pos = 0;
    read_common(data, pos);
}

std::string Key::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string tab(indents * indent_size, ' ');
    return tab + show_title() + "\n" + show_common(indents, indent_size);
}

std::string Key::raw() const{
    return raw_common();
}

time_t Key::get_time() const{
    return time;
}

uint8_t Key::get_pka() const{
    return pka;
}

std::vector <PGPMPI> Key::get_mpi() const{
    return mpi;
}

void Key::set_time(time_t t){
    time = t;
}

void Key::set_pka(uint8_t p){
    pka = p;
}

void Key::set_mpi(const std::vector <PGPMPI> & m){
    mpi = m;
    size = raw().size();
}

std::string Key::get_fingerprint() const{
    if (version == 3){
        std::string data = "";
        for(PGPMPI const & i : mpi){
            std::string m = write_MPI(i);
            data += m.substr(2, m.size() - 2);
        }
        return MD5(data).digest();
    }
    else if (version == 4){
        std::string packet = raw_common();
        return SHA1("\x99" + unhexlify(makehex(packet.size(), 4)) + packet).digest();
    }
    else{
        std::stringstream s; s << static_cast <unsigned int> (version);
        throw std::runtime_error("Error: Key packet version " + s.str() + " not defined.");
    }
    return ""; // should never reach here; mainly just to remove compiler warnings
}

std::string Key::get_keyid() const{
    if (version == 3){
        std::string data = write_MPI(mpi[0]);
        return data.substr(data.size() - 8, 8);
    }
    else if (version == 4){
        return get_fingerprint().substr(12, 8);
    }
    else{
        std::stringstream s; s << static_cast <unsigned int> (version);
        throw std::runtime_error("Error: Key packet version " + s.str() + " not defined.");
    }
    return ""; // should never reach here; mainly just to remove compiler warnings
}

Packet::Ptr Key::clone() const{
    return std::make_shared <Key> (*this);
}

Key & Key::operator=(const Key & copy)
{
    Packet::operator=(copy);
    time = copy.time;
    pka = copy.pka;
    mpi = copy.mpi;
    expire = copy.expire;
    return *this;
}
