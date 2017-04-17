#include "Key.h"

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

std::string Key::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string tab(indents * indent_size, ' ');
    return tab + show_title() + "\n" + show_common(indents, indent_size);
}

std::string Key::raw() const{
    return raw_common();
}

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
        mpi.push_back(read_MPI(data, pos));     // RSA n, DSA p, ELGAMAL p
        mpi.push_back(read_MPI(data, pos));     // RSA e, DSA q, ELGAMAL g

        // DSA
        if (pka == PKA::DSA){
            mpi.push_back(read_MPI(data, pos)); //        DSA g
            mpi.push_back(read_MPI(data, pos)); //        DSA y
        }
        // ELGAMAL
        else if (pka == PKA::ELGAMAL){
            mpi.push_back(read_MPI(data, pos)); //               ELGAMAL y
        }
    }
}

std::string Key::show_common(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');

    std::string out = indent + tab + "Version: " + std::to_string(version) + " - " + ((version < 4)?"Old":"New") + "\n" +
                      indent + tab + "Creation Time: " + show_time(time) + "\n";

    if (version < 4){
        out += indent + tab + "Expiration Time (Days): " + std::to_string(expire) + "\n";
        if (!expire){
            out += " (Never)\n";
        }
        out += indent + tab + "Public Key Algorithm: " + PKA::NAME.at(pka) + " (pka " + std::to_string(pka) + ")\n" +
               indent + tab + "RSA n: " + mpitohex(mpi[0]) + "(" + std::to_string(bitsize(mpi[0])) + " bits)\n" +
               indent + tab + "RSA e: " + mpitohex(mpi[1]);
    }
    else if (version == 4){
        out += indent + tab + "Public Key Algorithm: " + PKA::NAME.at(pka) + " (pka " + std::to_string(pka) + ")\n";
        if ((pka == PKA::RSA_ENCRYPT_OR_SIGN) ||
            (pka == PKA::RSA_ENCRYPT_ONLY)    ||
            (pka == PKA::RSA_SIGN_ONLY)){
            out += indent + tab + "RSA n (" + std::to_string(bitsize(mpi[0])) + " bits): " + mpitohex(mpi[0]) + "\n" +
                   indent + tab + "RSA e (" + std::to_string(bitsize(mpi[1])) + " bits): " + mpitohex(mpi[1]);
        }
        else if (pka == PKA::ELGAMAL){
            out += indent + tab + "ELGAMAL p (" + std::to_string(bitsize(mpi[0])) + " bits): " + mpitohex(mpi[0]) + "\n" +
                   indent + tab + "ELGAMAL g (" + std::to_string(bitsize(mpi[1])) + " bits): " + mpitohex(mpi[1]) + "\n" +
                   indent + tab + "ELGAMAL y (" + std::to_string(bitsize(mpi[2])) + " bits): " + mpitohex(mpi[2]);
        }
        else if (pka == PKA::DSA){
            out += indent + tab + "DSA p (" + std::to_string(bitsize(mpi[0])) + " bits): " + mpitohex(mpi[0]) + "\n" +
                   indent + tab + "DSA q (" + std::to_string(bitsize(mpi[1])) + " bits): " + mpitohex(mpi[1]) + "\n" +
                   indent + tab + "DSA g (" + std::to_string(bitsize(mpi[2])) + " bits): " + mpitohex(mpi[2]) + "\n" +
                   indent + tab + "DSA y (" + std::to_string(bitsize(mpi[3])) + " bits): " + mpitohex(mpi[3]);
        }
    }

    return out;
}

std::string Key::raw_common() const{
    std::string out = std::string(1, version) + unhexlify(makehex(time, 8));
    if (version < 4){ // to recreate older keys
        out += unhexlify(makehex(expire, 4));
    }

    out += std::string(1, pka);

    for(PGPMPI const m : mpi){
        out += write_MPI(m);
    }

    return out;
}

uint32_t Key::get_time() const{
    return time;
}

uint8_t Key::get_pka() const{
    return pka;
}

PKA::Values Key::get_mpi() const{
    return mpi;
}

void Key::set_time(uint32_t t){
    time = t;
}

void Key::set_pka(uint8_t p){
    pka = p;
}

void Key::set_mpi(const PKA::Values & m){
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
        throw std::runtime_error("Error: Key packet version " + std::to_string(version) + " not defined.");
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
        throw std::runtime_error("Error: Key packet version " + std::to_string(version) + " not defined.");
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
