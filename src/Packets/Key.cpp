#include "Key.h"

namespace OpenPGP {
namespace Packet {

Key::Key(uint8_t tag)
    : Tag(tag),
      time(),
      pka(),
      mpi(),
      expire()
      #ifdef GPG_COMPATIBLE
      ,
      curve(),
      kdf_size(),
      kdf_hash(),
      kdf_alg()
      #endif
{}

Key::Key()
    : Key(0)
{}

Key::Key(const Key & copy)
    : Tag(copy),
      time(copy.time),
      pka(copy.pka),
      mpi(copy.mpi),
      expire(copy.expire)
      #ifdef GPG_COMPATIBLE
      ,
      curve(copy.curve),
      kdf_size(copy.kdf_size),
      kdf_hash(copy.kdf_hash),
      kdf_alg(copy.kdf_alg)
      #endif
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
        mpi.push_back(read_MPI(data, pos));         // RSA n
        mpi.push_back(read_MPI(data, pos));         // RSA e
    }
    else if (version == 4){
        pka = data[pos + 5];
        pos += 6;

        // RSA
        if(PKA::is_RSA(pka)){
            mpi.push_back(read_MPI(data, pos));     // RSA n
            mpi.push_back(read_MPI(data, pos));     // RSA e
        }
        // DSA
        else if (pka == PKA::ID::DSA){
            mpi.push_back(read_MPI(data, pos));     // DSA p
            mpi.push_back(read_MPI(data, pos));     // DSA q
            mpi.push_back(read_MPI(data, pos));     // DSA g
            mpi.push_back(read_MPI(data, pos));     // DSA y
        }
        // ELGAMAL
        else if (pka == PKA::ID::ELGAMAL){
            mpi.push_back(read_MPI(data, pos));     // ELGAMAL p
            mpi.push_back(read_MPI(data, pos));     // ELGAMAL g
            mpi.push_back(read_MPI(data, pos));     // ELGAMAL y
        }
        #ifdef GPG_COMPATIBLE
        // ECDSA
        else if(pka == PKA::ID::ECDSA){
            uint8_t curve_dim = data[pos];
            curve = data.substr(pos + 1, curve_dim);
            pos += curve_dim + 1;
            mpi.push_back(read_MPI(data, pos));
        }
        // EdDSA
        else if (pka == PKA::ID::EdDSA){
            uint8_t curve_dim = data[pos];
            curve = data.substr(pos + 1, curve_dim);
            pos += curve_dim + 1;
            mpi.push_back(read_MPI(data, pos));
        }
        // ECDH
        else if (pka == PKA::ID::ECDH){
            uint8_t curve_dim = data[pos];
            curve = data.substr(pos + 1, curve_dim);
            pos += curve_dim + 1;
            mpi.push_back(read_MPI(data, pos));
            kdf_size = data[pos];
            kdf_hash = data[pos + 2];
            kdf_alg = data[pos + 3];
            pos += 4; // Jump over the KDF parameters
        }
        #endif
        else{
            throw std::runtime_error("Algorithm not found");
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
        if (PKA::is_RSA(pka)){
            out += indent + tab + "RSA n (" + std::to_string(bitsize(mpi[0])) + " bits): " + mpitohex(mpi[0]) + "\n" +
                   indent + tab + "RSA e (" + std::to_string(bitsize(mpi[1])) + " bits): " + mpitohex(mpi[1]);
        }
        else if (pka == PKA::ID::ELGAMAL){
            out += indent + tab + "ELGAMAL p (" + std::to_string(bitsize(mpi[0])) + " bits): " + mpitohex(mpi[0]) + "\n" +
                   indent + tab + "ELGAMAL g (" + std::to_string(bitsize(mpi[1])) + " bits): " + mpitohex(mpi[1]) + "\n" +
                   indent + tab + "ELGAMAL y (" + std::to_string(bitsize(mpi[2])) + " bits): " + mpitohex(mpi[2]);
        }
        #ifdef GPG_COMPATIBLE
        else if (pka == PKA::ID::ECDSA){
            out += indent + tab + "ECDSA " + PKA::CURVE_NAME.at(hexlify(curve, true)) + "\n" +
                   indent + tab + "ECDSA ec point: " + mpitohex(mpi[0]);
        }
        else if (pka == PKA::ID::EdDSA){
            out += indent + tab + "EdDSA " + PKA::CURVE_NAME.at(hexlify(curve, true)) + "\n" +
                   indent + tab + "EdDSA ec point: " + mpitohex(mpi[0]);
        }
        else if (pka == PKA::ID::ECDH){
            out += indent + tab + "ECDH " + PKA::CURVE_NAME.at(hexlify(curve, true)) + "\n" +
                   indent + tab + "ECDH ec point: " + mpitohex(mpi[0]);
        }
        #endif
        else if (pka == PKA::ID::DSA){
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

    #ifdef GPG_COMPATIBLE
    if (pka == PKA::ID::ECDSA || pka == PKA::ID::EdDSA || pka == PKA::ID::ECDH){
        out += std::string(1, PKA::CURVE_OID_LENGTH.at(hexlify(curve, true)));
        //out += curve.size();
        out += curve;
    }
    #endif

    for(MPI const m : mpi){
        out += write_MPI(m);
    }

    #ifdef GPG_COMPATIBLE
    if (pka == PKA::ID::ECDH){
        out += kdf_size; // Should be one
        out += std::string(1, 1);
        out += kdf_hash;
        out += kdf_alg;
    }
    #endif

    return out;
}

uint32_t Key::get_time() const{
    return time;
}

uint32_t Key::get_exp_time() const{
    if (version < 4){
        return expire;
    }
    else{
        throw std::runtime_error("Expiration time is defined only for version 3");
    }
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
        for(MPI const & i : mpi){
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

#ifdef GPG_COMPATIBLE
std::string Key::get_curve() const{
    return curve;
}
void Key::set_curve(const std::string c){
    curve = c;
}
uint8_t Key::get_kdf_hash() const{
    return kdf_hash;
}
void Key::set_kdf_hash(const uint8_t h){
    kdf_hash = h;
}
uint8_t Key::get_kdf_alg() const{
    return kdf_alg;
}
void Key::set_kdf_alg(const uint8_t a){
    kdf_alg = a;
}
#endif

Tag::Ptr Key::clone() const{
    return std::make_shared <Key> (*this);
}

Key & Key::operator=(const Key & copy)
{
    Tag::operator=(copy);
    time = copy.time;
    pka = copy.pka;
    mpi = copy.mpi;
    expire = copy.expire;
    return *this;
}

}
}
