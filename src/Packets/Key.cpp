#include "Packets/Key.h"

namespace OpenPGP {
namespace Packet {

Key::Key(const uint8_t tag)
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

void Key::actual_read(const std::string & data) {
    std::string::size_type pos = 0;
    read_common(data, pos);
}

void Key::show_contents(HumanReadable & hr) const {
    show_common(hr);
}

Key::Key()
    : Key(UNKNOWN)
{}

Key::Key(const std::string & data)
    : Key()
{
    read(data);
}

Key::~Key() {}

std::string Key::raw() const {
    return raw_common();
}

void Key::read_common(const std::string & data, std::string::size_type & pos) {
    set_version(data[pos]);
    set_time(toint(data.substr(pos + 1, 4), 256));

    if (version < 4) {
        set_expire((data[pos + 5] << 8) + data[pos + 6]);
        set_pka(data[pos + 7]);
        pos += 8;
        mpi.push_back(read_MPI(data, pos));         // RSA n
        mpi.push_back(read_MPI(data, pos));         // RSA e
    }
    else if (version == 4) {
        set_pka(data[pos + 5]);
        pos += 6;

        // RSA
        if(PKA::is_RSA(pka)) {
            mpi.push_back(read_MPI(data, pos));     // RSA n
            mpi.push_back(read_MPI(data, pos));     // RSA e
        }
        // DSA
        else if (pka == PKA::ID::DSA) {
            mpi.push_back(read_MPI(data, pos));     // DSA p
            mpi.push_back(read_MPI(data, pos));     // DSA q
            mpi.push_back(read_MPI(data, pos));     // DSA g
            mpi.push_back(read_MPI(data, pos));     // DSA y
        }
        // ELGAMAL
        else if (pka == PKA::ID::ELGAMAL) {
            mpi.push_back(read_MPI(data, pos));     // ELGAMAL p
            mpi.push_back(read_MPI(data, pos));     // ELGAMAL g
            mpi.push_back(read_MPI(data, pos));     // ELGAMAL y
        }
        #ifdef GPG_COMPATIBLE
        // ECDSA
        else if(pka == PKA::ID::ECDSA) {
            uint8_t curve_dim = data[pos];
            curve = data.substr(pos + 1, curve_dim);
            pos += curve_dim + 1;
            mpi.push_back(read_MPI(data, pos));
        }
        // EdDSA
        else if (pka == PKA::ID::EdDSA) {
            uint8_t curve_dim = data[pos];
            curve = data.substr(pos + 1, curve_dim);
            pos += curve_dim + 1;
            mpi.push_back(read_MPI(data, pos));
        }
        // ECDH
        else if (pka == PKA::ID::ECDH) {
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

void Key::show_common(HumanReadable & hr) const {
    hr << "Version: " + std::to_string(version) + " - " + ((version < 4)?"Old":"New")
       << "Creation Time: " + show_time(time);

    if (version < 4) {
        hr << "Expiration Time (Days): " + std::to_string(expire);
        if (!expire) {
            hr << " (Never)";
        }
        hr << "Public Key Algorithm: " + get_mapped(PKA::NAME, pka) + " (pka " + std::to_string(pka) + ")"
           << "RSA n: " + mpitohex(mpi[0]) + "(" + std::to_string(bitsize(mpi[0])) + " bits)"
           << "RSA e: " + mpitohex(mpi[1]);
    }
    else if (version == 4) {
        hr << "Public Key Algorithm: " + get_mapped(PKA::NAME, pka) + " (pka " + std::to_string(pka) + ")";
        if (PKA::is_RSA(pka)) {
            hr << "RSA n (" + std::to_string(bitsize(mpi[0])) + " bits): " + mpitohex(mpi[0])
               << "RSA e (" + std::to_string(bitsize(mpi[1])) + " bits): " + mpitohex(mpi[1]);
        }
        else if (pka == PKA::ID::ELGAMAL) {
            hr << "ELGAMAL p (" + std::to_string(bitsize(mpi[0])) + " bits): " + mpitohex(mpi[0])
               << "ELGAMAL g (" + std::to_string(bitsize(mpi[1])) + " bits): " + mpitohex(mpi[1])
               << "ELGAMAL y (" + std::to_string(bitsize(mpi[2])) + " bits): " + mpitohex(mpi[2]);
        }
        #ifdef GPG_COMPATIBLE
        else if (pka == PKA::ID::ECDSA) {
            hr << "ECDSA " + PKA::CURVE_NAME.at(hexlify(curve, true))
               << "ECDSA ec point: " + mpitohex(mpi[0]);
        }
        else if (pka == PKA::ID::EdDSA) {
            hr << "EdDSA " + PKA::CURVE_NAME.at(hexlify(curve, true))
               << "EdDSA ec point: " + mpitohex(mpi[0]);
        }
        else if (pka == PKA::ID::ECDH) {
            hr << "ECDH " + PKA::CURVE_NAME.at(hexlify(curve, true))
               << "ECDH ec point: " + mpitohex(mpi[0]);
        }
        #endif
        else if (pka == PKA::ID::DSA) {
            hr << "DSA p (" + std::to_string(bitsize(mpi[0])) + " bits): " + mpitohex(mpi[0])
               << "DSA q (" + std::to_string(bitsize(mpi[1])) + " bits): " + mpitohex(mpi[1])
               << "DSA g (" + std::to_string(bitsize(mpi[2])) + " bits): " + mpitohex(mpi[2])
               << "DSA y (" + std::to_string(bitsize(mpi[3])) + " bits): " + mpitohex(mpi[3]);
        }
    }
}

std::string Key::raw_common() const {
    std::string out = std::string(1, version) + unhexlify(makehex(time, 8));
    if (version < 4) { // to recreate older keys
        out += unhexlify(makehex(expire, 4));
    }

    out += std::string(1, pka);

    #ifdef GPG_COMPATIBLE
    if (pka == PKA::ID::ECDSA || pka == PKA::ID::EdDSA || pka == PKA::ID::ECDH) {
        out += std::string(1, PKA::CURVE_OID_LENGTH.at(hexlify(curve, true)));
        //out += curve.size();
        out += curve;
    }
    #endif

    for(MPI const m : mpi) {
        out += write_MPI(m);
    }

    #ifdef GPG_COMPATIBLE
    if (pka == PKA::ID::ECDH) {
        out += kdf_size; // Should be one
        out += std::string(1, 1);
        out += kdf_hash;
        out += kdf_alg;
    }
    #endif

    return out;
}

uint32_t Key::get_time() const {
    return time;
}

uint32_t Key::get_expire() const {
    if (version < 4) {
        return expire;
    }
    else{
        throw std::runtime_error("Expiration time is defined only for version 3");
    }
}

uint8_t Key::get_pka() const {
    return pka;
}

PKA::Values Key::get_mpi() const {
    return mpi;
}

void Key::set_time(uint32_t t) {
    time = t;
}

void Key::set_expire(const uint32_t t) {
    expire = t;
}

void Key::set_pka(uint8_t p) {
    pka = p;
}

void Key::set_mpi(const PKA::Values & m) {
    mpi = m;
}

std::string Key::get_fingerprint() const {
    if (version < 4) {
        std::string data = "";
        for(MPI const & i : mpi) {
            std::string m = write_MPI(i);
            data += m.substr(2, m.size() - 2);
        }
        return Hash::MD5(data).digest();
    }
    else if (version == 4) {
        const std::string packet = raw_common();
        return Hash::SHA1("\x99" + unhexlify(makehex(packet.size(), 4)) + packet).digest();
    }
    else{
        throw std::runtime_error("Error: Key packet version " + std::to_string(version) + " not defined.");
    }
    return ""; // should never reach here; mainly just to remove compiler warnings
}

std::string Key::get_keyid() const {
    if (version < 4) {
        std::string data = write_MPI(mpi[0]);
        return data.substr(data.size() - 8, 8);
    }
    else if (version == 4) {
        return get_fingerprint().substr(12, 8);
    }
    else{
        throw std::runtime_error("Error: Key packet version " + std::to_string(version) + " not defined.");
    }
    return ""; // should never reach here; mainly just to remove compiler warnings
}

#ifdef GPG_COMPATIBLE
std::string Key::get_curve() const {
    return curve;
}
void Key::set_curve(const std::string c) {
    curve = c;
}
uint8_t Key::get_kdf_hash() const {
    return kdf_hash;
}
void Key::set_kdf_hash(const uint8_t h) {
    kdf_hash = h;
}
uint8_t Key::get_kdf_alg() const {
    return kdf_alg;
}
void Key::set_kdf_alg(const uint8_t a) {
    kdf_alg = a;
}
#endif

Tag::Ptr Key::clone() const {
    return std::make_shared <Key> (*this);
}

}
}
