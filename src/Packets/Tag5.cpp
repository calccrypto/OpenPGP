#include "Packets/Tag5.h"

namespace OpenPGP {
namespace Packet {

void Tag5::read_s2k(const std::string & data, std::string::size_type & pos) {
    s2k.reset();

    if (data[pos] == S2K::ID::SIMPLE_S2K) {
        s2k = std::make_shared <S2K::S2K0> ();
    }
    else if (data[pos] == S2K::ID::SALTED_S2K) {
        s2k = std::make_shared <S2K::S2K1> ();
    }
    else if (data[pos] == S2K::ID::ITERATED_AND_SALTED_S2K) {
        s2k = std::make_shared <S2K::S2K3> ();
    }
    else{
        throw std::runtime_error("Error: Bad S2K ID encountered: " + std::to_string(data[0]));
    }

    s2k -> read(data, pos);
}

void Tag5::actual_read(const std::string & data, std::string::size_type & pos, const std::string::size_type & length) {
    const std::string::size_type orig_pos = pos;

    // public data
    read_common(data, pos);

    // S2K usage octet
    s2k_con = data[pos++];
    if ((s2k_con != 0) && (s2k_con != 254) && (s2k_con != 255)) {
        sym = s2k_con;
    }

    // one octet symmetric key encryption algorithm
    if ((s2k_con == 254) || (s2k_con == 255)) {
        sym = data[pos++];
    }

    // S2K specifier
    if ((s2k_con == 254) || (s2k_con == 255)) {
        read_s2k(data, pos);
    }

    // IV
    if (s2k_con) {
        IV = data.substr(pos, Sym::BLOCK_LENGTH.at(sym) >> 3);
        pos += IV.size();
    }

    // plaintex or encrypted data
    secret = data.substr(pos, length - (pos - orig_pos));

    pos = orig_pos + length;
}

void Tag5::show_private(HumanReadable & hr) const {
    if (s2k_con > 253) {
        hr << "String-to-Key Usage Conventions: " + std::to_string(s2k_con)
           << "Symmetric Key Algorithm: " + get_mapped(Sym::NAME, sym) + " (sym " + std::to_string(sym) + ")";
        s2k -> show(hr);
        if (s2k -> get_type()) {
            hr << "IV: " + hexlify(IV);
        }
    }

    if (s2k_con) {
        hr << "Encrypted Data (" + std::to_string(secret.size()) + " octets):"
           << HumanReadable::DOWN;

        std::string line = "";
        if (PKA::is_RSA(pka)) {
            line += "RSA d, p, q, u";
        }
        else if (pka == PKA::ID::ELGAMAL) {
            line += "ELGAMAL x";
        }
        else if (pka == PKA::ID::DSA) {
            line += "DSA x";
        }
        #ifdef GPG_COMPATIBLE
        else if (pka == PKA::ID::ECDSA) {
            line += "ECDSA x";
        }
        else if (pka == PKA::ID::EdDSA) {
            line += "EdDSA x";
        }
        else if (pka == PKA::ID::ECDH) {
            line += "ECDH x";
        }
        #endif
        else{
            line += "Unknown";
        }
        line += " + ";

        if (s2k_con == 254) {
            line += "SHA1 hash";
        }
        else{
            line += "2 Octet Checksum";
        }

        line += ": " + hexlify(secret);
        hr << line << HumanReadable::UP;
    }
    else{
        std::string::size_type pos = 0;

        if (PKA::is_RSA(pka)) {
            const MPI d = read_MPI(secret, pos);
            const MPI p = read_MPI(secret, pos);
            const MPI q = read_MPI(secret, pos);
            const MPI u = read_MPI(secret, pos);
            hr << "RSA d: (" + std::to_string(bitsize(d)) + ") bits: " + mpitohex(d)
               << "RSA p: (" + std::to_string(bitsize(p)) + ") bits: " + mpitohex(p)
               << "RSA q: (" + std::to_string(bitsize(q)) + ") bits: " + mpitohex(q)
               << "RSA u: (" + std::to_string(bitsize(u)) + ") bits: " + mpitohex(u);
        }
        else if (pka == PKA::ID::ELGAMAL) {
            const MPI x = read_MPI(secret, pos);
            hr << "ELGAMAL x: (" + std::to_string(bitsize(x)) + ") bits: " + mpitohex(x);
        }
        else if (pka == PKA::ID::DSA) {
            const MPI x = read_MPI(secret, pos);
            hr << "DSA x: (" + std::to_string(bitsize(x)) + ") bits: " + mpitohex(x);
        }
        #ifdef GPG_COMPATIBLE
        else if (pka == PKA::ID::ECDSA) {
            const MPI x = read_MPI(secret, pos);
            hr << "ECDSA x: (" + std::to_string(bitsize(x)) + ") bits: " + mpitohex(x);
        }
        else if (pka == PKA::ID::DSA) {
            const MPI x = read_MPI(secret, pos);
            hr << "EdDSA x: (" + std::to_string(bitsize(x)) + ") bits: " + mpitohex(x);
        }
        else if (pka == PKA::ID::ECDH) {
            const MPI x = read_MPI(secret, pos);
            hr << "ECDH x: (" + std::to_string(bitsize(x)) + ") bits: " + mpitohex(x);
        }
        #endif
        else{
            hr << "Unknown";
        }

        if (s2k_con == 254) {
            hr << "SHA1 hash: " + hexlify(secret.substr(pos, 20));
        }
        else{
            hr << "2 Octet Checksum : " + hexlify(secret.substr(pos, 2));
        }
    }
}

void Tag5::show_contents(HumanReadable & hr) const {
    show_common(hr);
    show_private(hr);
}

std::string Tag5::actual_raw() const {
    std::string out = raw_common() +            // public data
                      std::string(1, s2k_con);  // S2K usage octet
    if ((s2k_con == 254) || (s2k_con == 255)) {
        if (!s2k) {
            throw std::runtime_error("Error: S2K has not been set.");
        }
        out += std::string(1, sym);             // one octet symmetric key encryption algorithm
    }

    if ((s2k_con == 254) || (s2k_con == 255)) {
        if (!s2k) {
            throw std::runtime_error("Error: S2K has not been set.");
        }
        out += s2k -> write();                  // S2K specifier
    }

    if (s2k_con) {
        out += IV;                              // IV
    }

    return out + secret;
}

Error Tag5::actual_valid(const bool check_mpi) const {
    Error valid_public = Tag6::actual_valid(check_mpi);
    if (valid_public != Error::SUCCESS) {
        return valid_public;
    }

    if ((s2k_con == 254) || (s2k_con == 255)) {
        if (!s2k) {
            return Error::MISSING_S2K;
        }
    }
    else if (s2k_con != 0) {
        if (!Sym::valid(sym)) {
            return Error::INVALID_SYMMETRIC_ENCRYPTION_ALGORITHM;
        }
    }

    if (s2k_con) {
       if (IV.size() != (Sym::BLOCK_LENGTH.at(sym) >> 3)) {
            return Error::INVALID_LENGTH;
        }
    }

    return Error::SUCCESS;
}

Tag5::Tag5(const uint8_t tag)
    : Tag6(tag),
      s2k_con(0),
      sym(0),
      s2k(),
      IV(),
      secret()
{}

Tag5::Tag5()
    : Tag5(SECRET_KEY)
{}

Tag5::Tag5(const Tag5 & copy)
    : Tag6(copy),
      s2k_con(copy.s2k_con),
      sym(copy.sym),
      s2k(copy.s2k),
      IV(copy.IV),
      secret(copy.secret)
{
    s2k = s2k?s2k -> clone():nullptr;
}

Tag5::Tag5(const std::string & data)
    : Tag5(SECRET_KEY)
{
    read(data);
}

Tag5::~Tag5() {}

uint8_t Tag5::get_s2k_con() const {
    return s2k_con;
}

uint8_t Tag5::get_sym() const {
    return sym;
}

S2K::S2K::Ptr Tag5::get_s2k() const {
    return s2k;
}

S2K::S2K::Ptr Tag5::get_s2k_clone() const {
    return s2k -> clone();
}

std::string Tag5::get_IV() const {
    return IV;
}

std::string Tag5::get_secret() const {
    return secret;
}

Tag6 Tag5::get_public_obj() const {
    Tag6 out(raw());
    out.set_tag(PUBLIC_KEY);
    return out;
}

Tag6::Ptr Tag5::get_public_ptr() const {
    return std::make_shared <Packet::Tag6> (raw());
}

void Tag5::set_s2k_con(const uint8_t c) {
    s2k_con = c;
    size = raw_common().size() + 1;
    if (s2k) {
        size += s2k -> write().size();
    }
    if (s2k_con) {
        size += IV.size();
    }
    size += secret.size();
}

void Tag5::set_sym(const uint8_t s) {
    sym = s;
    size = raw_common().size() + 1;
    if (s2k) {
        size += s2k -> write().size();
    }
    if (s2k_con) {
        size += IV.size();
    }
    size += secret.size();
}

void Tag5::set_s2k(const S2K::S2K::Ptr & s) {
    if (s -> get_type() == S2K::ID::SIMPLE_S2K) {
        s2k = std::make_shared <S2K::S2K0> ();
    }
    else if (s -> get_type() == S2K::ID::SALTED_S2K) {
        s2k = std::make_shared <S2K::S2K1> ();
    }
    else if (s -> get_type() == S2K::ID::ITERATED_AND_SALTED_S2K) {
        s2k = std::make_shared <S2K::S2K3> ();
    }
    s2k = s -> clone();
    size = raw_common().size() + 1;
    if (s2k) {
        size += s2k -> write().size();
    }
    if (s2k_con) {
        size += IV.size();
    }
    size += secret.size();
}

void Tag5::set_IV(const std::string & iv) {
    IV = iv;
    size = raw_common().size() + 1;
    if (s2k) {
        size += s2k -> write().size();
    }
    if (s2k_con) {
        size += IV.size();
    }
    size += secret.size();
}

void Tag5::set_secret(const std::string & s) {
    secret = s;
    size = raw_common().size() + 1;
    if (s2k) {
        size += s2k -> write().size();
    }
    if (s2k_con) {
        size += IV.size();
    }
    size += secret.size();
}

std::string Tag5::calculate_key(const std::string & passphrase) const {
    std::string key;

    if (s2k_con == 0) {                                  // No S2K
        // not encrypted
    }
    else if ((s2k_con == 254) || (s2k_con == 255)) {     // S2K exists
        if (!s2k) {
            throw std::runtime_error("Error: S2K has not been set.");
        }

        key = s2k -> run(passphrase, Sym::KEY_LENGTH.at(sym) >> 3);
    }
    else{
        key = Hash::MD5(passphrase).digest();            // simple MD5 for all other values
    }

    return key;
}

const std::string & Tag5::encrypt_secret_keys(const std::string & passphrase, const PKA::Values & keys) {
    secret = "";

    // convert keys into string
    for(MPI const & mpi : keys) {
        secret += write_MPI(mpi);
    }

    // calculate checksum
    if(s2k_con == 254) {
        secret += Hash::use(s2k -> get_hash(), secret); // SHA1
    }
    else{
        uint16_t sum = 0;
        for(char const & c : secret) {
            sum += static_cast <unsigned char> (c);
        }

        secret += unhexlify(makehex(sum, 4));
    }

    if (s2k_con) {   // secret needs to be encrypted
        // calculate key to encrypt
        const std::string key = calculate_key(passphrase);

        // encrypt
        secret = use_normal_CFB_encrypt(sym, secret, key, IV);
    }

    return secret;
}

PKA::Values Tag5::decrypt_secret_keys(const std::string & passphrase) const {
    std::string keys;

    // S2k != 0 -> secret keys are encrypted
    if (s2k_con) {
        // calculate key to decrypt
        const std::string key = calculate_key(passphrase);

        // decrypt
        keys = use_normal_CFB_decrypt(sym, secret, key, IV);
    }
    else{
        keys = secret;
    }

    // remove checksum from cleartext key string
    const unsigned int hash_size = (s2k_con == 254)?20:2;
    const std::string given_checksum = keys.substr(keys.size() - hash_size, hash_size);
    keys = keys.substr(0, keys.size() - hash_size);

    // calculate and check checksum
    std::string calculated_checksum;
    if(s2k_con == 254) {
        calculated_checksum = Hash::use(Hash::ID::SHA1, keys);
    }
    else{
        uint16_t sum = 0;
        for(char const & c : keys) {
            sum += static_cast <unsigned char> (c);
        }

        calculated_checksum = unhexlify(makehex(sum, 4));
    }

    if (calculated_checksum != given_checksum) {
        throw std::runtime_error("Error: Secret key checksum and calculated checksum do not match.");
    }

    // extract MPI values
    PKA::Values out;
    std::string::size_type pos = 0;
    while (pos < keys.size()) {
        out.push_back(read_MPI(keys, pos));
    }

    return out;
}

Tag::Ptr Tag5::clone() const {
    Ptr out = std::make_shared <Packet::Tag5> (*this);
    out -> s2k = s2k?s2k -> clone():nullptr;
    return out;
}

Tag5 & Tag5::operator=(const Tag5 & copy) {
    Key::operator=(copy);
    s2k_con = copy.s2k_con;
    sym = copy.sym;
    s2k = copy.s2k?copy.s2k -> clone():nullptr;
    IV = copy.IV;
    secret = copy.secret;
    return *this;
}

}
}
