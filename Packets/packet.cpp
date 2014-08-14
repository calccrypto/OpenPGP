#include "packet.h"
std::string Packet::write_old_length(std::string data) const{
    unsigned int length = data.size();
    std::string out(1, 0b10000000 | (tag << 2));
    if (partial){
        out[0] |= 3;                                        // partial
    }
    else {
        if (length < 256){
            out[0] |= 0;                                    // 1 octet
            out += std::string(1, length);
        }
        else if ((256 <= length) && (length < 65536)){      // 2 octest
            out[0] |= 1;
            out += unhexlify(makehex(length, 4));
        }
        else if (65536 <= length){                          // 4 octets
            out[0] |= 2;
            out += unhexlify(makehex(length, 8));
        }
    }
    return out + data;
}

// returns formatted length string
std::string Packet::write_new_length(std::string data) const{
    std::string out(1, 0b11000000 | tag);
    unsigned int length = data.size();
    if (partial){                                           // partial
        uint8_t bits = 0;
        while (length > (1u << bits)){
            bits++;
        }
        length = 224 + bits;
        if (length > 254){
            throw std::runtime_error("Error: Data in partial packet too large.");
        }

        out += std::string(1, length);
    }
    else{
        if (length < 192){                                  // 1 octet
            out += std::string(1, length);
        }
        else if ((192 <= length) && (length < 8383)){       // 2 octets
            length -= 0xc0;
            out += std::string(1, (length >> 8) + 0xc0 ) + std::string(1, length & 0xff);
        }
        else if (length > 8383){                            // 3 octets
            out += std::string(1, '\xff') + unhexlify(makehex(length, 8));
        }
    }
    return out + data;
}

std::string Packet::show_title() const{
    std::stringstream out;
    out << (format?"New":"Old") << ": " << Packet_Tags.at(tag) << " (Tag " << static_cast <unsigned int> (tag) << ")";

    switch (partial){
        case 0:
            break;
        case 1:
            out << " (partial start)";
            break;
        case 2:
            out << " (partial continue)";
            break;
        case 3:
            out << " (partial end)";
            break;
        default:
            {
                std::stringstream s; s << static_cast <unsigned int> (partial);
                throw std::runtime_error("Error: Unknown partial type: " + s.str());
            }
            break;
    }
    return out.str();
}

Packet::Packet(uint8_t tag, uint8_t version):
    tag(tag),
    version(version),
    format(true),
    size(0),
    partial(0)
{}

Packet::Packet(uint8_t tag):
    Packet(tag, 0)
{}

Packet::Packet():
    Packet(0)
{}

Packet::~Packet(){}

std::string Packet::write(uint8_t header) const{
    if ((header && ((header == 2) ||                          // if user set new packet header or
       ((header == 1) && (tag > 15)))) ||                     // if user set new packet header but tag is greater than 15 or
       (!header && ((format || ((!format) && (tag > 15)))))){ // if user did not set packet header and format is new, or format is old but tag is greater than 15
        return write_new_length(raw());
    }
    return write_old_length(raw());
}

uint8_t Packet::get_tag() const{
    return tag;
}

bool Packet::get_format() const{
    return format;
}

unsigned int Packet::get_version() const{
    return version;
}

unsigned int Packet::get_size() const{
    return size;
}

uint8_t Packet::get_partial() const{
    return partial;
}

void Packet::set_tag(const uint8_t t){
    tag = t;
}

void Packet::set_format(const bool f){
    format = f;
}

void Packet::set_version(const unsigned int v){
    version = v;
}

void Packet::set_size(const unsigned int s){
    size = s;
}

void Packet::set_partial(const uint8_t p){
    partial = p;
}

Packet::Packet(const Packet &copy):
    tag(copy.tag),
    version(copy.version),
    format(copy.format),
    size(copy.size),
    partial(copy.partial)
{}

Packet & Packet::operator=(const Packet & copy)
{
    tag = copy.tag;
    version = copy.version;
    format = copy.format;
    size = copy.size;
    partial = copy.partial;
    return *this;
}

void Key::read_common(std::string & data){
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

std::string Key::show_common(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    std::stringstream out;
    out << std::string(tab, ' ') << "    Version: " << static_cast <unsigned int> (version) << " - " << ((version < 4)?"Old":"New") << "\n"
        << std::string(tab, ' ') << "    Creation Time: " << show_time(time);
    if (version < 4){
        out << "\n"
            << std::string(tab, ' ') << "    Expiration Time (Days): " << expire;
        if (!expire){
            out << " (Never)";
        }
        out << "\n"
            << std::string(tab, ' ') << "    Public Key Algorithm: " << Public_Key_Algorithms.at(pka) << " (pka " << static_cast <unsigned int> (pka) << ")\n"
            << std::string(tab, ' ') << "    RSA n: " << mpitohex(mpi[0]) << "(" << bitsize(mpi[0]) << " bits)\n"
            << std::string(tab, ' ') << "    RSA e: " << mpitohex(mpi[1]);
    }
    else if (version == 4){
        out << "\n"
            << std::string(tab, ' ') << "    Public Key Algorithm: " << Public_Key_Algorithms.at(pka) << " (pka " << static_cast <unsigned int> (pka) << ")\n";
        if (pka < 4){
            out << std::string(tab, ' ') << "    RSA n (" << bitsize(mpi[0]) << " bits): " << mpitohex(mpi[0]) << "\n"
                << std::string(tab, ' ') << "    RSA e (" << bitsize(mpi[1]) << " bits): " << mpitohex(mpi[1]);
        }
        else if (pka == 17){
            out << std::string(tab, ' ') << "    DSA p (" << bitsize(mpi[0]) << " bits): " << mpitohex(mpi[0]) << "\n"
                << std::string(tab, ' ') << "    DSA q (" << bitsize(mpi[1]) << " bits): " << mpitohex(mpi[1]) << "\n"
                << std::string(tab, ' ') << "    DSA g (" << bitsize(mpi[2]) << " bits): " << mpitohex(mpi[2]) << "\n"
                << std::string(tab, ' ') << "    DSA y (" << bitsize(mpi[3]) << " bits): " << mpitohex(mpi[3]);
        }
        else if (pka == 16){
            out << std::string(tab, ' ') << "    Elgamal p (" << bitsize(mpi[0]) << " bits): " << mpitohex(mpi[0]) << "\n"
                << std::string(tab, ' ') << "    Elgamal g (" << bitsize(mpi[1]) << " bits): " << mpitohex(mpi[1]) << "\n"
                << std::string(tab, ' ') << "    Elgamal y (" << bitsize(mpi[2]) << " bits): " << mpitohex(mpi[2]);
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

Key::Key(uint8_t tag):
    Packet(tag),
    time(),
    pka(),
    mpi(),
    expire()
{}

Key::Key():
    Key(0)
{}

Key::Key(const Key & copy):
    Packet(copy),
    time(copy.time),
    pka(copy.pka),
    mpi(copy.mpi),
    expire(copy.expire)
{}

Key::Key(std::string & data):
    Key()
{
    read(data);
}

Key::~Key(){}

void Key::read(std::string & data, const uint8_t part){
    read_common(data);
}

std::string Key::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    return std::string(tab, ' ') + show_title() + "\n" + show_common(indents, indent_size);
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

ID::~ID(){}

ID & ID::operator=(const ID & copy)
{
    Packet::operator=(copy);
    return *this;
}
