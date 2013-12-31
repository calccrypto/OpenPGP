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
        mpi.push_back(read_MPI(data));              // RSA n, DSA p, ElGamal p
        mpi.push_back(read_MPI(data));              // RSA e, DSA q, ElGamal g

        // DSA
        if (pka == 17){
            mpi.push_back(read_MPI(data));          // DSA g
            mpi.push_back(read_MPI(data));          // DSA y
        }
        // Elgamal
        else if (pka == 16)
            mpi.push_back(read_MPI(data));          // ElGamal y
    }
}

std::string Tag6::show_tag6(){
    std::stringstream out;
    out << "    Version: " << (unsigned int) version << " - " << ((version < 4)?"Old":"New") << "\n"
        << "    Creation Time: " << show_time(time) << "\n";
    if (version < 4){
        out << "    Expiration Time (Days): " << expire;
        if (!expire){
            out << " (Never)";
        }
        out << "\n"
            << "    Public Key Algorithm: " << Public_Key_Algorithms.at(pka) << " (pka " << (unsigned int) pka << ")\n"
            << "    RSA n: " << mpi[0].get_str(16) << "(" << mpi[0].get_str(2).size() << " bits)\n"
            << "    RSA e: " << mpi[1].get_str(16) << "\n";
    }
    else if (version == 4){
        out << "    Public Key Algorithm: " << Public_Key_Algorithms.at(pka) << " (pka " << (unsigned int) pka << ")\n";

        if (pka < 4){
            out << "    RSA n (" << mpi[0].get_str(2).size() << " bits): " << mpi[0].get_str(16) << "\n"
                << "    RSA e (" << mpi[1].get_str(2).size() << " bits): " << mpi[1].get_str(16) << "\n";
        }
        else if (pka == 17){
            out << "    DSA p (" << mpi[0].get_str(2).size() << " bits): " << mpi[0].get_str(16) << "\n"
                << "    DSA q (" << mpi[1].get_str(2).size() << " bits): " << mpi[1].get_str(16) << "\n"
                << "    DSA g (" << mpi[2].get_str(2).size() << " bits): " << mpi[2].get_str(16) << "\n"
                << "    DSA y (" << mpi[3].get_str(2).size() << " bits): " << mpi[3].get_str(16) << "\n";
        }
        else if (pka == 16){
            out << "    Elgamal p (" << mpi[0].get_str(2).size() << " bits): " << mpi[0].get_str(16) << "\n"
                << "    Elgamal g (" << mpi[1].get_str(2).size() << " bits): " << mpi[1].get_str(16) << "\n"
                << "    Elgamal y (" << mpi[2].get_str(2).size() << " bits): " << mpi[2].get_str(16) << "\n";
        }
    }
    return out.str();
}

std::string Tag6::raw_tag6(){
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

Tag6::Tag6(){
    tag = 6;
}

Tag6::Tag6(std::string & data){
    tag = 6;
    read(data);
}

void Tag6::read(std::string & data){
    read_tag6(data);
}

std::string Tag6::show(){
    return show_tag6();
}

std::string Tag6::raw(){
    return raw_tag6();
}

time_t Tag6::get_time(){
    return time;
}

uint8_t Tag6::get_pka(){
    return pka;
}

std::vector <mpz_class> Tag6::get_mpi(){
    return mpi;
}

void Tag6::set_time(time_t t){
    time = t;
}

void Tag6::set_pka(uint8_t p){
    pka = p;
}

void Tag6::set_mpi(const std::vector <mpz_class> & m){
    mpi = m;
}

std::string Tag6::get_fingerprint(){
    if (version == 3){
        std::string data = "";
        for(mpz_class & i : mpi){
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
        std::cerr << "Error: Public Key packet version " << (int) version << " not defined." << std::endl;
        throw(1);
    }
    return ""; // should never reach here; mainly just to remove compiler warnings
}

std::string Tag6::get_keyid(){
    if (version == 3){
        std::string data = write_MPI(mpi[0]);
        return data.substr(data.size() - 8, 8);
    }
    if (version == 4){
        return get_fingerprint().substr(12, 8);
    }
    else{
        std::cerr << "Error: Public Key packet version " << (int) version << " not defined." << std::endl;
        throw(1);
    }
    return ""; // should never reach here; mainly just to remove compiler warnings
}

Tag6 * Tag6::clone(){
    return new Tag6(*this);
}
