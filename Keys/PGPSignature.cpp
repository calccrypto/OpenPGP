#include "PGPSignature.h"
PGPSignature::PGPSignature(){
    ASCII_Armor = 5;
}

PGPSignature::PGPSignature(const PGPSignature & pgp){
    if (pgp.ASCII_Armor != 5){
        std::cerr << "Error: Input is not a PGP Signature." << std::endl;
        throw 1;
    }
    ASCII_Armor = pgp.ASCII_Armor;
    Armor_Header = pgp.Armor_Header;
    for(Packet * const & p : pgp.packets){
        packets.push_back(p -> clone());
    }
}

PGPSignature::PGPSignature(std::string & data){
    armored = true;
    read(data, 5);
}

PGPSignature::PGPSignature(std::ifstream & f){
    armored = true;
    read(f, 5);
}
