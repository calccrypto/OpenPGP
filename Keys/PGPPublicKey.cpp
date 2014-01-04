#include "PGPPublicKey.h"
PGPPublicKey::PGPPublicKey(){
    ASCII_Armor = 1;
}

PGPPublicKey::PGPPublicKey(const PGPPublicKey & pgp){
    if (pgp.ASCII_Armor != 1){
        std::cerr << "Error: Input is not a PGP Public Key." << std::endl;
        throw 1;
    }
    ASCII_Armor = pgp.ASCII_Armor;
    Armor_Header = pgp.Armor_Header;
    for(Packet * const & p : pgp.packets){
        packets.push_back(p -> clone());
    }
}

PGPPublicKey::PGPPublicKey(std::string & data){
    armored = true;
    read(data, 1);
}

PGPPublicKey::PGPPublicKey(std::ifstream & f){
    armored = true;
    read(f, 1);
}
