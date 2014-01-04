#include "PGPPrivateKey.h"
PGPPrivateKey::PGPPrivateKey(){
    ASCII_Armor = 2;
}

PGPPrivateKey::PGPPrivateKey(const PGPPrivateKey & pgp){
    if (pgp.ASCII_Armor != 2){
        std::cerr << "Error: Input is not a PGP Private Key." << std::endl;
        throw 1;
    }
    ASCII_Armor = pgp.ASCII_Armor;
    Armor_Header = pgp.Armor_Header;
    for(Packet * const & p : pgp.packets){
        packets.push_back(p -> clone());
    }
}

PGPPrivateKey::PGPPrivateKey(std::string & data){
    armored = true;
    read(data, 2);
}

PGPPrivateKey::PGPPrivateKey(std::ifstream & f){
    armored = true;
    read(f, 2);
}
