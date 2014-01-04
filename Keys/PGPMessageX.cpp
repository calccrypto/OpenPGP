#include "PGPMessageX.h"
PGPMessageX::PGPMessageX(){
    ASCII_Armor = 4;
}

PGPMessageX::PGPMessageX(const PGPMessageX & pgp){
    if (pgp.ASCII_Armor != 4){
        std::cerr << "Error: Input is not a PGP Message, Part X." << std::endl;
        throw 1;
    }
    ASCII_Armor = pgp.ASCII_Armor;
    Armor_Header = pgp.Armor_Header;
    for(Packet * const & p : pgp.packets){
        packets.push_back(p -> clone());
    }
}

PGPMessageX::PGPMessageX(std::string & data){
    armored = true;
    read(data, 4);
}

PGPMessageX::PGPMessageX(std::ifstream & f){
    armored = true;
    read(f, 4);
}

