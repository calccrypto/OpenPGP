#include "PGPMessageXY.h"
PGPMessageXY::PGPMessageXY(){
    ASCII_Armor = 2;
}

PGPMessageXY::PGPMessageXY(const PGPMessageXY & pgp){
    if (pgp.ASCII_Armor != 2){
        std::cerr << "Error: Input is not a PGP Message, Part X of Y." << std::endl;
        throw 1;
    }
    ASCII_Armor = pgp.ASCII_Armor;
    Armor_Header = pgp.Armor_Header;
    for(Packet * const & p : pgp.packets){
        packets.push_back(p -> clone());
    }
}

PGPMessageXY::PGPMessageXY(std::string & data){
    armored = true;
    read(data, 3);
}

PGPMessageXY::PGPMessageXY(std::ifstream & f){
    armored = true;
    read(f, 3);
}

