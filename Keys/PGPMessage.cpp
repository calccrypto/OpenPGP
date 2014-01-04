#include "PGPMessage.h"
PGPMessage::PGPMessage(){
    ASCII_Armor = 0;
}

PGPMessage::PGPMessage(const PGPMessage & pgp){
    if (pgp.ASCII_Armor != 0){
        std::cerr << "Error: Input is not a PGP Message." << std::endl;
        throw 1;
    }
    ASCII_Armor = pgp.ASCII_Armor;
    Armor_Header = pgp.Armor_Header;
    for(Packet * const & p : pgp.packets){
        packets.push_back(p -> clone());
    }
}

PGPMessage::PGPMessage(std::string & data){
    armored = true;
    read(data, 0);
}

PGPMessage::PGPMessage(std::ifstream & f){
    armored = true;
    read(f, 0);
}


