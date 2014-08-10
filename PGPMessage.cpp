#include "PGPMessage.h"

// OpenPGP Message :- Encrypted Message | Signed Message | Compressed Message | Literal Message.
const bool PGPMessage::OpenPGPMessage(std::list <Token>::iterator it, std::list <Token> & s) const{
    if ((*it == ENCRYPTEDMESSAGE) || (*it == SIGNEDMESSAGE) || (*it == COMPRESSEDMESSAGE) || (*it == LITERALMESSAGE)){
        *it = OPENPGPMESSAGE;
        return true;
    }
    return false;
}

// Compressed Message :- Compressed Data Packet.
const bool PGPMessage::CompressedMessage(std::list <Token>::iterator it, std::list <Token> & s) const{
    if (*it == CDP){
        *it = COMPRESSEDMESSAGE;
        return true;
    }
    return false;
}

// Literal Message :- Literal Data Packet.
const bool PGPMessage::LiteralMessage(std::list <Token>::iterator it, std::list <Token> & s) const{
    if (*it == LDP){
        *it = LITERALMESSAGE;
        return true;
    }
    return false;
}

// ESK :- Public-Key Encrypted Session Key Packet | Symmetric-Key Encrypted Session Key Packet.
const bool PGPMessage::EncryptedSessionKey(std::list <Token>::iterator it, std::list <Token> & s) const{
    if ((*it == PKESKP) || (*it == SKESKP)){
        *it = ESK;
        return true;
    }
    return false;
}

// ESK Sequence :- ESK | ESK Sequence, ESK.
const bool PGPMessage::ESKSequence(std::list <Token>::iterator it, std::list <Token> & s) const{
    if (*it == ESK){
        *it = ESKSEQUENCE;
        return true;
    }
    else if (*it == ESKSEQUENCE){
        std::list <Token>::iterator it2 = it; it2++;
        if (*it2 == ESK){
            s.erase(it2);
            *it = ESKSEQUENCE;
            return true;
        }
    }
    return false;
}

// Encrypted Data :- Symmetrically Encrypted Data Packet | Symmetrically Encrypted Integrity Protected Data Packet
const bool PGPMessage::EncryptedData(std::list <Token>::iterator it, std::list <Token> & s) const{
    if ((*it == SEDP) || (*it == SEIPDP)){
        *it = ENCRYPTEDDATA;
        return true;
    }
    return false;
}

// Encrypted Message :- Encrypted Data | ESK Sequence, Encrypted Data.
const bool PGPMessage::EncryptedMessage(std::list <Token>::iterator it, std::list <Token> & s) const{
    if (*it == ENCRYPTEDDATA){
        *it = ENCRYPTEDMESSAGE;
        return true;
    }
    else if (*it == ESKSEQUENCE){
        std::list <Token>::iterator it2 = it; it2++;
        if (*it2 == ENCRYPTEDDATA){
            *it = ENCRYPTEDMESSAGE;
            s.erase(it2);
            return true;
        }
    }
    return false;
}

// One-Pass Signed Message :- One-Pass Signature Packet, OpenPGP Message, Corresponding Signature Packet.
const bool PGPMessage::OnePassSignedMessage(std::list <Token>::iterator it, std::list <Token> & s) const{
    std::list <Token>::iterator it2 = it; it2++;
    std::list <Token>::iterator it3 = it2; it3++;
    if ((*it == OPSP) && (*it2 == OPENPGPMESSAGE) && (*it3 == SP)){
        *it = ONEPASSSIGNEDMESSAGE;
        s.erase(it2);
        s.erase(it3);
        return true;
    }
    return false;
}

// Signed Message :- Signature Packet, OpenPGP Message | One-Pass Signed Message.
const bool PGPMessage::SignedMessage(std::list <Token>::iterator it, std::list <Token> & s) const{
    if (*it == ONEPASSSIGNEDMESSAGE){
        *it = SIGNEDMESSAGE;
        return true;
    }
    else if (*it == SP){
        std::list <Token>::iterator it2 = it; it2++;
        if (*it2 == OPENPGPMESSAGE){
            *it = SIGNEDMESSAGE;
            s.erase(it2);
            return true;
        }
    }
    return false;
}

PGPMessage::PGPMessage():
    PGP()
{
    ASCII_Armor = 6;
}

PGPMessage::PGPMessage(const PGPMessage & copy):
    PGP(copy)
{
    if ((ASCII_Armor == 255) && meaningful()){
        ASCII_Armor = 6;
    }
}

PGPMessage::PGPMessage(std::string & data):
    PGP(data)
{
    if ((ASCII_Armor == 255) && meaningful()){
        ASCII_Armor = 6;
    }
}

PGPMessage::PGPMessage(std::ifstream & f):
    PGP(f)
{
    if ((ASCII_Armor == 255) && meaningful()){
        ASCII_Armor = 6;
    }
}

PGPMessage::~PGPMessage(){}

const bool PGPMessage::match(const Token & t) const{
    if (!packets.size()){
        return false;
    }

    if ((t != OPENPGPMESSAGE) && (t != ENCRYPTEDMESSAGE)  &&
        (t != SIGNEDMESSAGE)  && (t != COMPRESSEDMESSAGE) &&
        (t != LITERALMESSAGE)){
        throw std::runtime_error("Error: Invalid token to match");
        // return false;
    }

    // get list of packets and convert them to Token
    std::list <Token> s;
    for(const Packet::Ptr & p : packets){
        Token push;
        switch(p -> get_tag()){
            case 8:
                push = CDP;
                break;
            case 11:
                push = LDP;
                break;
            case 1:
                push = PKESKP;
                break;
            case 3:
                push = SKESKP;
                break;
            case 9:
                push = SEDP;
                break;
            case 18:
                push = SEIPDP;
                break;
            case 4:
                push = OPSP;
                break;
            case 2:
                push = SP;
                break;
            default:
                throw std::runtime_error("Error: Non-Message packet found.");
                // return false;
                break;
        }
        s.push_back(push);
    }

    while ((*(s.begin()) != t) || (s.size() != 1)){ // while the sentence has not been fully parsed, or has been fully parse but not correctly
        bool reduced = false;
        for(std::list <Token>::iterator it = s.begin(); it != s.end(); it++){ // for each token
            // make sure the sentence continues to fit at least one of the rules at least once per loop over the sentence
            if (OpenPGPMessage(it, s) || CompressedMessage(it, s) || LiteralMessage(it, s) ||
                EncryptedSessionKey(it, s) || ESKSequence(it, s) || EncryptedData(it, s) ||
                EncryptedMessage(it, s) || OnePassSignedMessage(it, s) || SignedMessage(it, s)){
                reduced = true;
                break;
            }
        }
        if (!reduced){
            return false;
        }
    }
    return true;
}

bool PGPMessage::meaningful() const {
    return match(OPENPGPMESSAGE);
}

PGP::Ptr PGPMessage::clone() const{
    return PGPMessage::Ptr(new PGPMessage);
}