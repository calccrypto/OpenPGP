#include "PGPMessage.h"

// OpenPGP Message :- Encrypted Message | Signed Message | Compressed Message | Literal Message.
const bool PGPMessage::OpenPGPMessage(std::list <Token>::iterator it) const{
    if ((*it == ENCRYPTEDMESSAGE) || (*it == SIGNEDMESSAGE) || (*it == COMPRESSEDMESSAGE) || (*it == LITERALMESSAGE)){
        *it = OPENPGPMESSAGE;
        return true;
    }
    return false;
}

// Compressed Message :- Compressed Data Packet.
const bool PGPMessage::CompressedMessage(std::list <Token>::iterator it) const{
    if (*it == CDP){
        *it = COMPRESSEDMESSAGE;
        return true;
    }
    return false;
}

// Literal Message :- Literal Data Packet.
const bool PGPMessage::LiteralMessage(std::list <Token>::iterator it) const{
    if (*it == LDP){
        *it = LITERALMESSAGE;
        return true;
    }
    return false;
}

// ESK :- Public-Key Encrypted Session Key Packet | Symmetric-Key Encrypted Session Key Packet.
const bool PGPMessage::EncryptedSessionKey(std::list <Token>::iterator it) const{
    if ((*it == PKESKP) || (*it == SKESKP)){
        *it = ESK;
        return true;
    }
    return false;
}

// ESK Sequence :- ESK | ESK Sequence, ESK.
const bool PGPMessage::ESKSequence(std::list <Token>::iterator it) const{
    if ((*it == ESK) || (*it == ESKSEQUENCE)){
        *it = ESKSEQUENCE;
        return true;
    }
    return false;
}

// Encrypted Data :- Symmetrically Encrypted Data Packet | Symmetrically Encrypted Integrity Protected Data Packet
const bool PGPMessage::EncryptedData(std::list <Token>::iterator it) const{
    if ((*it == SEDP) || (*it == SEIPDP)){
        *it = ENCRYPTEDDATA;
        return true;
    }
    return false;
}

// Encrypted Message :- Encrypted Data | ESK Sequence, Encrypted Data.
const bool PGPMessage::EncryptedMessage(std::list <Token>::iterator it) const{
    std::list <Token>::iterator it2 = it; it2++;
    if (((*it == ENCRYPTEDDATA) || (*it == ESKSEQUENCE)) && (*it2 == ENCRYPTEDDATA)){
        *it = ENCRYPTEDMESSAGE;
        return true;
    }
    return false;
}

// One-Pass Signed Message :- One-Pass Signature Packet, OpenPGP Message, Corresponding Signature Packet.
const bool PGPMessage::OnePassSignedMessage(std::list <Token>::iterator it) const{
    std::list <Token>::iterator it2 = it; it2++;
    std::list <Token>::iterator it3 = it2; it3++;
    if (((*it == ENCRYPTEDDATA) || (*it == ESKSEQUENCE)) && (*it2 == OPENPGPMESSAGE) && (*it3 == SP)){
        *it = ONEPASSSIGNEDMESSAGE;
        return true;
    }
    return false;
}

// Signed Message :- Signature Packet, OpenPGP Message | One-Pass Signed Message.
const bool PGPMessage::SignedMessage(std::list <Token>::iterator it) const{
    std::list <Token>::iterator it2 = it; it2++;
    if ((*it == SP) && ((*it2 == OPENPGPMESSAGE) || (*it2 == ONEPASSSIGNEDMESSAGE))){
        *it = SIGNEDMESSAGE;
        return true;
    }
    return false;
}

PGPMessage::PGPMessage():
    PGP()
{}

PGPMessage::PGPMessage(const PGPMessage & copy):
    PGP(copy)
{}

PGPMessage::PGPMessage(std::string & data):
    PGP(data)
{}

PGPMessage::PGPMessage(std::ifstream & f):
    PGP(f)
{}

PGPMessage::~PGPMessage(){}

PGP::Ptr PGPMessage::clone() const{
    return PGPMessage::Ptr(new PGPMessage);
}

bool PGPMessage::meaningful() const{
    // get list of packets and convert them to Token
    std::list <Token> sentence;
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
                break;
        }
        sentence.push_back(push);
    }
    
    while ((*(sentence.begin()) != OPENPGPMESSAGE) || (sentence.size() != 1)){ // while the sentence has not been fully parsed, or has been fully parse but not correctly
        bool reduced = false;
        for(std::list <Token>::iterator it = sentence.begin(); it != sentence.end(); it++){ // for each token
            // make sure the sentence continues to fit at least one of the rules at least once per loop over the sentence
            if (OpenPGPMessage(it) || CompressedMessage(it) || LiteralMessage(it) || 
                EncryptedSessionKey(it) || ESKSequence(it) || EncryptedData(it) || 
                EncryptedMessage(it) || OnePassSignedMessage(it) || SignedMessage(it)){
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
