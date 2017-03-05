#include "Tag2Subpacket.h"

const uint8_t Tag2Subpacket::ID::Signature_Creation_Time                = 2;
const uint8_t Tag2Subpacket::ID::Signature_Expiration_Time              = 3;
const uint8_t Tag2Subpacket::ID::Exportable_Certification               = 4;
const uint8_t Tag2Subpacket::ID::Trust_Signature                        = 5;
const uint8_t Tag2Subpacket::ID::Regular_Expression                     = 6;
const uint8_t Tag2Subpacket::ID::Revocable                              = 7;
const uint8_t Tag2Subpacket::ID::Key_Expiration_Time                    = 9;
const uint8_t Tag2Subpacket::ID::Placeholder_for_Backward_Compatibility = 10;
const uint8_t Tag2Subpacket::ID::Preferred_Symmetric_Algorithms         = 11;
const uint8_t Tag2Subpacket::ID::Revocation_Key                         = 12;
const uint8_t Tag2Subpacket::ID::Issuer                                 = 16;
const uint8_t Tag2Subpacket::ID::Notation_Data                          = 20;
const uint8_t Tag2Subpacket::ID::Preferred_Hash_Algorithms              = 21;
const uint8_t Tag2Subpacket::ID::Preferred_Compression_Algorithms       = 22;
const uint8_t Tag2Subpacket::ID::Key_Server_Preferences                 = 23;
const uint8_t Tag2Subpacket::ID::Preferred_Key_Server                   = 24;
const uint8_t Tag2Subpacket::ID::Primary_User_ID                        = 25;
const uint8_t Tag2Subpacket::ID::Policy_URI                             = 26;
const uint8_t Tag2Subpacket::ID::Key_Flags                              = 27;
const uint8_t Tag2Subpacket::ID::Signers_User_ID                        = 28;
const uint8_t Tag2Subpacket::ID::Reason_for_Revocation                  = 29;
const uint8_t Tag2Subpacket::ID::Features                               = 30;
const uint8_t Tag2Subpacket::ID::Signature_Target                       = 31;
const uint8_t Tag2Subpacket::ID::Embedded_Signature                     = 32;

const std::map <uint8_t, std::string> Tag2Subpacket::Name = {
    std::make_pair(0,                                                                  "Reserved"),
    std::make_pair(1,                                                                  "Reserved"),
    std::make_pair(Tag2Subpacket::ID::Signature_Creation_Time,                         "Signature Creation Time"),
    std::make_pair(Tag2Subpacket::ID::Signature_Expiration_Time,                       "Signature Expiration Time"),
    std::make_pair(Tag2Subpacket::ID::Exportable_Certification,                        "Exportable Certification"),
    std::make_pair(Tag2Subpacket::ID::Trust_Signature,                                 "Trust Signature"),
    std::make_pair(Tag2Subpacket::ID::Regular_Expression,                              "Regular Expression"),
    std::make_pair(Tag2Subpacket::ID::Revocable,                                       "Revocable"),
    std::make_pair(8,                                                                  "Reserved"),
    std::make_pair(Tag2Subpacket::ID::Key_Expiration_Time,                             "Key Expiration Time"),
    std::make_pair(Tag2Subpacket::ID::Placeholder_for_Backward_Compatibility,          "Placeholder for Backward Compatibility"),       // No Format Defined
    std::make_pair(Tag2Subpacket::ID::Preferred_Symmetric_Algorithms,                  "Preferred Symmetric Algorithms"),
    std::make_pair(Tag2Subpacket::ID::Revocation_Key,                                  "Revocation Key"),
    std::make_pair(13,                                                                 "Reserved"),
    std::make_pair(14,                                                                 "Reserved"),
    std::make_pair(15,                                                                 "Reserved"),
    std::make_pair(Tag2Subpacket::ID::Issuer,                                          "Issuer"),
    std::make_pair(17,                                                                 "Reserved"),
    std::make_pair(18,                                                                 "Reserved"),
    std::make_pair(19,                                                                 "Reserved"),
    std::make_pair(Tag2Subpacket::ID::Notation_Data,                                   "Notation Data"),
    std::make_pair(Tag2Subpacket::ID::Preferred_Hash_Algorithms,                       "Preferred Hash Algorithms"),
    std::make_pair(Tag2Subpacket::ID::Preferred_Compression_Algorithms,                "Preferred Compression Algorithms"),
    std::make_pair(Tag2Subpacket::ID::Key_Server_Preferences,                          "Key Server Preferences"),
    std::make_pair(Tag2Subpacket::ID::Preferred_Key_Server,                            "Preferred Key Server"),
    std::make_pair(Tag2Subpacket::ID::Primary_User_ID,                                 "Primary User ID"),
    std::make_pair(Tag2Subpacket::ID::Policy_URI,                                      "Policy URI"),
    std::make_pair(Tag2Subpacket::ID::Key_Flags,                                       "Key Flags"),
    std::make_pair(Tag2Subpacket::ID::Signers_User_ID,                                 "Signer's User ID"),
    std::make_pair(Tag2Subpacket::ID::Reason_for_Revocation,                           "Reason for Revocation"),
    std::make_pair(Tag2Subpacket::ID::Features,                                        "Features"),
    std::make_pair(Tag2Subpacket::ID::Signature_Target,                                "Signature Target"),
    std::make_pair(Tag2Subpacket::ID::Embedded_Signature,                              "Embedded Signature"),
    std::make_pair(100,                                                                "Private/Experimental algorithm"),
    std::make_pair(101,                                                                "Private/Experimental algorithm"),
    std::make_pair(102,                                                                "Private/Experimental algorithm"),
    std::make_pair(103,                                                                "Private/Experimental algorithm"),
    std::make_pair(104,                                                                "Private/Experimental algorithm"),
    std::make_pair(105,                                                                "Private/Experimental algorithm"),
    std::make_pair(106,                                                                "Private/Experimental algorithm"),
    std::make_pair(107,                                                                "Private/Experimental algorithm"),
    std::make_pair(108,                                                                "Private/Experimental algorithm"),
    std::make_pair(109,                                                                "Private/Experimental algorithm"),
    std::make_pair(110,                                                                "Private/Experimental algorithm"),
};

std::string Tag2Subpacket::show_title() const{
    return "        " + Tag2Subpacket::Name.at(type) + " Subpacket (sub " + std::to_string(type) + ") (" + std::to_string(size) + " octets)";
}

Tag2Subpacket::~Tag2Subpacket(){}

Tag2Subpacket & Tag2Subpacket::operator=(const Tag2Subpacket & copy){
    Subpacket::operator=(copy);
    return *this;
}