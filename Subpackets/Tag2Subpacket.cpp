#include "Tag2Subpacket.h"

const uint8_t Tag2Subpacket::SIGNATURE_CREATION_TIME                = 2;
const uint8_t Tag2Subpacket::SIGNATURE_EXPIRATION_TIME              = 3;
const uint8_t Tag2Subpacket::EXPORTABLE_CERTIFICATION               = 4;
const uint8_t Tag2Subpacket::TRUST_SIGNATURE                        = 5;
const uint8_t Tag2Subpacket::REGULAR_EXPRESSION                     = 6;
const uint8_t Tag2Subpacket::REVOCABLE                              = 7;
const uint8_t Tag2Subpacket::KEY_EXPIRATION_TIME                    = 9;
const uint8_t Tag2Subpacket::PLACEHOLDER_FOR_BACKWARD_COMPATIBILITY = 10;
const uint8_t Tag2Subpacket::PREFERRED_SYMMETRIC_ALGORITHMS         = 11;
const uint8_t Tag2Subpacket::REVOCATION_KEY                         = 12;
const uint8_t Tag2Subpacket::ISSUER                                 = 16;
const uint8_t Tag2Subpacket::NOTATION_DATA                          = 20;
const uint8_t Tag2Subpacket::PREFERRED_HASH_ALGORITHMS              = 21;
const uint8_t Tag2Subpacket::PREFERRED_COMPRESSION_ALGORITHMS       = 22;
const uint8_t Tag2Subpacket::KEY_SERVER_PREFERENCES                 = 23;
const uint8_t Tag2Subpacket::PREFERRED_KEY_SERVER                   = 24;
const uint8_t Tag2Subpacket::PRIMARY_USER_ID                        = 25;
const uint8_t Tag2Subpacket::POLICY_URI                             = 26;
const uint8_t Tag2Subpacket::KEY_FLAGS                              = 27;
const uint8_t Tag2Subpacket::SIGNERS_USER_ID                        = 28;
const uint8_t Tag2Subpacket::REASON_FOR_REVOCATION                  = 29;
const uint8_t Tag2Subpacket::FEATURES                               = 30;
const uint8_t Tag2Subpacket::SIGNATURE_TARGET                       = 31;
const uint8_t Tag2Subpacket::EMBEDDED_SIGNATURE                     = 32;

const std::map <uint8_t, std::string> Tag2Subpacket::NAME = {
    std::make_pair(0,                                               "Reserved"),
    std::make_pair(1,                                               "Reserved"),
    std::make_pair(SIGNATURE_CREATION_TIME,                         "Signature Creation Time"),
    std::make_pair(SIGNATURE_EXPIRATION_TIME,                       "Signature Expiration Time"),
    std::make_pair(EXPORTABLE_CERTIFICATION,                        "Exportable Certification"),
    std::make_pair(TRUST_SIGNATURE,                                 "Trust Signature"),
    std::make_pair(REGULAR_EXPRESSION,                              "Regular Expression"),
    std::make_pair(REVOCABLE,                                       "Revocable"),
    std::make_pair(8,                                               "Reserved"),
    std::make_pair(KEY_EXPIRATION_TIME,                             "Key Expiration Time"),
    std::make_pair(PLACEHOLDER_FOR_BACKWARD_COMPATIBILITY,          "Placeholder for Backward Compatibility"),       // No Format Defined
    std::make_pair(PREFERRED_SYMMETRIC_ALGORITHMS,                  "Preferred Symmetric Algorithms"),
    std::make_pair(REVOCATION_KEY,                                  "Revocation Key"),
    std::make_pair(13,                                              "Reserved"),
    std::make_pair(14,                                              "Reserved"),
    std::make_pair(15,                                              "Reserved"),
    std::make_pair(ISSUER,                                          "Issuer"),
    std::make_pair(17,                                              "Reserved"),
    std::make_pair(18,                                              "Reserved"),
    std::make_pair(19,                                              "Reserved"),
    std::make_pair(NOTATION_DATA,                                   "Notation Data"),
    std::make_pair(PREFERRED_HASH_ALGORITHMS,                       "Preferred Hash Algorithms"),
    std::make_pair(PREFERRED_COMPRESSION_ALGORITHMS,                "Preferred Compression Algorithms"),
    std::make_pair(KEY_SERVER_PREFERENCES,                          "Key Server Preferences"),
    std::make_pair(PREFERRED_KEY_SERVER,                            "Preferred Key Server"),
    std::make_pair(PRIMARY_USER_ID,                                 "Primary User ID"),
    std::make_pair(POLICY_URI,                                      "Policy URI"),
    std::make_pair(KEY_FLAGS,                                       "Key Flags"),
    std::make_pair(SIGNERS_USER_ID,                                 "Signer's User ID"),
    std::make_pair(REASON_FOR_REVOCATION,                           "Reason for Revocation"),
    std::make_pair(FEATURES,                                        "Features"),
    std::make_pair(SIGNATURE_TARGET,                                "Signature Target"),
    std::make_pair(EMBEDDED_SIGNATURE,                              "Embedded Signature"),
    std::make_pair(100,                                             "Private/Experimental algorithm"),
    std::make_pair(101,                                             "Private/Experimental algorithm"),
    std::make_pair(102,                                             "Private/Experimental algorithm"),
    std::make_pair(103,                                             "Private/Experimental algorithm"),
    std::make_pair(104,                                             "Private/Experimental algorithm"),
    std::make_pair(105,                                             "Private/Experimental algorithm"),
    std::make_pair(106,                                             "Private/Experimental algorithm"),
    std::make_pair(107,                                             "Private/Experimental algorithm"),
    std::make_pair(108,                                             "Private/Experimental algorithm"),
    std::make_pair(109,                                             "Private/Experimental algorithm"),
    std::make_pair(110,                                             "Private/Experimental algorithm"),
};

std::string Tag2Subpacket::show_title() const{
    return Subpacket::show_title() + NAME.at(type) + " Subpacket (sub " + std::to_string(type) + ") (" + std::to_string(size) + " octets)";
}

Tag2Subpacket::~Tag2Subpacket(){}

Tag2Subpacket & Tag2Subpacket::operator=(const Tag2Subpacket & copy){
    Subpacket::operator=(copy);
    return *this;
}