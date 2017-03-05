#include "sigtypes.h"

bool Signature_Type::is_certification(const uint8_t sig){
    return ((sig == Signature_Type::ID::Generic_certification_of_a_User_ID_and_Public_Key_packet)   ||
            (sig == Signature_Type::ID::Persona_certification_of_a_User_ID_and_Public_Key_packet)   ||
            (sig == Signature_Type::ID::Casual_certification_of_a_User_ID_and_Public_Key_packet)    ||
            (sig == Signature_Type::ID::Positive_certification_of_a_User_ID_and_Public_Key_packet));
}