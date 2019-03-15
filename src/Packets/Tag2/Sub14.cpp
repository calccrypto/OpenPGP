#include "Packets/Tag2/Sub14.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub14::Sub14(...){
    throw std::runtime_error("Error: Reserved Subpacket.");
}

Sub::Ptr Sub14::clone() const{
    return std::make_shared <Sub14> (*this);
}

}
}
}
