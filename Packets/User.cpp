#include "User.h"

namespace OpenPGP {
namespace Packet {

User::~User(){}

User & User::operator=(const User & copy)
{
    Base::operator=(copy);
    return *this;
}

}
}