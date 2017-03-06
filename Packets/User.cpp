#include "User.h"

User::~User(){}

User & User::operator=(const User & copy)
{
    Packet::operator=(copy);
    return *this;
}
