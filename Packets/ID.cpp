#include "ID.h"

ID::~ID(){}

ID & ID::operator=(const ID & copy)
{
    Packet::operator=(copy);
    return *this;
}
