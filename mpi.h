/*
Multiprecision Integer (MPI) reader
as defined by RFC4880 sec 3.2

All data manipulation is done on bytes
*/

#include "common/includes.h"
#include "common/integer.h"

#ifndef __PGPMPI__
#define __PGPMPI__

std::string write_MPI(integer data);        // given some value, return the formatted mpi
integer read_MPI(std::string & data);       // remove mpi from data, returning mpi value. the rest of the data will be returned through pass-by-reference

#endif
