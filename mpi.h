/*
Multiprecision mpz_class (MPI) reader
as defined by RFC4880 sec 3.2

All data manipulation is done on bytes
*/


#include <gmpxx.h>

#include "common/includes.h"

#ifndef __PGPMPI__
#define __PGPMPI__

std::string write_MPI(const mpz_class & data);        // given some value, return the formatted mpi
mpz_class read_MPI(std::string & data);       // remove mpi from data, returning mpi value. the rest of the data will be returned through pass-by-reference

#endif
