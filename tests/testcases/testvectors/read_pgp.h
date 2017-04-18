#ifndef __READ_PGP__
#define __READ_PGP__

#include <string>

#include "PGP.h"

#ifndef GPG_DIR
#define GPG_DIR "testcases/testvectors/gpg/"
#endif

// open a file and attempt to read the contents into a PGP data structure
template <typename T>
bool read_pgp(const std::string & name, T & pgp, const std::string & directory = GPG_DIR){
    std::ifstream file(directory + name);
    if (!file){
        return false;
    }

    pgp.read(std::string(std::istreambuf_iterator <char> (file), {}));

    std::string error;
    return pgp.meaningful(error);
}

#endif