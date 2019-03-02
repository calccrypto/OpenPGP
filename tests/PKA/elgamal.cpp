#include <gtest/gtest.h>

#include "Misc/mpi.h"
#include "Misc/pgptime.h"
#include "PKA/ElGamal.h"
#include "RNG/RNGs.h"
#include "common/includes.h"

TEST(ElGamal, keygen) {
    OpenPGP::RNG::BBS rng(static_cast <OpenPGP::MPI> (static_cast <unsigned int> (OpenPGP::now())));

    // keep bitsize small to reduce computation time
    for(std::size_t const bitsize : {64, 128, 256, 512}) {
        const std::string data = unbinify(rng.rand(bitsize >> 1));
        const OpenPGP::MPI mpi_data = OpenPGP::rawtompi(data);

        const OpenPGP::PKA::Values key = OpenPGP::PKA::ElGamal::keygen(bitsize);
        const OpenPGP::PKA::Values pub = {key[0], key[1], key[2]};
        const OpenPGP::PKA::Values pri = {key[3]};

        const OpenPGP::PKA::Values encrypted = OpenPGP::PKA::ElGamal::encrypt(data, pub);
        const std::string decrypted = OpenPGP::PKA::ElGamal::decrypt(encrypted, pri, pub);

        // convert to mpi to ignore missing leading zeros
        EXPECT_EQ(mpi_data, OpenPGP::rawtompi(decrypted));
    }
}
