#include "Hashes/MerkleDamgard.h"

namespace OpenPGP {
namespace Hash {

MerkleDamgard::MerkleDamgard()
    : Alg(),
      stack(),
      clen(0)
{}

MerkleDamgard::~MerkleDamgard() {}

}
}