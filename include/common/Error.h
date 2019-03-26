#ifndef __OPENPGP_ERROR__
#define __OPENPGP_ERROR__

namespace OpenPGP {
    enum Error {
        SUCCESS,
        INVALID_COMPRESSION_ALGORITHM,
        INVALID_HASH_ALGORITHM,
        INVALID_LEFT16_BITS,            // Tag 2
        INVALID_LENGTH,
        INVALID_LITERAL_DATA_FORMAT,    // Tag 11
        INVALID_MPI_COUNT,
        INVALID_PUBLIC_KEY_ALGORITHM,
        INVALID_SHA1_HASH,              // Tag 18
        INVALID_SIGNATURE_TYPE,
        INVALID_SYMMETRIC_ENCRYPTION_ALGORITHM,
        INVALID_TAG,
        INVALID_TAG10,                  // Tag 10
        INVALID_VERSION,
        MISSING_S2K,                    // Tag 3, 5
        PKA_CANNOT_BE_USED,
        SHOULD_NOT_BE_EMITTED,          // Tag 12
        WRONG_S2K_TYPE,
    };
}

#endif
