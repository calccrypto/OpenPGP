#include "pgpbzip2.h"

int bz2_compress(FILE * in, FILE * out){
    int rc;
    BZFILE * bzf = BZ2_bzWriteOpen(&rc, out, bz2_BLOCKSIZE100K, bz2_VERBOSITY, bz2_WORKFACTOR);

    if (rc != BZ_OK){
        BZ2_bzWriteClose(&rc, bzf, 1, 0, 0);
        std::stringstream s; s << rc;
        throw std::runtime_error("BZ2_bzWriteOpen Error: " + s.str());
        //return rc;
    }

    char buffer[bz2_BUFFER_SIZE];
    memset(buffer, 0, bz2_BUFFER_SIZE);
    
    unsigned int len;
    
    while ((len = fread(buffer, sizeof(char), bz2_BUFFER_SIZE, in))){
        BZ2_bzWrite(&rc, bzf, buffer, len);
        if (rc != BZ_OK){
            BZ2_bzWriteClose(&rc, bzf, 1, 0, 0);
            std::stringstream s; s << rc;
            throw std::runtime_error("BZ2_bzWrite Error: %d" + s.str());
            //return rc;
        }
    }

    BZ2_bzWriteClose(&rc, bzf, 0, 0, 0);
    return 0;
}

int bz2_decompress(FILE * in, FILE * out){
    int rc;
    BZFILE * bzf = BZ2_bzReadOpen(&rc, in, bz2_VERBOSITY, bz2_SMALL, NULL, 0);

    if (rc != BZ_OK){
        BZ2_bzReadClose(&rc, bzf);
        std::stringstream s; s << rc;
        throw std::runtime_error("BZ2_bzReadOpen Error: %d" + s.str());
        //return rc;
    }

    char buffer[bz2_BUFFER_SIZE];
    memset(buffer, 0, bz2_BUFFER_SIZE);

    while (rc == BZ_OK){
        int read = BZ2_bzRead(&rc, bzf, buffer, bz2_BUFFER_SIZE * sizeof(char));
        if ((rc == BZ_OK) || (rc == BZ_STREAM_END)){
            int write = fwrite(buffer, sizeof(char), read, out);
            if (write != read){
                return -1; // not end of file
            }
        }
    }

    if (rc != BZ_STREAM_END){
        BZ2_bzReadClose(&rc, bzf);
        std::stringstream s; s << rc;
        throw std::runtime_error("Error after BZ2_bzRead: %d" + s.str());
        //return rc;
    }

    BZ2_bzReadClose(&rc, bzf);
    return 0;
}