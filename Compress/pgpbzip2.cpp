#include "pgpbzip2.h"

int bz2_compress(const std::string & src, std::string & dst){
    dst = ""; // clear out destination

    int rc, flush;
    bz_stream strm;
    char in[bz2_BUFFER_SIZE];
    char out[bz2_BUFFER_SIZE];

    unsigned int index = 0;
    unsigned int len = src.size();

    strm.bzalloc = NULL;
    strm.bzfree = NULL;
    strm.opaque = NULL;

    rc = BZ2_bzCompressInit(&strm, bz2_BLOCKSIZE100K, bz2_VERBOSITY, bz2_WORKFACTOR);
    if (rc != BZ_OK){
        BZ2_bzCompressEnd(&strm);
        return rc;
    }

    do{
        strm.avail_in = ((index + bz2_BUFFER_SIZE) < len)?bz2_BUFFER_SIZE:(len - index);
        for(unsigned int i = 0; i < strm.avail_in; i++){
            in[i] = src[i + index];
        }
        index += strm.avail_in;
        flush = (index == len)?BZ_FINISH:BZ_RUN;

        strm.next_in = in;

        do{
            strm.next_out = out;
            strm.avail_out = bz2_BUFFER_SIZE;

            rc = BZ2_bzCompress(&strm, flush);
            assert(rc != BZ_SEQUENCE_ERROR);
            for(unsigned int i = 0; i < bz2_BUFFER_SIZE - strm.avail_out; i++){
                dst += std::string(1, out[i]);
            }

        } while (strm.avail_out == 0);
        assert (strm.avail_in == 0);

    } while (flush != BZ_FINISH);
    assert(rc == BZ_STREAM_END);

    return BZ2_bzCompressEnd(&strm);
}

int bz2_decompress(const std::string & src, std::string & dst){
    dst = ""; // clear out destination

    int rc;
    bz_stream strm;
    char in[bz2_BUFFER_SIZE];
    char out[bz2_BUFFER_SIZE];

    unsigned int index = 0;
    unsigned int len = src.size();

    strm.bzalloc = NULL;
    strm.bzfree = NULL;
    strm.opaque = NULL;

    rc = BZ2_bzDecompressInit(&strm, bz2_VERBOSITY, bz2_SMALL);
    if (rc != BZ_OK){
        BZ2_bzCompressEnd(&strm);
        return rc;
    }

    do{
        strm.avail_in = ((index + bz2_BUFFER_SIZE) < len)?bz2_BUFFER_SIZE:(len - index);
        for(unsigned int i = 0; i < strm.avail_in; i++){
            in[i] = src[i + index];
        }
        index += strm.avail_in;

        strm.next_in = in;

        do{
            strm.next_out = out;
            strm.avail_out = bz2_BUFFER_SIZE;

            rc = BZ2_bzDecompress(&strm);
            assert((rc == BZ_OK) || (rc == BZ_STREAM_END));

            for(unsigned int i = 0; i < bz2_BUFFER_SIZE - strm.avail_out; i++){
                dst += std::string(1, out[i]);
            }

        } while (strm.avail_out == 0);
        assert (strm.avail_in == 0);

    } while (rc != BZ_STREAM_END);

    return BZ2_bzDecompressEnd(&strm);
}
