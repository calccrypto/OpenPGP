#include "pgpzlib.h"

#include "../common/compiler.h"

/* Compress from file source to file dest until EOF on source.
   def() returns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_STREAM_ERROR if an invalid compression
   level is supplied, Z_VERSION_ERROR if the version of zlib.h and the
   version of the library linked do not match, or Z_ERRNO if there is
   an error reading or writing the files. */
int zlib_compress(const std::string & src, std::string & dst, int windowBits, int level)
{
    dst = ""; // clear out destination

    int ret, flush;
    unsigned have;
    z_stream strm;
    unsigned char in[ZLIB_CHUNK];
    unsigned char out[ZLIB_CHUNK];

    unsigned int index = 0;
    unsigned int len = src.size();

    /* allocate deflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    ret = deflateInit2(&strm, level, Z_DEFLATED, windowBits, 8, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK)
        return ret;

    /* compress until end of file */
    do {
        // strm.avail_in = fread(in, 1, CHUNK, source);
        // if (ferror(source)) {
            // (void)deflateEnd(&strm);
            // return Z_ERRNO;
        // }
        // flush = feof(source) ? Z_FINISH : Z_NO_FLUSH;

        strm.avail_in = ((index + ZLIB_CHUNK) < len)?ZLIB_CHUNK:(len - index);
        for(unsigned int i = 0; i < strm.avail_in; i++){
            in[i] = src[i + index];
        }
        index += strm.avail_in;
        flush = (index == len)? Z_FINISH : Z_NO_FLUSH;

        strm.next_in = in;

        /* run deflate() on input until output buffer not full, finish
           compression if all of source has been read in */
        do {
            strm.avail_out = ZLIB_CHUNK;
            strm.next_out = out;
            ret = deflate(&strm, flush);    /* no bad return value */
            assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
            have = ZLIB_CHUNK - strm.avail_out;
            // if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
                // (void)deflateEnd(&strm);
                // return Z_ERRNO;
            // }
            for(unsigned int i = 0; i < have; i++){
                dst += std::string(1, out[i]);
            }

        } while (strm.avail_out == 0);
        assert(strm.avail_in == 0);     /* all input will be used */

        /* done when last data in file processed */
    } while (flush != Z_FINISH);
    assert(ret == Z_STREAM_END);        /* stream will be complete */

    /* clean up and return */
    (void)deflateEnd(&strm);
    return Z_OK;
}

/* Decompress from file source to file dest until stream ends or EOF.
   inf() returns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_DATA_ERROR if the deflate data is
   invalid or incomplete, Z_VERSION_ERROR if the version of zlib.h and
   the version of the library linked do not match, or Z_ERRNO if there
   is an error reading or writing the files. */
int zlib_decompress(const std::string & src, std::string & dst, int windowBits)
{
    dst = ""; // clear out destination

    int ret;
    unsigned have;
    z_stream strm;
    unsigned char in[ZLIB_CHUNK];
    unsigned char out[ZLIB_CHUNK];

    unsigned int index = 0;
    unsigned int len = src.size();

    /* allocate inflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit2(&strm, windowBits);
    if (ret != Z_OK)
        return ret;

    /* decompress until deflate stream ends or end of file */
    do {
        // strm.avail_in = fread(in, 1, CHUNK, source);
        // if (ferror(source)) {
            // (void)inflateEnd(&strm);
            // return Z_ERRNO;
        // }

        strm.avail_in = ((index + ZLIB_CHUNK) < len)?ZLIB_CHUNK:(len - index);
        for(unsigned int i = 0; i < strm.avail_in; i++){
            in[i] = src[i + index];
        }
        index += strm.avail_in;

        if (strm.avail_in == 0)
            break;
        strm.next_in = in;

        /* run inflate() on input until output buffer not full */
        do {
            strm.avail_out = ZLIB_CHUNK;
            strm.next_out = out;
            ret = inflate(&strm, Z_NO_FLUSH);
            assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
            switch (ret) {
            case Z_NEED_DICT:
                ret = Z_DATA_ERROR;     /* and fall through */
                FALL_THROUGH;
            case Z_DATA_ERROR:
                FALL_THROUGH;
            case Z_MEM_ERROR:
                (void)inflateEnd(&strm);
                return ret;
            }
            have = ZLIB_CHUNK - strm.avail_out;

            // if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
                // (void)inflateEnd(&strm);
                // return Z_ERRNO;
            // }

            for(unsigned int i = 0; i < have; i++){
                dst += std::string(1, out[i]);
            }
        } while (strm.avail_out == 0);

        /* done when inflate() says it's done */
    } while (ret != Z_STREAM_END);

    /* clean up and return */
    (void)inflateEnd(&strm);
    return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}
