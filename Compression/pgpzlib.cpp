#include "pgpzlib.h"

//int zlib_compress(std::string & compressed, const std::string & decompressed){
//    unsigned long decompressed_size = decompressed.size();
//    Bytef * d = (Bytef *) decompressed.c_str();
//
//    unsigned long c_size = (decompressed_size * 1.1) + 12;
//    Bytef * c = new Bytef[c_size];
//
//    int z_rc = compress(c, &c_size, d, decompressed_size);
//    compressed = std::string((char *) c, c_size);
//
//    delete c;
//    return z_rc;
//}
//
//int zlib_dempress(std::string & decompressed, const std::string & compressed, unsigned long decompressed_size){
//    unsigned long compressed_size = compressed.size();
//    Bytef * c = (Bytef *) compressed.c_str();
//
//    Bytef * d = new Bytef[decompressed_size];
//    int z_rc = uncompress(d, &decompressed_size, c, compressed_size);
//
//    delete d;
//    return z_rc;
//}
//
