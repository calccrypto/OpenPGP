#include "pgpzip.h"

std::string compress(const std::vector <std::string> & filenames){
    int err;
    struct zip * ar = zip_open("ziptmp", ZIP_CREATE, &err);
    if (!ar){
        std::stringstream s; s << err;
        throw std::runtime_error("Error: ZIP error " + s.str());
        // return err;
    }

    // compress each file
    for(const std::string & filename : filenames){
        // open file
        std::ifstream src(filename.c_str(), std::ios::binary);
        // copy out data
        std::stringstream s; s << src.rdbuf();
        // move data into string
        std::string buffer = s.str();
        // create zip_source
        zip_source * zip_src = zip_source_buffer(ar, filename.c_str(), buffer.size() * sizeof(char), 0);
        // add to archive
        // need to change filename to not be full path
        zip_file_add(ar, filename.c_str(), zip_src , ZIP_FL_OVERWRITE);
    }
    // close archive
    zip_close(ar);

    // copy data out and remove temp file
    std::fstream f("ziptmp", std::ios::binary);
    std::stringstream s; s << f.rdbuf();
    remove("ziptmp");
    return s.str();
}

void decompress(const std::string & zippath){
    int err;
    // open archive
    struct zip * ar = zip_open("ziptmp", 0, &err);
    if (!ar){
        std::stringstream s; s << err;
        throw std::runtime_error("Error: ZIP error " + s.str());
        // return err;
    }

    // decompress each file
    for(zip_int64_t i = 0; i < zip_get_num_entries(ar, 0); i++){
        struct zip_file * f = zip_fopen_index(ar, i, 0);
        if (!f){
            throw std::runtime_error("Unable to open zip file");
        }

        // get compressed file information
        struct zip_stat stat;
        zip_stat_init(&stat);
        err = zip_stat_index(ar, i, 0, &stat);
        if (err){
            throw std::runtime_error("ZIP stat error");
        }
        char buffer[stat.size];
        zip_fread(f, buffer, stat.size);
        std::ofstream out(stat.name, std::ios::binary);
        out << buffer;
    }
}