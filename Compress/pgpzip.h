#include <fstream>
#include <stdexcept>
#include <sstream>
#include <stdexcept>
#include <stdio.h>
#include <vector>
#include <zip.h>

std::string compress(const std::vector <std::string> & filenames); // probably want to separate paths from names
void decompress(const std::string & zippath);