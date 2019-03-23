#include "Packets/Tag2/Sub22.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub22::actual_read(const std::string & data) {
    set_pca(data);
}

void Sub22::show_contents(HumanReadable & hr) const {
    for(char const & c : pca) {
        hr << "comp alg - " + get_mapped(Compression::NAME, (uint8_t) c) + " (comp " + std::to_string(c) + ")";
    }
}

Sub22::Sub22()
    : Sub(PREFERRED_COMPRESSION_ALGORITHMS),
      pca()
{}

Sub22::Sub22(const std::string & data)
    : Sub22()
{
    read(data);
}

std::string Sub22::raw() const {
    return pca;
}

std::string Sub22::get_pca() const {
    return pca;
}

void Sub22::set_pca(const std::string & c) {
    pca = c;
}

Sub::Ptr Sub22::clone() const {
    return std::make_shared <Sub22> (*this);
}

}
}
}
