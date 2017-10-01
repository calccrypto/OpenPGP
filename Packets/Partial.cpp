#include "Partial.h"

namespace OpenPGP {
namespace Packet {

std::string Partial::show_title() const{
    std::stringstream out;
    out << (format?"New":"Old") << ": ";

    switch (partial){
        case 1:
            out << " (partial start)";
            break;
        case 2:
            out << " (partial continue)";
            break;
        case 3:
            out << " (partial end)";
            break;
        default:
            throw std::runtime_error("Error: Unknown partial type: " + std::to_string(partial));
            break;
    }
    return out.str();
}

Partial::Partial()
    : Partial(std::string())
{}

Partial::Partial(const std::string & data)
    : Tag(),
      stream(data)
{}

void Partial::read(const std::string & data){
    stream = data;
}

std::string Partial::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string tab(indents * indent_size, ' ');
    return tab + tab + show_title() + "\n" + std::string((indents + 1) * indent_size, ' ') + hexlify(stream);
}

std::string Partial::raw() const{
    return stream;
}

std::string Partial::get_stream() const{
    return stream;
}

void Partial::set_stream(const std::string & data){
    stream = data;
}

Tag::Ptr Partial::clone() const{
    return std::make_shared <Partial> (*this);
}

}
}