#include "Tag11.h"

namespace OpenPGP {
namespace Packet {

Tag11::Tag11()
    : Tag(LITERAL_DATA),
      format(),
      filename(),
      time(),
      literal()
{}

Tag11::Tag11(const Tag11 & copy)
    : Tag(copy),
      format(copy.format),
      filename(copy.filename),
      time(copy.time),
      literal(copy.literal)
{}

Tag11::Tag11(const std::string & data)
    : Tag11()
{
    read(data);
}

void Tag11::read(const std::string & data){
    size        = data.size();
    format      = data[0];
    uint8_t len = data[1];
    filename    = data.substr(2, len);

    if (filename == "_CONSOLE"){
        std::cerr << "Warning: Special name \"_CONSOLE\" used. Message is considered to be \"for your eyes only\"." << std::endl;
    }

    time    = toint(data.substr(2 + len, 4), 256);
    literal = data.substr(len + 6, data.size() - len - 6);
}

std::string Tag11::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    const decltype(Literal::NAME)::const_iterator literal_it = Literal::NAME.find(format);
    return indent + show_title() + "\n" +
           indent + tab + "Format: " + ((literal_it == Literal::NAME.end())?"Unknown":(literal_it -> second)) + "\n" +
           indent + tab + "Data (" + std::to_string(1 + filename.size() + 4 + literal.size()) + " octets):\n" +
           indent + tab + tab + "Filename: " + filename + "\n" +
           indent + tab + tab + "Creation Date: " + show_time(time) + "\n" +
           indent + tab + tab + "Data: " + literal;
}

std::string Tag11::raw() const{
    return std::string(1, format) + std::string(1, filename.size()) + filename + unhexlify(makehex(time, 8)) + literal;
}

uint8_t Tag11::get_format() const{
    return format;
}

std::string Tag11::get_filename() const{
    return filename;
}

uint32_t Tag11::get_time() const{
    return time;
}

std::string Tag11::get_literal() const{
    if (filename == "_CONSOLE"){
        std::cerr << "Warning: Special name \"_CONSOLE\22 used. Message is considered to be \"for your eyes only\"." << std::endl;
    }
    return literal;
}

std::string Tag11::out(const bool writefile){
    if (filename == "_CONSOLE"){
        std::cerr << "Warning: Special name \"_CONSOLE\22 used. Message is considered to be \"for your eyes only\"." << std::endl;
    }

    if ((filename != "") && writefile){
        std::ofstream f;
        switch (format){
            case 'b':
                f.open(filename.c_str(), std::ios::binary);
                break;
            case 't': case 'u':
                f.open(filename.c_str());
                break;
            default:
                throw std::runtime_error("Error: Unknown Literal Data format type: " + std::to_string(format));
                break;
        }
        if (!f){
            throw std::runtime_error("Error: Failed to open file to write literal data.");
        }
        f << literal;
    }
    else{
        return literal;
    }
    return "Data written to file '" + filename + "'.";
}

void Tag11::set_format(const uint8_t f){
    format = f;
    size = raw().size();
}

void Tag11::set_filename(const std::string & f){
    filename = f;
    size = raw().size();
}

void Tag11::set_time(const uint32_t t){
    time = t;
    size = raw().size();
}

void Tag11::set_literal(const std::string & l){
    literal = l;
    size = raw().size();
}

Tag::Ptr Tag11::clone() const{
    return std::make_shared <Packet::Tag11> (*this);
}

}
}