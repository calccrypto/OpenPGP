#include "Tag11.h"

Tag11::Tag11():
    Packet(11),
    format(),
    filename(),
    time(),
    literal()
{}

Tag11::Tag11(std::string & data):
    Tag11()
{
    read(data);
}

void Tag11::read(std::string & data, const uint8_t part){
    size = data.size();
    format = data[0];
    uint8_t len = data[1];
    filename = data.substr(2, len);

    if (filename == "_CONSOLE"){
        std::cerr << "Warning: Special name \"_CONSOLE\" used. Message is considered to be \"for your eyes only\"." << std::endl;
    }

    time = toint(data.substr(2 + len, 4), 256);
    literal = data.substr(len + 6, data.size() - len - 6);
}

std::string Tag11::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    std::stringstream out;
    out << std::string(tab, ' ') << show_title() << "\n"
        << std::string(tab, ' ') << "    Format: " << BTU.at(format) << "\n"
        << std::string(tab, ' ') << "    Data (" << (1 + filename.size() + 4 + literal.size()) << " octets):\n"
        << std::string(tab, ' ') << "        Filename: " << filename << "\n"
        << std::string(tab, ' ') << "        Creation Date: " << show_time(time) << "\n"
        << std::string(tab, ' ') << "        Data: " << literal;
    return out.str();
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
                {
                    std::stringstream s; s << "Error: Unknown Literal Data format type: " << static_cast <char> (format) << std::endl;
                    throw std::runtime_error(s.str());
                }
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

Packet::Ptr Tag11::clone() const{
    return std::make_shared <Tag11> (*this);
}
