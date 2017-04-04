#include "Tag2Sub22.h"

Tag2Sub22::Tag2Sub22()
    : Tag2Subpacket(Tag2Subpacket::PREFERRED_COMPRESSION_ALGORITHMS),
      pca()
{}

Tag2Sub22::Tag2Sub22(const std::string & data)
    : Tag2Sub22()
{
    read(data);
}

void Tag2Sub22::read(const std::string & data){
    pca = data;
    size = data.size();
}

std::string Tag2Sub22::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');

    std::string out = indent + show_title();
    for(char const & c : pca){
        const decltype(Compression::NAME)::const_iterator comp_it = Compression::NAME.find(c);
        out += "\n" + indent + tab + "comp alg - " + ((comp_it == Compression::NAME.end())?"Unknown":(comp_it -> second)) + " (comp " + std::to_string(c) + ")";
    }

    return out;
}

std::string Tag2Sub22::raw() const{
    return pca;
}

std::string Tag2Sub22::get_pca() const{
    return pca;
}

void Tag2Sub22::set_pca(const std::string & c){
    pca = c;
}

Tag2Subpacket::Ptr Tag2Sub22::clone() const{
    return std::make_shared <Tag2Sub22> (*this);
}
