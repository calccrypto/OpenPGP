#include "common/HumanReadable.h"

std::string HumanReadable::duplicate_string(const std::string & src, const std::size_t times) const {
    std::string out = "";
    out.reserve(src.size() * (times + 1));
    for(std::size_t i = 0; i < times; i++) {
        out += src;
    }
    return out;
}

HumanReadable::HumanReadable(const std::size_t indent_size, const std::size_t depth, const char indent_char)
    : indent(std::string(indent_size, indent_char)),
      prefix(duplicate_string(indent, depth)),
      data(),
      level(0)
{}

HumanReadable::HumanReadable(const std::string & prefix, const std::string & indent)
    : indent(indent),
      prefix(prefix),
      data(),
      level(0)
{}

std::size_t HumanReadable::up() {
    if (level) {
        level--;
    }

    return level;
}

std::size_t HumanReadable::down() {
    return ++level;
}

std::size_t HumanReadable::curr_level() const {
    return level;
}

std::string HumanReadable::get() const {
    return data.str();
}

HumanReadable & HumanReadable::operator<<(const std::string & str) {
    data << prefix;

    for(std::size_t i = 0; i < level; i++) {
        data << indent;
    }

    data << str + "\n";
    return *this;
}

HumanReadable & HumanReadable::operator<<(const Move dir) {
    switch (dir) {
        case UP:
            up();
            break;
        case DOWN:
            down();
            break;
    }
    return *this;
}

std::ostream & operator<<(std::ostream & stream, const HumanReadable & hr) {
    return stream << hr.get();
}
