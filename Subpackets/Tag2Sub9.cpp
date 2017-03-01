#include "Tag2Sub9.h"

Tag2Sub9::Tag2Sub9()
    : Tag2Subpacket(9, 4),
      dt()
{}

Tag2Sub9::Tag2Sub9(const std::string & data)
    : Tag2Sub9()
{
    read(data);
}

void Tag2Sub9::read(const std::string & data){
    dt = static_cast <time_t> (toint(data, 256));
}
std::string Tag2Sub9::show(const time_t create_time, const uint8_t indents, const uint8_t indent_size) const{
    const std::string tab(indents * indent_size, ' ');
    std::stringstream out;
    out << tab << show_title() << "\n"
        << tab << "            Key Expiration Time: ";
    if (dt == 0){
        out << "Never";
    }
    else{
        out << show_time(create_time + dt);
    }
    return out.str();
}

std::string Tag2Sub9::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string tab(indents * indent_size, ' ');
    std::stringstream out;
    out << tab << show_title() << "\n"
        << tab << "            Key Expiration Time: ";
    if (dt == 0){
        out << "Never";
    }
    else{
        const time_t years   = (dt / 31536000);
        const time_t days    = (dt / 86400) % 365;
        const time_t hours   = (dt / 3600) % 24;
        const time_t minutes = (dt / 60) % 60;
        const time_t seconds =  dt     % 60;

        if (years){
            out << years << " years";
        }

        if (days){
            out << days << " days";
        }

        if (hours){
            out << hours << " hours";
        }

        if (minutes){
            out << minutes << " minutes";
        }

        if (seconds){
            out << seconds << " seconds";
        }

        out << " after key creation";
    }
    return out.str();
}

std::string Tag2Sub9::raw() const{
    return unhexlify(makehex(dt, 8));
}

time_t Tag2Sub9::get_dt() const{
    return dt;
}

void Tag2Sub9::set_dt(const time_t t){
    dt = t;
}

Tag2Subpacket::Ptr Tag2Sub9::clone() const{
    return std::make_shared <Tag2Sub9> (*this);
}
