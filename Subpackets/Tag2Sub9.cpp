#include "Tag2Sub9.h"

Tag2Sub9::Tag2Sub9()
    : Tag2Subpacket(Tag2Subpacket::KEY_EXPIRATION_TIME, 4),
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
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');

    std::string out = indent + show_title() + "\n" +
                      indent + tab + "Key Expiration Time: ";
    if (dt == 0){
        out += "Never";
    }
    else{
        out += show_time(create_time + dt);
    }

    return out;
}

std::string Tag2Sub9::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');

    std::string out = indent + show_title() + "\n" +
                      indent + tab + "Key Expiration Time: ";

    if (dt == 0){
        out += "Never";
    }
    else{
        const time_t years   = (dt / 31536000);
        const time_t days    = (dt / 86400) % 365;
        const time_t hours   = (dt / 3600) % 24;
        const time_t minutes = (dt / 60) % 60;
        const time_t seconds =  dt     % 60;

        if (years){
            out += std::to_string(years) + " years";
        }

        if (days){
            out += std::to_string(days) + " days";
        }

        if (hours){
            out += std::to_string(hours) + " hours";
        }

        if (minutes){
            out += std::to_string(minutes) + " minutes";
        }

        if (seconds){
            out += std::to_string(seconds) + " seconds";
        }

        out += " after key creation";
    }

    return out;
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
