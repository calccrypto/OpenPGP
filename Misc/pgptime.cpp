#include "pgptime.h"

namespace OpenPGP {

// get current time since epoch
time_t now(){
    time_t rawtime;
    time(&rawtime);
    return rawtime;
}

// write a time in seconds from epoch to string
std::string show_time(time_t time){
    // value to string conversion
    struct tm * gmt = gmtime(&time);
    std::stringstream date;
    // convert to string. could use asctime, but needed a bit more info
    date << dayofweek[gmt -> tm_wday] << " "
         << month[gmt -> tm_mon] << " "
         << gmt -> tm_mday << " "
         << std::setfill('0') << std::setw(2) << gmt -> tm_hour << ":"
         << std::setfill('0') << std::setw(2) << gmt -> tm_min  << ":"
         << std::setfill('0') << std::setw(2) << gmt -> tm_sec  << " UTC "
         << (1900 + gmt -> tm_year);
    return date.str();
}

// write a time following strftime format
std::string show_time_format(time_t time, const char* format = "%F %T", uint8_t limit = 80){
    char *buffer = new char[limit]();
    strftime (buffer, limit, format, localtime (&time));
    std::string result(buffer);
    delete [] buffer;
    return result;
}

std::string show_date(time_t time){
    struct tm * gmt = gmtime(&time);
    std::stringstream date;
    date << (1900 + gmt -> tm_year) << "-"
         << std::setfill('0') << std::setw(2) << (gmt -> tm_mon + 1) << "-"
         << std::setfill('0') << std::setw(2) <<  gmt -> tm_mday;
    return date.str();
}

std::string show_dt(time_t dt){
    const time_t years   = (dt / 31536000);
    const time_t days    = (dt / 86400) % 365;
    const time_t hours   = (dt / 3600) % 24;
    const time_t minutes = (dt / 60) % 60;
    const time_t seconds =  dt     % 60;

    std::string out = "";

    if (years){
        out += std::to_string(years) + " years";
    }

    if (days){
        if (out.size()){
            out += " ";
        }
        out += std::to_string(days) + " days";
    }

    if (hours){
        if (out.size()){
            out += " ";
        }
        out += std::to_string(hours) + "hours";
    }

    if (minutes){
        if (out.size()){
            out += " ";
        }
        out += std::to_string(minutes) + " minutes";
    }

    if (seconds){
        if (out.size()){
            out += " ";
        }
        out += std::to_string(seconds) + " seconds";
    }

    return out;
}

}
