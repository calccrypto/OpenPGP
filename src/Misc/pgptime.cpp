#include "Misc/pgptime.h"

#include <iomanip>
#include <sstream>

namespace OpenPGP {

// get current time since epoch
time_t now() {
    time_t rawtime;
    time(&rawtime);
    return rawtime;
}

// write a time in seconds from epoch to string
std::string show_time(time_t time) {
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

std::string show_date(time_t time) {
    struct tm * gmt = gmtime(&time);
    std::stringstream date;
    date << (1900 + gmt -> tm_year) << "-"
         << std::setfill('0') << std::setw(2) << (gmt -> tm_mon + 1) << "-"
         << std::setfill('0') << std::setw(2) <<  gmt -> tm_mday;
    return date.str();
}

std::string show_dt(time_t dt) {
    if (dt == 0) {
        return "now";
    }

    const bool neg = (dt < 0);
    if (neg) {
        dt = -dt; // to not do type conversions
    }

    const time_t years   = (dt / 31536000);
    const time_t days    = (dt / 86400) % 365;
    const time_t hours   = (dt / 3600) % 24;
    const time_t minutes = (dt / 60) % 60;
    const time_t seconds =  dt     % 60;

    std::string out = "";

    if (years) {
        out += std::to_string(years) + " year" + ((years > 1)?"s":"");
    }

    if (days) {
        out += std::string((bool) out.size(), ' ') + std::to_string(days) + " day" + ((days > 1)?"s":"");
    }

    if (hours) {
        out += std::string((bool) out.size(), ' ') + std::to_string(hours) + " hour" + ((hours > 1)?"s":"");
    }

    if (minutes) {
        out += std::string((bool) out.size(), ' ') + std::to_string(minutes) + " minute" + ((minutes > 1)?"s":"");
    }

    if (seconds) {
        out += std::string((bool) out.size(), ' ') + std::to_string(seconds) + " second" + ((seconds > 1)?"s":"");
    }

    if (neg) {
        out += " ago";
    }
    else {
        out += " from now";
    }

    return out;
}

}
