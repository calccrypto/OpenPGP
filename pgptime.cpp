#include "pgptime.h"

// get current time since epoch
time_t now(){
    time_t rawtime;
    time(&rawtime);
    return rawtime;
}

// write a time in seconds from epoch to string
std::string show_time(time_t T){
    // value to string conversion
    struct tm * gmt = gmtime(&T);
    std::stringstream date;
    // convert to string. could use asctime, but needed a bit more info
    date << dayofweek[gmt -> tm_wday] << " " << month[gmt -> tm_mon] << " " << gmt -> tm_mday << " " << gmt -> tm_hour << ":" << gmt -> tm_min << ":" << gmt -> tm_sec << " UTC " << (1900 + gmt -> tm_year);
    return date.str();
}

std::string show_date(time_t T){
    struct tm * gmt = gmtime(&T);
    std::stringstream date;
    date << (1900 + gmt -> tm_year) << "-" << (gmt -> tm_mon + 1) << "-" << gmt -> tm_mday;
    return date.str();
}
