#include <ctime>
#include <iostream>
#include <sstream>

#include "consts.h"

#ifndef __PGPTIME__
#define __PGPTIME__

// get current time since epoch
time_t now();

// show time as: Day_of_Week Month Day Hour:Minute:Second UTC Year
std::string show_time(time_t T);

// show time as Year-Month-Day
std::string show_date(time_t T);
#endif
