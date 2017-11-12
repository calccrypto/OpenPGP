/*
pgptime.h

Copyright (c) 2013 - 2017 Jason Lee @ calccrypto at gmail.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifndef __PGP_TIME__
#define __PGP_TIME__

#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>

namespace OpenPGP {
    const std::string dayofweek[7] = {"Sun", "Mon", "Tues", "Wed", "Thur", "Fri", "Sat"};
    const std::string month[12]    = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sept", "Oct", "Nov", "Dec"};

    // get current time since epoch
    time_t now();

    // show time as: Day_of_Week Month Day Hour:Minute:Second UTC Year
    std::string show_time(time_t time);

    // write a time following strftime format
    std::string show_time_format(time_t time, const char* format, uint8_t limit);

    // show time as Year-Month-Day
    std::string show_date(time_t time);

    // show time difference as Y Years D Days H Hours M Minutes S Seconds
    // Only if the field is not zero. If a field is 0, it will not show.
    std::string show_dt(time_t dt);
}

#endif
