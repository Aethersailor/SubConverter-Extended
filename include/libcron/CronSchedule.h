#pragma once

#include "libcron/CronData.h"
#include <chrono>
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable:4244)
#endif
#include <date/date.h>
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

#include "libcron/DateTime.h"

namespace libcron
{
    class CronSchedule
    {
        public:
            explicit CronSchedule(CronData& data)
                    : data(data)
            {
            }

            CronSchedule(const CronSchedule&) = default;

            CronSchedule& operator=(const CronSchedule&) = default;

            std::tuple<bool, std::chrono::system_clock::time_point>
            calculate_from(const std::chrono::system_clock::time_point& from) const;

            // https://github.com/HowardHinnant/date/wiki/Examples-and-Recipes#obtaining-ymd-hms-components-from-a-time_point
            static DateTime to_calendar_time(std::chrono::system_clock::time_point time)
            {
                auto daypoint = date::floor<date::days>(time);
                auto ymd = date::year_month_day(daypoint);   // calendar date
                auto time_of_day = date::make_time(time - daypoint); // Yields time_of_day type

                // Obtain individual components as integers
                DateTime dt{
                        int(ymd.year()),
                        unsigned(ymd.month()),
                        unsigned(ymd.day()),
                        static_cast<uint8_t>(time_of_day.hours().count()),
                        static_cast<uint8_t>(time_of_day.minutes().count()),
                        static_cast<uint8_t>(time_of_day.seconds().count())};

                return dt;
            }

        private:
            CronData data;
    };

}
