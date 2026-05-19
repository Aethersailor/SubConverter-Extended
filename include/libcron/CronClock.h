#pragma once

#include <chrono>

namespace libcron
{
    class ICronClock
    {
        public:
            virtual std::chrono::system_clock::time_point now() const = 0;
            virtual std::chrono::seconds utc_offset(std::chrono::system_clock::time_point now) const = 0;
    };

    class UTCClock
            : public ICronClock
    {
        public:
            std::chrono::system_clock::time_point now() const override
            {
                return std::chrono::system_clock::now();
            }

            std::chrono::seconds utc_offset(std::chrono::system_clock::time_point) const override
            {
				using namespace std::chrono;
                return 0s;
            }
    };

    class LocalClock
            : public ICronClock
    {
        public:
            std::chrono::system_clock::time_point now() const override
            {
                auto now = std::chrono::system_clock::now();
                return now + utc_offset(now);
            }

			std::chrono::seconds utc_offset(std::chrono::system_clock::time_point now) const override;
    };
}
