#pragma once

#include <functional>
#include <chrono>
#include <utility>
#include "CronData.h"
#include "CronSchedule.h"

namespace libcron
{
    class TaskInformation
    {
        public:
            virtual ~TaskInformation() = default;
            virtual std::chrono::system_clock::duration get_delay() const = 0;
            virtual std::string get_name() const = 0;
    };

    class Task : public TaskInformation
    {
        public:
            using TaskFunction = std::function<void(const TaskInformation&)>;

            Task(std::string name, const CronSchedule schedule, TaskFunction task)
                    : name(std::move(name)), schedule(std::move(schedule)), task(std::move(task))
            {
            }

            void execute(std::chrono::system_clock::time_point now)
            {
                // Next Schedule is still the current schedule, calculate delay (actual execution - planned execution)
                delay = now - next_schedule;

                last_run = now;
                task(*this);
            }

            std::chrono::system_clock::duration get_delay() const override
            {
                return delay;
            }

            Task(const Task& other) = default;

            Task& operator=(const Task&) = default;

            bool calculate_next(std::chrono::system_clock::time_point from);

            bool operator>(const Task& other) const
            {
                return next_schedule > other.next_schedule;
            }

            bool operator<(const Task& other) const
            {
                return next_schedule < other.next_schedule;
            }

            bool is_expired(std::chrono::system_clock::time_point now) const;

            std::chrono::system_clock::duration
            time_until_expiry(std::chrono::system_clock::time_point now) const;

            std::string get_name() const override
            {
                return name;
            }

            std::string get_status(std::chrono::system_clock::time_point now) const;

        private:
            std::string name;
            CronSchedule schedule;
            std::chrono::system_clock::time_point next_schedule;
            std::chrono::system_clock::duration delay = std::chrono::seconds(-1);
            TaskFunction task;
            bool valid = false;
            std::chrono::system_clock::time_point last_run = std::numeric_limits<std::chrono::system_clock::time_point>::min();
    };
}

inline bool operator==(const std::string &lhs, const libcron::Task &rhs)
{
    return lhs == rhs.get_name();
}

inline bool operator==(const libcron::Task &lhs, const std::string &rhs)
{
    return lhs.get_name() == rhs;
}

inline bool operator!=(const std::string &lhs, const libcron::Task &rhs)
{
    return !(lhs == rhs);
}

inline bool operator!=(const libcron::Task &lhs, const std::string &rhs)
{
    return !(lhs == rhs);
}
