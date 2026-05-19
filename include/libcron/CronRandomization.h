#pragma once

#include <tuple>
#include <random>
#include <regex>
#include <functional>
#include "CronData.h"

namespace libcron
{
    class CronRandomization
    {
        public:
            std::tuple<bool, std::string> parse(const std::string& cron_schedule);

            CronRandomization();

            CronRandomization(const CronRandomization&) = delete;

            CronRandomization & operator=(const CronRandomization &) = delete;

        private:
            template<typename T>
            std::pair<bool, std::string> get_random_in_range(const std::string& section,
                                                             int& selected_value,
                                                             std::pair<int, int> limit = std::make_pair(-1, -1));

            std::pair<int, int> day_limiter(const std::set<Months>& month);

            int cap(int value, int lower, int upper);

            std::regex const rand_expression{ R"#([rR]\((\d+)\-(\d+)\))#", std::regex_constants::ECMAScript };
            std::random_device rd{};
            std::mt19937 twister;
    };

    template<typename T>
    std::pair<bool, std::string> CronRandomization::get_random_in_range(const std::string& section,
                                                                        int& selected_value,
                                                                        std::pair<int, int> limit)
    {
        auto res = std::make_pair(true, std::string{});
        selected_value = -1;

        std::smatch random_match;

        if (std::regex_match(section.cbegin(), section.cend(), random_match, rand_expression))
        {
            // Random range, get left and right numbers.
            auto left = std::stoi(random_match[1].str());
            auto right = std::stoi(random_match[2].str());

            if (limit.first != -1 && limit.second != -1)
            {
                left = cap(left, limit.first, limit.second);
                right = cap(right, limit.first, limit.second);
            }

            libcron::CronData cd;
            std::set<T> numbers;
            res.first = cd.convert_from_string_range_to_number_range<T>(
                    std::to_string(left) + "-" + std::to_string(right), numbers);

            // Remove items outside limits.
            if (limit.first != -1 && limit.second != -1)
            {
                for (auto it = numbers.begin(); it != numbers.end(); )
                {
                    if (CronData::value_of(*it) < limit.first || CronData::value_of(*it) > limit.second)
                    {
                        it = numbers.erase(it);
                    }
                    else
                    {
                        ++it;
                    }
                }
            }

            if (res.first)
            {
                // Generate random indexes to select one of the numbers in the range.
                std::uniform_int_distribution<> dis(0, static_cast<int>(numbers.size() - 1));

                // Select the random number to use as the schedule
                auto it = numbers.begin();
                std::advance(it, dis(twister));
                selected_value = CronData::value_of(*it);
                res.second = std::to_string(selected_value);
            }
        }
        else
        {
            // Not random, just append input to output.
            res.second = section;
        }

        return res;
    }
}
