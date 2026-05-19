#pragma once

#include <set>
#include <regex>
#include <string>
#include <vector>
#include <unordered_map>
#include <libcron/TimeTypes.h>

namespace libcron
{
    class CronData
    {
        public:
            static const int NUMBER_OF_LONG_MONTHS = 7;
            static const libcron::Months months_with_31[NUMBER_OF_LONG_MONTHS];

            static CronData create(const std::string& cron_expression);

            CronData() = default;

            CronData(const CronData&) = default;

            CronData& operator=(const CronData&) = default;

            bool is_valid() const
            {
                return valid;
            }

            const std::set<Seconds>& get_seconds() const
            {
                return seconds;
            }

            const std::set<Minutes>& get_minutes() const
            {
                return minutes;
            }

            const std::set<Hours>& get_hours() const
            {
                return hours;
            }

            const std::set<DayOfMonth>& get_day_of_month() const
            {
                return day_of_month;
            }

            const std::set<Months>& get_months() const
            {
                return months;
            }

            const std::set<DayOfWeek>& get_day_of_week() const
            {
                return day_of_week;
            }

            template<typename T>
            static uint8_t value_of(T t)
            {
                return static_cast<uint8_t>(t);
            }

            template<typename T>
            static bool has_any_in_range(const std::set<T>& set, uint8_t low, uint8_t high)
            {
                bool found = false;

                for (auto i = low; !found && i <= high; ++i)
                {
                    found |= set.find(static_cast<T>(i)) != set.end();
                }

                return found;
            }

            template<typename T>
            bool convert_from_string_range_to_number_range(const std::string& range, std::set<T>& numbers);

            template<typename T>
            static std::string& replace_string_name_with_numeric(std::string& s);

        private:
            void parse(const std::string& cron_expression);

            template<typename T>
            bool validate_numeric(const std::string& s, std::set<T>& numbers);

            template<typename T>
            bool validate_literal(const std::string& s,
                                  std::set<T>& numbers,
                                  const std::vector<std::string>& names);

            template<typename T>
            bool process_parts(const std::vector<std::string>& parts, std::set<T>& numbers);

            template<typename T>
            bool add_number(std::set<T>& set, int32_t number);

            template<typename T>
            bool is_within_limits(int32_t low, int32_t high);

            template<typename T>
            bool get_range(const std::string& s, T& low, T& high);

            template<typename T>
            bool get_step(const std::string& s, uint8_t& start, uint8_t& step);

            std::vector<std::string> split(const std::string& s, char token);

            bool is_number(const std::string& s);

            bool is_between(int32_t value, int32_t low_limit, int32_t high_limit);

            bool validate_date_vs_months() const;

            bool check_dom_vs_dow(const std::string& dom, const std::string& dow) const;

            std::set<Seconds> seconds{};
            std::set<Minutes> minutes{};
            std::set<Hours> hours{};
            std::set<DayOfMonth> day_of_month{};
            std::set<Months> months{};
            std::set<DayOfWeek> day_of_week{};
            bool valid = false;

            static const std::vector<std::string> month_names;
            static const std::vector<std::string> day_names;
            static std::unordered_map<std::string, CronData> cache;

            template<typename T>
            void add_full_range(std::set<T>& set);
    };

    template<typename T>
    bool CronData::validate_numeric(const std::string& s, std::set<T>& numbers)
    {
        std::vector<std::string> parts = split(s, ',');

        return process_parts(parts, numbers);
    }

    template<typename T>
    bool CronData::validate_literal(const std::string& s,
                                    std::set<T>& numbers,
                                    const std::vector<std::string>& names)
    {
        std::vector<std::string> parts = split(s, ',');

        auto value_of_first_name = value_of(T::First);

        // Replace each found name with the corresponding value.
        for (const auto& name : names)
        {
            std::regex m(name, std::regex_constants::ECMAScript | std::regex_constants::icase);

            for (auto& part : parts)
            {
                std::string replaced;
                std::regex_replace(std::back_inserter(replaced), part.begin(), part.end(), m,
                                   std::to_string(value_of_first_name));

                part = replaced;
            }

            value_of_first_name++;
        }

        return process_parts(parts, numbers);
    }

    template<typename T>
    bool CronData::process_parts(const std::vector<std::string>& parts, std::set<T>& numbers)
    {
        bool res = true;

        for (const auto& p : parts)
        {
            res &= convert_from_string_range_to_number_range(p, numbers);
        }

        return res;
    }

    template<typename T>
    bool CronData::get_range(const std::string& s, T& low, T& high)
    {
        bool res = false;

        auto value_range = R"#((\d+)-(\d+))#";

        std::regex range(value_range, std::regex_constants::ECMAScript);

        std::smatch match;

        if (std::regex_match(s.begin(), s.end(), match, range))
        {
            auto left = std::stoi(match[1].str());
            auto right = std::stoi(match[2].str());

            if (is_within_limits<T>(left, right))
            {
                low = static_cast<T>(left);
                high = static_cast<T>(right);
                res = true;
            }
        }

        return res;
    }

    template<typename T>
    bool CronData::get_step(const std::string& s, uint8_t& start, uint8_t& step)
    {
        bool res = false;

        auto value_range = R"#((\d+|\*)/(\d+))#";

        std::regex range(value_range, std::regex_constants::ECMAScript);

        std::smatch match;

        if (std::regex_match(s.begin(), s.end(), match, range))
        {
            int raw_start;

            if (match[1].str() == "*")
            {
                raw_start = value_of(T::First);
            }
            else
            {
                raw_start = std::stoi(match[1].str());
            }

            auto raw_step = std::stoi(match[2].str());

            if (is_within_limits<T>(raw_start, raw_start) && raw_step > 0)
            {
                start = static_cast<uint8_t>(raw_start);
                step = static_cast<uint8_t>(raw_step);
                res = true;
            }
        }

        return res;
    }

    template<typename T>
    void CronData::add_full_range(std::set<T>& set)
    {
        for (auto v = value_of(T::First); v <= value_of(T::Last); ++v)
        {
            if (set.find(static_cast<T>(v)) == set.end())
            {
                set.emplace(static_cast<T>(v));
            }
        }
    }

    template<typename T>
    bool CronData::add_number(std::set<T>& set, int32_t number)
    {
        bool res = true;

        // Don't add if already there
        if (set.find(static_cast<T>(number)) == set.end())
        {
            // Check range
            if (is_within_limits<T>(number, number))
            {
                set.emplace(static_cast<T>(number));
            }
            else
            {
                res = false;
            }
        }

        return res;
    }

    template<typename T>
    bool CronData::is_within_limits(int32_t low, int32_t high)
    {
        return is_between(low, value_of(T::First), value_of(T::Last))
               && is_between(high, value_of(T::First), value_of(T::Last));
    }

    template<typename T>
    bool CronData::convert_from_string_range_to_number_range(const std::string& range, std::set<T>& numbers)
    {
        T left;
        T right;
        uint8_t step_start;
        uint8_t step;

        bool res = true;

        if (range == "*" || range == "?")
        {
            // We treat the ignore-character '?' the same as the full range being allowed.
            add_full_range<T>(numbers);
        }
        else if (is_number(range))
        {
            res = add_number<T>(numbers, std::stoi(range));
        }
        else if (get_range<T>(range, left, right))
        {
            // A range can be written as both 1-22 or 22-1, meaning totally different ranges.
            // First case is 1...22 while 22-1 is only four hours: 22, 23, 0, 1.
            if (left <= right)
            {
                for (auto v = value_of(left); v <= value_of(right); ++v)
                {
                    res &= add_number(numbers, v);
                }
            }
            else
            {
                // 'left' and 'right' are not in value order. First, get values between 'left' and T::Last, inclusive
                for (auto v = value_of(left); v <= value_of(T::Last); ++v)
                {
                    res = add_number(numbers, v);
                }

                // Next, get values between T::First and 'right', inclusive.
                for (auto v = value_of(T::First); v <= value_of(right); ++v)
                {
                    res = add_number(numbers, v);
                }
            }
        }
        else if (get_step<T>(range, step_start, step))
        {
            // Add from step_start to T::Last with a step of 'step'
            for (auto v = step_start; v <= value_of(T::Last); v += step)
            {
                res = add_number(numbers, v);
            }
        }
        else
        {
            res = false;
        }

        return res;
    }

    template<typename T>
    std::string & CronData::replace_string_name_with_numeric(std::string& s)
    {
        auto value = static_cast<int>(T::First);

        const std::vector<std::string>* name_source{};

        static_assert(std::is_same<T, libcron::Months>()
                      || std::is_same<T, libcron::DayOfWeek>(),
                        "T must be either Months or DayOfWeek");

        if constexpr (std::is_same<T, libcron::Months>())
        {
            name_source = &month_names;
        }
        else
        {
            name_source = &day_names;
        }

        for (const auto& name : *name_source)
        {
            std::regex m(name, std::regex_constants::ECMAScript | std::regex_constants::icase);

            std::string replaced;

            std::regex_replace(std::back_inserter(replaced), s.begin(), s.end(), m, std::to_string(value));

            s = replaced;

            ++value;
        }

        return s;
    }
}
