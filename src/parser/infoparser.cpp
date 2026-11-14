#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>
#include <vector>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <limits>
#include <stdexcept>

#include "config/regmatch.h"
#include "parser/config/proxy.h"
#include "utils/base64/base64.h"
#include "utils/rapidjson_extra.h"
#include "utils/regexp.h"
#include "utils/string.h"
#include "utils/time_compat.h"

static bool fitsTrafficBytes(double value)
{
    return value >= 0 &&
           value < std::ldexp(1.0, std::numeric_limits<unsigned long long>::digits);
}

unsigned long long streamToInt(const std::string &stream)
{
    if(stream.empty())
        return 0;
    double streamval = 1.0;
    std::vector<std::string> units = {"B", "KB", "MB", "GB", "TB", "PB", "EB"};
    size_t index = units.size();
    do
    {
        index--;
        if(endsWith(stream, units[index]))
        {
            streamval = std::pow(1024, index) * to_number<float>(stream.substr(0, stream.size() - units[index].size()), 0.0);
            break;
        }
    }
    while(index != 0);
    return fitsTrafficBytes(streamval) ? static_cast<unsigned long long>(streamval) : 0;
}

static bool parseQuotaPercent(const std::string &text, double &fraction)
{
    char *end;
    const float percent = std::strtof(text.c_str(), &end);
    if(end == text.c_str() || !(percent >= 0 && percent <= 100))
        return false;

    const auto suffix = text.find_first_not_of(" \t\r\n", end - text.c_str());
    if(suffix == std::string::npos || text[suffix] != '%' ||
       text.find_first_not_of(" \t\r\n", suffix + 1) != std::string::npos)
        return false;

    fraction = percent / 100.0;
    return true;
}

time_t dateStringToTimestamp(std::string date)
{
    time_t rawtime;
    time(&rawtime);
    if(startsWith(date, "left="))
    {
        time_t seconds_left = 0;
        date.erase(0, 5);
        if(endsWith(date, "d"))
        {
            date.erase(date.size() - 1);
            seconds_left = to_number<double>(date, 0.0) * 86400.0;
        }
        return rawtime + seconds_left;
    }
    else
    {
        struct tm expire_time;
        std::vector<std::string> date_array = split(date, ":");
        if(date_array.size() != 6)
            return 0;

        if(localtime_r(&rawtime, &expire_time) == nullptr)
            return 0;
        expire_time.tm_year = to_int(date_array[0], 1900) - 1900;
        expire_time.tm_mon = to_int(date_array[1], 1) - 1;
        expire_time.tm_mday = to_int(date_array[2]);
        expire_time.tm_hour = to_int(date_array[3]);
        expire_time.tm_min = to_int(date_array[4]);
        expire_time.tm_sec = to_int(date_array[5]);
        return mktime(&expire_time);
    }
}

bool getSubInfoFromHeader(const std::string &header, std::string &result)
{
    constexpr std::string_view name = "subscription-userinfo:";
    std::string_view headers(header);
    const auto response_start = headers.rfind("\nHTTP/");
    if(response_start != std::string_view::npos)
        headers.remove_prefix(response_start + 1);

    while(!headers.empty())
    {
        const auto line_end = headers.find('\n');
        auto line = headers.substr(0, line_end);
        headers.remove_prefix(line_end == std::string_view::npos
                                  ? headers.size() : line_end + 1);
        if(line.empty() || line == "\r")
            break;
        if(line.size() < name.size() ||
           !std::equal(name.begin(), name.end(), line.begin(),
                       [](char expected, unsigned char actual) {
                           return expected == std::tolower(actual);
                       }))
            continue;

        line.remove_prefix(name.size());
        const auto first = line.find_first_not_of(" \t\r");
        if(first == std::string_view::npos)
            return false;
        const auto last = line.find_last_not_of(" \t\r");
        result.assign(line.substr(first, last - first + 1));
        return true;
    }
    return false;
}

bool getSubInfoFromNodes(const std::vector<Proxy> &nodes, const RegexMatchConfigs &stream_rules, const RegexMatchConfigs &time_rules, std::string &result)
{
    std::string remarks, stream_info, time_info, retStr;

    for(const Proxy &x : nodes)
    {
        remarks = x.Remark;
        if(stream_info.empty())
        {
            for(const RegexMatchConfig &y : stream_rules)
            {
                if(regMatch(remarks, y.Match))
                {
                    retStr = regReplace(remarks, y.Match, y.Replace);
                    if(retStr != remarks)
                    {
                        stream_info = retStr;
                        break;
                    }
                }
                else
                    continue;
            }
        }

        remarks = x.Remark;
        if(time_info.empty())
        {
            for(const RegexMatchConfig &y : time_rules)
            {
                if(regMatch(remarks, y.Match))
                {
                    retStr = regReplace(remarks, y.Match, y.Replace);
                    if(retStr != remarks)
                    {
                        time_info = retStr;
                        break;
                    }
                }
                else
                    continue;
            }
        }

        if(!stream_info.empty() && !time_info.empty())
            break;
    }

    if(stream_info.empty() && time_info.empty())
        return false;

    //calculate how much stream left
    unsigned long long total = 0, used = 0;
    bool valid_quota = true;
    std::string total_str = getUrlArg(stream_info, "total"), left_str = getUrlArg(stream_info, "left"), used_str = getUrlArg(stream_info, "used");
    if(strFind(total_str, "%"))
    {
        const bool has_used = !used_str.empty();
        double fraction;
        valid_quota = (has_used || !left_str.empty()) &&
                      parseQuotaPercent(total_str, fraction);
        if(valid_quota)
        {
            const double divisor = has_used ? 1 - fraction : fraction;
            const auto known = streamToInt(has_used ? used_str : left_str);
            const double estimated = divisor > 0 ? known / divisor : -1.0;
            valid_quota = fitsTrafficBytes(estimated);
            if(valid_quota)
            {
                total = static_cast<unsigned long long>(estimated);
                used = has_used ? known : total - std::min(known, total);
            }
        }
    }
    else
    {
        total = streamToInt(total_str);
        if(!used_str.empty())
        {
            used = streamToInt(used_str);
        }
        else if(!left_str.empty())
        {
            auto left = streamToInt(left_str);
            if (left > total) left = 0;
            used = total - left;
        }
    }

    const unsigned long long expire = dateStringToTimestamp(time_info);
    if(!valid_quota && !expire)
        return false;
    if(valid_quota)
        result = "upload=0; download=" + std::to_string(used) + "; total=" + std::to_string(total) + ";";
    else
        result.clear();
    if(expire)
    {
        if(!result.empty())
            result += ' ';
        result += "expire=" + std::to_string(expire) + ";";
    }

    return true;
}

static bool parseSSDTrafficBytes(const std::string &value,
                                 unsigned long long &bytes)
{
    if(value.empty())
        return false;

    double gibibytes;
    size_t consumed;
    try
    {
        gibibytes = std::stod(value, &consumed);
    }
    catch(const std::invalid_argument &)
    {
        return false;
    }
    catch(const std::out_of_range &)
    {
        return false;
    }

    constexpr int gibibyte_shift = 30;
    const double limit = std::ldexp(
        1.0, std::numeric_limits<unsigned long long>::digits - gibibyte_shift);
    if(!(gibibytes >= 0 && gibibytes < limit) ||
       value.find_first_not_of(" \t\n\r\f\v", consumed) != std::string::npos)
        return false;

    bytes = static_cast<unsigned long long>(std::ldexp(gibibytes, gibibyte_shift));
    return true;
}

bool getSubInfoFromSSD(const std::string &sub, std::string &result)
{
    rapidjson::Document json;
    json.Parse(urlSafeBase64Decode(sub.substr(6)).data());
    if(json.HasParseError())
        return false;

    unsigned long long used, total;
    if(!parseSSDTrafficBytes(GetMember(json, "traffic_used"), used) ||
       !parseSSDTrafficBytes(GetMember(json, "traffic_total"), total))
        return false;
    result = "upload=0; download=" + std::to_string(used) + "; total=" + std::to_string(total) + ";";

    const std::string expire_str = GetMember(json, "expiry");
    unsigned long long expire = dateStringToTimestamp(regReplace(
        expire_str, R"(^(\d+)-(\d+)-(\d+) (\d+):(\d+)(?::(\d+))?$)",
        "$1:$2:$3:$4:$5:${6:-00}"));
    if(expire)
        result += " expire=" + std::to_string(expire) + ";";

    return true;
}
