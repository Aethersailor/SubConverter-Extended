#ifndef RULESET_COMMENT_H_INCLUDED
#define RULESET_COMMENT_H_INCLUDED

#include <string>
#include <string_view>

namespace ruleset_comment_detail {

inline bool isSpace(unsigned char c)
{
    return c == ' ' || (c >= '\t' && c <= '\r');
}

inline void stripAt(std::string &line, size_t slash, bool raw_value)
{
    size_t first = 0;
    while(isSpace(line[first]))
        ++first;
    if(first == slash)
    {
        line.clear();
        return;
    }
    while(slash != std::string::npos &&
          !isSpace(line[slash - 1]))
        slash = line.find("//", slash + 2);
    if(slash == std::string::npos)
        return;

    // Only these structured values have an unambiguous inline-comment boundary.
    // Regex, logical, path and other free-text rules retain their entire value.
    if(!raw_value)
    {
        size_t end = line.find(',', first);
        if(end == std::string::npos || end > slash)
            end = slash;
        while(end > first && isSpace(line[end - 1]))
            --end;
        const std::string_view type(line.data() + first,
                                    end - first);
        constexpr std::string_view types[] = {
            "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6",
            "IP6-CIDR", "SRC-IP-CIDR", "SRC-IP", "IP-SUFFIX", "SRC-IP-SUFFIX",
            "GEOIP", "SRC-GEOIP", "GEOSITE", "IP-ASN", "SRC-IP-ASN",
            "SRC-PORT", "DST-PORT", "DEST-PORT", "IN-PORT", "PORT", "PORT-RANGE",
            "SRC-PORT-RANGE", "IP-VERSION", "NETWORK", "PROTOCOL", "DSCP", "UID",
            "USER-ID", "MATCH", "FINAL", "HOST", "HOST-SUFFIX", "HOST-KEYWORD"
        };
        bool structured = false;
        for(const auto candidate : types)
        {
            if(type == candidate)
            {
                structured = true;
                break;
            }
        }
        if(!structured)
            return;
    }

    if(line.find('"', first) >= slash && line.find('\'', first) >= slash &&
       line.find('\\', first) >= slash)
    {
        while(slash && isSpace(line[slash - 1]))
            --slash;
        line.erase(slash);
        return;
    }

    char quote = 0;
    bool escaped = false;
    for(size_t i = first; i + 1 < line.size(); ++i)
    {
        const char c = line[i];
        if(escaped)
            escaped = false;
        else if(c == '\\')
            escaped = true;
        else if(quote)
        {
            if(c == quote)
                quote = 0;
        }
        else if(c == '\'' || c == '"')
            quote = c;
        else if(c == '/' && line[i + 1] == '/' && i > first &&
                isSpace(line[i - 1]))
        {
            while(i && isSpace(line[i - 1]))
                --i;
            line.erase(i);
            return;
        }
    }
}

} // namespace ruleset_comment_detail

inline void stripRulesetComment(std::string &line, bool raw_value = false)
{
    const size_t slash = line.find("//");
    if(slash != std::string::npos)
        ruleset_comment_detail::stripAt(line, slash, raw_value);
}

#endif // RULESET_COMMENT_H_INCLUDED
