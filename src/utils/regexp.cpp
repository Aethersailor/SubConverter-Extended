#include <string>
#include <cstdarg>
#include <memory>

#include <jpcre2.hpp>
using jp = jpcre2::select<char>;

#include "regexp.h"

struct CompiledRegex::Impl
{
    jp::Regex regex;
    bool valid = false;
};

CompiledRegex::CompiledRegex(const std::string &pattern, CompiledRegexMode mode)
    : impl_(std::make_unique<Impl>())
{
    if(mode == CompiledRegexMode::FullMatch)
    {
        impl_->regex.setPattern(pattern).addModifier("m").addPcre2Option(
            PCRE2_ANCHORED | PCRE2_ENDANCHORED | PCRE2_UTF).compile();
    }
    else if(mode == CompiledRegexMode::Replace)
    {
        impl_->regex.setPattern(pattern).addModifier("m").addPcre2Option(
            PCRE2_UTF | PCRE2_MULTILINE | PCRE2_ALT_BSUX).compile();
    }
    else
    {
        impl_->regex.setPattern(pattern).addModifier("m").addPcre2Option(
            PCRE2_UTF | PCRE2_ALT_BSUX).compile();
    }
    impl_->valid = !!impl_->regex;
}

CompiledRegex::~CompiledRegex() = default;
CompiledRegex::CompiledRegex(CompiledRegex &&) noexcept = default;
CompiledRegex &CompiledRegex::operator=(CompiledRegex &&) noexcept = default;

bool CompiledRegex::valid() const noexcept
{
    return impl_ && impl_->valid;
}

bool CompiledRegex::matches(const std::string &subject)
{
    return valid() && impl_->regex.match(subject, "g");
}

std::string CompiledRegex::replace(const std::string &subject,
                                   const std::string &replacement,
                                   bool global)
{
    if(!valid())
        return subject;
    return impl_->regex.replace(subject, replacement, global ? "gEx" : "Ex");
}

bool regMatch(const std::string &src, const std::string &match)
{
    jp::Regex reg;
    reg.setPattern(match).addModifier("m").addPcre2Option(PCRE2_ANCHORED|PCRE2_ENDANCHORED|PCRE2_UTF).compile();
    if(!reg)
        return false;
    return reg.match(src, "g");
}

bool regFind(const std::string &src, const std::string &match)
{
    jp::Regex reg;
    reg.setPattern(match).addModifier("m").addPcre2Option(PCRE2_UTF|PCRE2_ALT_BSUX).compile();
    if(!reg)
        return false;
    return reg.match(src, "g");
}

std::string regReplace(const std::string &src, const std::string &match, const std::string &rep, bool global, bool multiline)
{
    jp::Regex reg;
    reg.setPattern(match).addModifier(multiline ? "m" : "").addPcre2Option(PCRE2_UTF|PCRE2_MULTILINE|PCRE2_ALT_BSUX).compile();
    if(!reg)
        return src;
    return reg.replace(src, rep, global ? "gEx" : "Ex");
}

bool regValid(const std::string &reg)
{
    jp::Regex r;
    r.setPattern(reg).addPcre2Option(PCRE2_UTF|PCRE2_ALT_BSUX).compile();
    return !!r;
}

int regGetMatch(const std::string &src, const std::string &match, size_t group_count, ...)
{
    auto result = regGetAllMatch(src, match, false);
    if(result.empty())
        return -1;
    va_list vl;
    va_start(vl, group_count);
    size_t index = 0;
    while(group_count)
    {
        std::string* arg = va_arg(vl, std::string*);
        if(arg != nullptr)
            *arg = std::move(result[index]);
        index++;
        group_count--;
        if(result.size() <= index)
            break;
    }
    va_end(vl);
    return 0;
}

std::vector<std::string> regGetAllMatch(const std::string &src, const std::string &match, bool group_only)
{
    jp::Regex reg;
    reg.setPattern(match).addModifier("m").addPcre2Option(PCRE2_UTF|PCRE2_ALT_BSUX).compile();
    jp::VecNum vec_num;
    jp::RegexMatch rm;
    size_t count = rm.setRegexObject(&reg).setSubject(src).setNumberedSubstringVector(&vec_num).setModifier("gm").match();
    std::vector<std::string> result;
    if(!count)
        return result;
    size_t begin = 0;
    if(group_only)
        begin = 1;
    size_t index = begin, match_index = 0;
    while(true)
    {
        if(vec_num.size() <= match_index)
            break;
        if(vec_num[match_index].size() <= index)
        {
            match_index++;
            index = begin;
            continue;
        }
        result.push_back(std::move(vec_num[match_index][index]));
        index++;
    }
    return result;
}


std::string regTrim(const std::string &src)
{
    return regReplace(src, R"(^\s*([\s\S]*)\s*$)", "$1", false, false);
}
