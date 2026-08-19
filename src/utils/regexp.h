#ifndef REGEXP_H_INCLUDED
#define REGEXP_H_INCLUDED

#include <memory>
#include <string>
#include <vector>

enum class CompiledRegexMode {
    Search,
    FullMatch,
};

class CompiledRegex
{
public:
    CompiledRegex(const std::string &pattern, CompiledRegexMode mode);
    ~CompiledRegex();

    CompiledRegex(CompiledRegex &&) noexcept;
    CompiledRegex &operator=(CompiledRegex &&) noexcept;
    CompiledRegex(const CompiledRegex &) = delete;
    CompiledRegex &operator=(const CompiledRegex &) = delete;

    bool valid() const noexcept;
    bool matches(const std::string &subject);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

bool regValid(const std::string &reg);
bool regFind(const std::string &src, const std::string &match);
std::string regReplace(const std::string &src, const std::string &match, const std::string &rep, bool global = true, bool multiline = true);
bool regMatch(const std::string &src, const std::string &match);
int regGetMatch(const std::string &src, const std::string &match, size_t group_count, ...);
std::vector<std::string> regGetAllMatch(const std::string &src, const std::string &match, bool group_only = false);
std::string regTrim(const std::string &src);

#endif // REGEXP_H_INCLUDED
