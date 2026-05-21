#include <future>
#include <thread>
#include <utility>

#include "handler/settings.h"
#include "utils/network.h"
#include "webget.h"
#include "multithread.h"
//#include "vfs.h"

//safety lock for multi-thread
std::mutex on_emoji, on_rename, on_stream, on_time;

static std::shared_future<std::string> make_ready_future(std::string value)
{
    std::promise<std::string> promise;
    promise.set_value(std::move(value));
    return promise.get_future().share();
}

RegexMatchConfigs safe_get_emojis()
{
    guarded_mutex guard(on_emoji);
    return global.emojis;
}

RegexMatchConfigs safe_get_renames()
{
    guarded_mutex guard(on_rename);
    return global.renames;
}

RegexMatchConfigs safe_get_streams()
{
    guarded_mutex guard(on_stream);
    return global.streamNodeRules;
}

RegexMatchConfigs safe_get_times()
{
    guarded_mutex guard(on_time);
    return global.timeNodeRules;
}

void safe_set_emojis(RegexMatchConfigs data)
{
    guarded_mutex guard(on_emoji);
    global.emojis.swap(data);
}

void safe_set_renames(RegexMatchConfigs data)
{
    guarded_mutex guard(on_rename);
    global.renames.swap(data);
}

void safe_set_streams(RegexMatchConfigs data)
{
    guarded_mutex guard(on_stream);
    global.streamNodeRules.swap(data);
}

void safe_set_times(RegexMatchConfigs data)
{
    guarded_mutex guard(on_time);
    global.timeNodeRules.swap(data);
}

static bool canReadLocalFetchPath(const std::string &path,
                                  FetchContext context)
{
    if(!isPublicFetchRestricted(context))
        return true;
    if(isTrustedLocalResourcePath(path))
        return true;
    writeLog(0, "已阻止公开请求读取本地文件：" + path,
             LOG_LEVEL_WARNING);
    return false;
}

std::shared_future<std::string> fetchFileAsync(const std::string &path, const std::string &proxy, int cache_ttl, bool find_local, bool async, FetchContext context)
{
    if(!async)
    {
        if(find_local && fileExist(path, true) && canReadLocalFetchPath(path, context))
            return make_ready_future(fileGet(path, true));
        if(isLink(path))
            return make_ready_future(webGet(path, proxy, cache_ttl, nullptr, nullptr, context));
        return make_ready_future(std::string());
    }

    std::shared_future<std::string> retVal;
    /*if(vfs::vfs_exist(path))
        retVal = std::async(std::launch::async, [path](){return vfs::vfs_get(path);});
    else */if(find_local && fileExist(path, true) && canReadLocalFetchPath(path, context))
        retVal = std::async(std::launch::async, [path](){return fileGet(path, true);});
    else if(isLink(path))
        retVal = std::async(std::launch::async, [path, proxy, cache_ttl, context](){return webGet(path, proxy, cache_ttl, nullptr, nullptr, context);});
    else
        return make_ready_future(std::string());
    return retVal;
}

std::string fetchFile(const std::string &path, const std::string &proxy, int cache_ttl, bool find_local, FetchContext context)
{
    return fetchFileAsync(path, proxy, cache_ttl, find_local, false, context).get();
}
