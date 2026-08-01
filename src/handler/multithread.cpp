#include <algorithm>
#include <future>
#include <thread>
#include <utility>

#include "handler/settings.h"
#include "utils/network.h"
#include "utils/bounded_executor.h"
#include "webget.h"
#include "multithread.h"
//#include "vfs.h"

//safety lock for multi-thread
std::mutex on_emoji, on_rename, on_stream, on_time;

static size_t configuredWorkerCount()
{
    return static_cast<size_t>(
        std::clamp(global.maxConcurThreads / 2, 2, 8));
}

static size_t configuredQueueCapacity()
{
    return std::max<size_t>(64, configuredWorkerCount() * 16);
}

static BoundedExecutor &rulesetExecutor()
{
    static BoundedExecutor executor(configuredWorkerCount(),
                                    configuredQueueCapacity());
    return executor;
}

std::shared_future<std::string> makeReadyStringFuture(std::string value)
{
    std::promise<std::string> promise;
    promise.set_value(std::move(value));
    return promise.get_future().share();
}

size_t rulesetExecutorWorkerCount()
{
    return rulesetExecutor().workerCount();
}

size_t rulesetExecutorQueueCapacity()
{
    return rulesetExecutor().queueCapacity();
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

void safe_replace_settings(Settings &&settings)
{
    std::scoped_lock guard(on_emoji, on_rename, on_stream, on_time);
    global = std::move(settings);
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

static std::string fetchFileWithState(
    const std::string &path, const ProxyPolicy &proxy, int cache_ttl,
    bool find_local, FetchContext context,
    const std::shared_ptr<RulesetFetchState> &fetch_state) {
    auto record = [&](int status_code, bool request_rejected) {
        if (!fetch_state)
            return;
        fetch_state->status_code.store(status_code);
        fetch_state->request_rejected.store(request_rejected);
    };
    auto validContent = [](const std::string &content) {
        const std::string trimmed = trimWhitespace(content, true, true);
        const std::string lower = toLower(trimmed);
        return !trimmed.empty() && !startsWith(lower, "<!doctype html") &&
               !startsWith(lower, "<html");
    };

    if (find_local && fileExist(path, true)) {
        if (!canReadLocalFetchPath(path, context)) {
            record(403, true);
            return {};
        }
        std::string content = fileGet(path, true);
        if (!validContent(content)) {
            record(422, false);
            return {};
        }
        record(200, false);
        return content;
    }

    if (!isLink(path)) {
        record(isPublicFetchRestricted(context) ? 403 : 400,
               isPublicFetchRestricted(context));
        return {};
    }

    FetchArgument argument{HTTP_GET,
                           path,
                           proxy,
                           nullptr,
                           nullptr,
                           nullptr,
                           static_cast<unsigned int>(std::max(cache_ttl, 0)),
                           false,
                           context,
                           false};
    FetchOutcome outcome;
    fetchRemote(argument, outcome);
    record(outcome.status_code,
           outcome.failure == FetchFailureCategory::RequestRejected);
    if (!outcome.success || !validContent(outcome.content)) {
        if (outcome.success)
            record(422, false);
        return {};
    }
    return outcome.content;
}

std::shared_future<std::string> fetchFileAsync(
    const std::string &path, const ProxyPolicy &proxy, int cache_ttl,
    bool find_local, bool async, FetchContext context,
    std::shared_ptr<RulesetFetchState> fetch_state) {
    if (!fetch_state) {
        if (!async) {
            if (find_local && fileExist(path, true) &&
                canReadLocalFetchPath(path, context))
                return makeReadyStringFuture(fileGet(path, true));
            if (isLink(path))
                return makeReadyStringFuture(
                    webGet(path, proxy, cache_ttl, nullptr, nullptr, context));
            return makeReadyStringFuture(std::string());
        }

        std::future<std::string> retVal;
        if (find_local && fileExist(path, true) &&
            canReadLocalFetchPath(path, context))
            retVal = rulesetExecutor().submit(
                [path]() { return fileGet(path, true); });
        else if (isLink(path))
            retVal = rulesetExecutor().submit(
                [path, proxy, cache_ttl, context]() {
                    return webGet(path, proxy, cache_ttl, nullptr, nullptr,
                                  context);
                });
        else
            return makeReadyStringFuture(std::string());
        return retVal.share();
    }

    if (!async)
        return makeReadyStringFuture(fetchFileWithState(
            path, proxy, cache_ttl, find_local, context, fetch_state));

    return rulesetExecutor()
        .submit([path, proxy, cache_ttl, find_local, context, fetch_state]() {
            return fetchFileWithState(path, proxy, cache_ttl, find_local,
                                      context, fetch_state);
        })
        .share();
}

std::string fetchFile(const std::string &path, const ProxyPolicy &proxy, int cache_ttl, bool find_local, FetchContext context)
{
    return fetchFileAsync(path, proxy, cache_ttl, find_local, false, context).get();
}
