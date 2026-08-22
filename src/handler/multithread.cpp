#include <algorithm>
#include <atomic>
#include <future>
#include <thread>
#include <utility>

#include "handler/settings.h"
#include "handler/settings_view.h"
#include "server/request_context.h"
#include "utils/network.h"
#include "utils/bounded_executor.h"
#include "utils/cooperative_cpu.h"
#include "utils/resource_control.h"
#include "utils/system.h"
#include "webget.h"
#include "multithread.h"
//#include "vfs.h"

//safety lock for multi-thread
std::mutex on_emoji, on_rename, on_stream, on_time;

static bool forceMaxResourceBudgetApplied()
{
    const ResourceControlSnapshot resources = resourceControlSnapshot();
    return resources.effective_mode == "force_max" &&
           resources.startup_budget_applied;
}

static size_t configuredWorkerCount()
{
    const std::string configured =
        getEnv("SUBCONVERTER_RULESET_EXECUTOR_WORKERS");
    if(!configured.empty())
        return static_cast<size_t>(std::clamp(to_int(configured, 2), 1, 8));
    if(forceMaxResourceBudgetApplied())
        return static_cast<size_t>(
            std::max(1, effectiveSettings().maxConcurThreads));
    return static_cast<size_t>(
        std::clamp(effectiveSettings().maxConcurThreads / 2, 2, 8));
}

static size_t configuredQueueCapacity()
{
    const std::string configured =
        getEnv("SUBCONVERTER_RULESET_EXECUTOR_QUEUE_CAPACITY");
    if(!configured.empty())
        return static_cast<size_t>(
            std::clamp(to_int(configured, 64), 1, 1024));
    if(forceMaxResourceBudgetApplied())
        return static_cast<size_t>(
            std::max(1, effectiveSettings().maxPendingConns));
    return std::max<size_t>(64, configuredWorkerCount() * 16);
}

static std::atomic<BoundedExecutor *> activeRulesetExecutor {nullptr};
static std::atomic<bool> rulesetExecutorShutdownRequested {false};

static BoundedExecutor &rulesetExecutor()
{
    static BoundedExecutor executor(configuredWorkerCount(),
                                    configuredQueueCapacity());
    static const bool registered =
        (activeRulesetExecutor.store(&executor, std::memory_order_release), true);
    (void)registered;
    if(rulesetExecutorShutdownRequested.load(std::memory_order_acquire))
        executor.requestShutdown(true);
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

void shutdownRulesetExecutor()
{
    rulesetExecutorShutdownRequested.store(true, std::memory_order_release);
    requestOutboundFetchShutdown();
    BoundedExecutor *executor =
        activeRulesetExecutor.load(std::memory_order_acquire);
    if(executor)
        executor->shutdown(true);
}

void requestRulesetExecutorShutdown()
{
    rulesetExecutorShutdownRequested.store(true, std::memory_order_release);
    requestOutboundFetchShutdown();
    BoundedExecutor *executor =
        activeRulesetExecutor.load(std::memory_order_acquire);
    if(executor)
        executor->requestShutdown(true);
}

RegexMatchConfigs safe_get_emojis()
{
    guarded_mutex guard(on_emoji);
    return effectiveSettings().emojis;
}

RegexMatchConfigs safe_get_renames()
{
    guarded_mutex guard(on_rename);
    return effectiveSettings().renames;
}

RegexMatchConfigs safe_get_streams()
{
    guarded_mutex guard(on_stream);
    return effectiveSettings().streamNodeRules;
}

RegexMatchConfigs safe_get_times()
{
    guarded_mutex guard(on_time);
    return effectiveSettings().timeNodeRules;
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
    writeLog(LOG_LEVEL_WARNING, "已阻止公开请求读取本地文件：" + path);
    return false;
}

std::shared_future<std::string> fetchFileAsync(const std::string &path, const ProxyPolicy &proxy, int cache_ttl, bool find_local, bool async, FetchContext context)
{
    const bool trusted_local_path = isTrustedLocalResourcePath(path);
    const bool scope_limit = !trusted_local_path;
    if(!async)
    {
        if(find_local && fileExist(path, scope_limit) &&
           canReadLocalFetchPath(path, context))
            return makeReadyStringFuture(fileGet(path, scope_limit));
        if(isLink(path))
            return makeReadyStringFuture(webGet(path, proxy, cache_ttl, nullptr, nullptr, context));
        return makeReadyStringFuture(std::string());
    }

    std::future<std::string> retVal;
    if(find_local && fileExist(path, scope_limit) &&
       canReadLocalFetchPath(path, context))
    {
        std::shared_ptr<RequestContext> request_context =
            captureCurrentRequestContext();
        const auto deadline = request_context
            ? request_context->deadline()
            : RequestContext::Clock::time_point::max();
        const RequestCancellationToken cancellation = request_context
            ? request_context->cancellationToken()
            : RequestCancellationToken();
        auto submission = waitWithoutCpuPermit([&] {
            return rulesetExecutor().submitUntil(
                deadline, cancellation,
                [path, scope_limit, request_context](){
                    ScopedRequestContext scope(request_context);
                    return fileGet(path, scope_limit);
                });
        });
        retVal = std::move(submission.future);
    }
    else if(isLink(path))
    {
        SettingsSnapshot settings = captureEffectiveSettingsSnapshot();
        std::shared_ptr<RequestContext> request_context =
            captureCurrentRequestContext();
        const auto deadline = request_context
            ? request_context->deadline()
            : RequestContext::Clock::time_point::max();
        const RequestCancellationToken cancellation = request_context
            ? request_context->cancellationToken()
            : RequestCancellationToken();
        auto submission = waitWithoutCpuPermit([&] {
            return rulesetExecutor().submitUntil(
                deadline, cancellation,
                [path, proxy, cache_ttl, context, settings, request_context](){
                    ScopedRequestContext request_scope(request_context);
                    ScopedSettingsView view(settings);
                    return webGet(path, proxy, cache_ttl, nullptr, nullptr,
                                  context);
                });
        });
        retVal = std::move(submission.future);
    }
    else
        return makeReadyStringFuture(std::string());
    return retVal.share();
}

std::string fetchFile(const std::string &path, const ProxyPolicy &proxy, int cache_ttl, bool find_local, FetchContext context)
{
    return fetchFileAsync(path, proxy, cache_ttl, find_local, false, context).get();
}
