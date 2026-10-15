#include <iostream>
#include <libcron/Cron.h>
#include <string>

#include "config/crontask.h"
#include "handler/multithread.h"
#include "handler/settings.h"
#include "script_quickjs.h"
#include "utils/logger.h"
#include "utils/system.h"

libcron::Cron cron;

struct script_info {
  std::string name;
  time_t begin_time = 0;
  time_t timeout = 0;
};

int timeout_checker(JSRuntime *rt, void *opaque) {
  script_info info = *static_cast<script_info *>(opaque);
  if (info.timeout != 0 &&
      time(NULL) >= info.begin_time + info.timeout) /// timeout reached
  {
    writeLog(LOG_LEVEL_WARNING,
             "脚本 '" + info.name + "' 已超过超时时间 " +
                 std::to_string(info.timeout) + " 秒，正在终止。");
    return 1;
  }
  return 0;
}

void refresh_schedule() {
  cron.clear_schedules();
  for (const CronTaskConfig &x : global.cronTasks) {
    cron.add_schedule(x.Name, x.CronExp, [=](auto &) {
      qjs::Runtime runtime;
      qjs::Context context(runtime);
      try {
        script_runtime_init(runtime);
        script_context_init(context);
        defer(script_cleanup(context);) ProxyPolicy proxy =
            parseProxy(global.proxyConfig, global.proxyBypass);
        std::string script = fetchFile(x.Path, proxy, global.cacheConfig);
        if (script.empty()) {
          writeLog(LOG_LEVEL_WARNING,
                   "脚本 '" + x.Name + "' 运行失败：文件为空或不存在！");
          return;
        }
        script_info info;
        if (x.Timeout > 0) {
          info.begin_time = time(NULL);
          info.timeout = x.Timeout;
          info.name = x.Name;
          JS_SetInterruptHandler(JS_GetRuntime(context.ctx), timeout_checker,
                                 &info);
        }
        context.eval(script);
      } catch (qjs::exception) {
        script_print_stack(context);
      }
    });
  }
}

size_t cron_tick() { return cron.tick(); }
