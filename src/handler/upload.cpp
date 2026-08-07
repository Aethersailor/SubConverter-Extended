#include <string>

#include "utils/ini_reader/ini_reader.h"
#include "utils/logger.h"
#include "utils/rapidjson_extra.h"
#include "utils/redact.h"
#include "utils/system.h"
#include "handler/settings.h"
#include "webget.h"

namespace {

std::string gistApiUrl(const std::string &path)
{
    std::string base = trimWhitespace(getEnv("SUBCONVERTER_GIST_API_BASE"), true, true);
    if(base.empty())
        base = "https://api.github.com";
    while(endsWith(base, "/"))
        base.pop_back();
    return base + path;
}

}

std::string buildGistData(std::string name, std::string content)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    writer.StartObject();
    writer.Key("description");
    writer.String("SubConverter-Extended");
    writer.Key("public");
    writer.Bool(false);
    writer.Key("files");
    writer.StartObject();
    writer.Key(name.data());
    writer.StartObject();
    writer.Key("content");
    writer.String(content.data());
    writer.EndObject();
    writer.EndObject();
    writer.EndObject();
    return sb.GetString();
}

int uploadGist(std::string name, std::string path, std::string content, bool writeManageURL)
{
    INIReader ini;
    rapidjson::Document json;
    std::string token, id, username, retData, url;
    int retVal = 0;

    if(!fileExist("gistconf.ini"))
    {
        //std::cerr<<"gistconf.ini not found. Skipping...\n";
        writeLog(0, "未找到 gistconf.ini，跳过。", LOG_LEVEL_ERROR);
        return -1;
    }

    ini.parse_file("gistconf.ini");
    if(ini.enter_section("common") != 0)
    {
        //std::cerr<<"gistconf.ini has incorrect format. Skipping...\n";
        writeLog(0, "gistconf.ini 格式不正确，跳过。", LOG_LEVEL_ERROR);
        return -1;
    }

    token = ini.get("token");
    if(!token.size())
    {
        //std::cerr<<"No token is provided. Skipping...\n";
        writeLog(0, "未提供 token，跳过。", LOG_LEVEL_ERROR);
        return -1;
    }

    id = ini.get("id");
    username = ini.get("username");
    if(!path.size())
    {
        if(ini.item_exist("path"))
            path = ini.get(name, "path");
        else
            path = name;
    }

    if(!id.size())
    {
        //std::cerr<<"No gist id is provided. Creating new gist...\n";
        writeLog(0, "未提供 Gist ID，正在创建新 Gist...", LOG_LEVEL_ERROR);
        retVal = webPost(gistApiUrl("/gists"), buildGistData(path, content), parseProxy(global.proxyConfig), {{"Authorization", "token " + token}}, &retData);
        if(retVal != 201)
        {
            //std::cerr<<"Create new Gist failed! Return data:\n"<<retData<<"\n";
            writeLog(0,
                     "GIST_CREATE_FAILED status=" + std::to_string(retVal) +
                         " detail=" + summarizeSensitiveTextForLog(retData),
                     LOG_LEVEL_ERROR);
            return -1;
        }
    }
    else
    {
        url = "https://gist.githubusercontent.com/" + username + "/" + id + "/raw/" + path;
        //std::cerr<<"Gist id provided. Modifying Gist...\n";
        writeLog(0, "已提供 Gist ID，正在修改 Gist...", LOG_LEVEL_INFO);
        if(writeManageURL)
            content = "#!MANAGED-CONFIG " + url + "\n" + content;
        retVal = webPatch(gistApiUrl("/gists/" + id), buildGistData(path, content), parseProxy(global.proxyConfig), {{"Authorization", "token " + token}}, &retData);
        if(retVal != 200)
        {
            //std::cerr<<"Modify gist failed! Return data:\n"<<retData<<"\n";
            writeLog(0,
                     "GIST_UPDATE_FAILED status=" + std::to_string(retVal) +
                         " detail=" + summarizeSensitiveTextForLog(retData),
                     LOG_LEVEL_ERROR);
            return -1;
        }
    }
    json.Parse(retData.data());
    GetMember(json, "id", id);
    if(json.HasMember("owner"))
        GetMember(json["owner"], "login", username);
    url = "https://gist.githubusercontent.com/" + username + "/" + id + "/raw/" + path;
    ini.erase_section();
    ini.set("token", token);
    ini.set("id", id);
    ini.set("username", username);

    ini.set_current_section(path);
    ini.erase_section();
    ini.set("type", name);
    ini.set("url", url);

    const FileCommitResult persistence_result =
        static_cast<FileCommitResult>(ini.to_file("gistconf.ini"));
    if(persistence_result != FileCommitResult::Durable)
    {
        writeLog(0,
                 "GIST_REMOTE_UPLOAD_COMPLETED_LOCAL_STATE_FAILED target=" +
                     name + " remote=" + summarizeUrlForLog(url) +
                     (persistence_result == FileCommitResult::CommittedUnsynced
                          ? " local_state_visible=true durability=unconfirmed"
                          : " local_state_visible=false") +
                     " action=report-failure",
                 LOG_LEVEL_ERROR);
        return -1;
    }
    writeLog(0,
             "GIST_UPLOAD_COMPLETE target=" + name +
                 " remote=" + summarizeUrlForLog(url) +
                 " local_state=persisted",
             LOG_LEVEL_INFO);
    return 0;
}
