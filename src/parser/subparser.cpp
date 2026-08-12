#include <algorithm>
#include <cctype>
#include <initializer_list>
#include <string>
#include <map>

#include "utils/base64/base64.h"
#include "utils/ini_reader/ini_reader.h"
#include "utils/network.h"
#include "utils/rapidjson_extra.h"
#include "utils/regexp.h"
#include "utils/redact.h"
#include "utils/string.h"
#include "utils/string_hash.h"
#include "utils/urlencode.h"
#include "utils/yamlcpp_extra.h"
#include "config/proxy.h"
#include "subparser.h"
#include "utils/logger.h"

using namespace rapidjson;
using namespace rapidjson_ext;
using namespace YAML;

string_array ss_ciphers = {
    "rc4-md5", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "aes-128-cfb", "aes-192-cfb",
    "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "camellia-128-cfb",
    "camellia-192-cfb", "camellia-256-cfb", "bf-cfb", "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305", "salsa20", "chacha20", "chacha20-ietf", "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "2022-blake3-chacha12-poly1305",
    "2022-blake3-chacha8-poly1305"
};
string_array ssr_ciphers = {
    "none", "table", "rc4", "rc4-md5", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "bf-cfb", "camellia-128-cfb",
    "camellia-192-cfb", "camellia-256-cfb", "cast5-cfb", "des-cfb", "idea-cfb", "rc2-cfb",
    "seed-cfb", "salsa20", "chacha20", "chacha20-ietf"
};

std::map<std::string, std::string> parsedMD5;
std::string modSSMD5 = "f7653207090ce3389115e9c88541afe0";

//remake from speedtestutil
std::string removeBrackets(const std::string& input) {
    std::string result = input;
    size_t left = result.find('[');
    size_t right = result.find(']');

    if (left != std::string::npos && right != std::string::npos && right > left) {
        result.erase(right, 1); // 删除 ']'
        result.erase(left, 1);  // 删除 '['
    }

    return result;
}

void extractRemark(std::string &link, std::string &remark) {
    string_size pos = link.rfind("#");
    if (pos != link.npos) {
        remark = urlDecode(link.substr(pos + 1));
        link.erase(pos);
    }

    pos = link.find("#");
    if (pos != link.npos) {
        link.erase(pos);
    }
}

namespace {

struct ParsedShareUri {
    std::string user;
    std::string host;
    std::string port;
    std::string query;
    std::string remark;
};

int shareUriHexValue(unsigned char ch) {
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    return -1;
}

// Userinfo follows RFC 3986 percent-encoding, not HTML form encoding. A
// literal '+' therefore remains '+'. Query values use the project's regular
// form-style URL decoder below, matching url.Values-based Xray generators.
std::string decodeShareUriUserInfo(const std::string &value) {
    std::string decoded;
    decoded.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        unsigned char ch = static_cast<unsigned char>(value[i]);
        if (ch == '%' && i + 2 < value.size()) {
            const int high = shareUriHexValue(static_cast<unsigned char>(value[i + 1]));
            const int low = shareUriHexValue(static_cast<unsigned char>(value[i + 2]));
            if (high >= 0 && low >= 0) {
                ch = static_cast<unsigned char>((high << 4) | low);
                i += 2;
            }
        }
        if (ch != '\r' && ch != '\n')
            decoded.push_back(static_cast<char>(ch));
    }
    return decoded;
}

bool validSharePort(const std::string &port) {
    if (port.empty() || port.size() > 5 ||
        !std::all_of(port.begin(), port.end(), [](unsigned char ch) {
            return std::isdigit(ch) != 0;
        }))
        return false;
    const int value = to_int(port, 0);
    return value >= 1 && value <= 65535;
}

bool decodeStrictBase64(const std::string &encoded, std::string &decoded) {
    if (encoded.empty())
        return false;

    size_t padding_start = encoded.size();
    for (size_t i = 0; i < encoded.size(); ++i) {
        const unsigned char ch = static_cast<unsigned char>(encoded[i]);
        if (ch == '=') {
            padding_start = std::min(padding_start, i);
            continue;
        }
        if (padding_start != encoded.size() ||
            !(std::isalnum(ch) || ch == '-' || ch == '_' || ch == '+' || ch == '/'))
            return false;
    }
    const size_t padding = encoded.size() - padding_start;
    if (padding > 0) {
        const size_t expected_padding =
            padding_start % 4 == 2 ? 2 : (padding_start % 4 == 3 ? 1 : 0);
        if (encoded.size() % 4 != 0 || padding != expected_padding)
            return false;
    } else if (padding_start % 4 == 1) {
        return false;
    }

    std::string candidate = urlSafeBase64Decode(encoded);
    std::string normalized = encoded.substr(0, padding_start);
    normalized = replaceAllDistinct(replaceAllDistinct(normalized, "+", "-"), "/", "_");
    if (urlSafeBase64Encode(candidate) != normalized)
        return false;
    decoded = std::move(candidate);
    return true;
}

bool parseShareAuthority(const std::string &authority, std::string &host,
                         std::string &port) {
    if (authority.empty())
        return false;
    if (authority.front() == '[') {
        const size_t bracket = authority.find(']');
        if (bracket == std::string::npos || bracket + 2 >= authority.size() ||
            authority[bracket + 1] != ':')
            return false;
        host = authority.substr(1, bracket - 1);
        port = authority.substr(bracket + 2);
    } else {
        const size_t colon = authority.rfind(':');
        if (colon == std::string::npos || colon == 0 || colon + 1 >= authority.size() ||
            authority.find(':') != colon)
            return false;
        host = authority.substr(0, colon);
        port = authority.substr(colon + 1);
    }
    return !host.empty() && host.find_first_of("\r\n") == std::string::npos &&
           validSharePort(port);
}

bool parseUserPassword(const std::string &userinfo, bool allow_plain,
                       std::string &username, std::string &password) {
    std::string decoded;
    if (allow_plain && userinfo.find(':') != std::string::npos)
        decoded = decodeShareUriUserInfo(userinfo);
    else if (!decodeStrictBase64(userinfo, decoded))
        return false;

    const size_t colon = decoded.find(':');
    if (colon == std::string::npos)
        return false;
    username = decoded.substr(0, colon);
    password = decoded.substr(colon + 1);
    return username.find_first_of("\r\n") == std::string::npos &&
           password.find_first_of("\r\n") == std::string::npos;
}

bool parseShareUri(std::string uri, const std::string &scheme, ParsedShareUri &parsed) {
    const std::string prefix = scheme + "://";
    if (!startsWith(uri, prefix))
        return false;
    uri.erase(0, prefix.size());

    extractRemark(uri, parsed.remark);
    const size_t query_pos = uri.find('?');
    if (query_pos != std::string::npos) {
        parsed.query = uri.substr(query_pos + 1);
        uri.erase(query_pos);
    }
    if (!uri.empty() && uri.back() == '/')
        uri.pop_back();

    const size_t at = uri.rfind('@');
    if (at == std::string::npos || at == 0 || at + 1 >= uri.size())
        return false;
    parsed.user = decodeShareUriUserInfo(uri.substr(0, at));
    std::string authority = uri.substr(at + 1);

    if (!authority.empty() && authority.front() == '[') {
        const size_t bracket = authority.find(']');
        if (bracket == std::string::npos || bracket + 1 >= authority.size() || authority[bracket + 1] != ':')
            return false;
        parsed.host = authority.substr(1, bracket - 1);
        parsed.port = authority.substr(bracket + 2);
    } else {
        const size_t colon = authority.rfind(':');
        if (colon == std::string::npos || colon == 0 || colon + 1 >= authority.size())
            return false;
        parsed.host = authority.substr(0, colon);
        parsed.port = authority.substr(colon + 1);
    }

    return !parsed.user.empty() && !parsed.host.empty() && validSharePort(parsed.port);
}

bool validHysteria2PortToken(const std::string &token, uint16_t &first_port,
                             std::string &remaining) {
    const size_t dash = token.find('-');
    if (dash == std::string::npos) {
        if (!validSharePort(token))
            return false;
        first_port = static_cast<uint16_t>(to_int(token, 0));
        remaining.clear();
        return true;
    }
    if (dash == 0 || dash + 1 >= token.size() || token.find('-', dash + 1) != std::string::npos)
        return false;
    const std::string start = token.substr(0, dash);
    const std::string end = token.substr(dash + 1);
    if (!validSharePort(start) || !validSharePort(end))
        return false;
    const int first = to_int(start, 0);
    const int last = to_int(end, 0);
    if (first > last)
        return false;
    first_port = static_cast<uint16_t>(first);
    remaining = first < last ? std::to_string(first + 1) + "-" + end : std::string();
    return true;
}

bool parseModernShareUri(std::string uri, const std::string &scheme,
                         bool require_user, const std::string &default_port,
                         bool allow_hysteria2_ports, ParsedShareUri &parsed,
                         std::string &additional_ports) {
    const std::string prefix = scheme + "://";
    if (!startsWith(uri, prefix))
        return false;
    uri.erase(0, prefix.size());

    const size_t fragment_pos = uri.find('#');
    if (fragment_pos != std::string::npos) {
        parsed.remark = decodeShareUriUserInfo(uri.substr(fragment_pos + 1));
        uri.erase(fragment_pos);
    }
    const size_t query_pos = uri.find('?');
    if (query_pos != std::string::npos) {
        parsed.query = uri.substr(query_pos + 1);
        uri.erase(query_pos);
    }
    if (!uri.empty() && uri.back() == '/')
        uri.pop_back();
    if (uri.empty() || uri.find('/') != std::string::npos)
        return false;

    const size_t at = uri.rfind('@');
    std::string authority;
    if (at == std::string::npos) {
        if (require_user)
            return false;
        authority = uri;
    } else {
        if (at == 0 || at + 1 >= uri.size())
            return false;
        parsed.user = decodeShareUriUserInfo(uri.substr(0, at));
        authority = uri.substr(at + 1);
    }

    std::string port_spec;
    if (!authority.empty() && authority.front() == '[') {
        const size_t bracket = authority.find(']');
        if (bracket == std::string::npos)
            return false;
        parsed.host = authority.substr(1, bracket - 1);
        if (bracket + 1 < authority.size()) {
            if (authority[bracket + 1] != ':' || bracket + 2 >= authority.size())
                return false;
            port_spec = authority.substr(bracket + 2);
        }
    } else {
        const size_t colon = authority.rfind(':');
        if (colon == std::string::npos) {
            parsed.host = authority;
        } else {
            if (authority.find(':') != colon || colon == 0 || colon + 1 >= authority.size())
                return false;
            parsed.host = authority.substr(0, colon);
            port_spec = authority.substr(colon + 1);
        }
    }
    if (parsed.host.empty())
        return false;
    if (port_spec.empty())
        port_spec = default_port;

    if (!allow_hysteria2_ports) {
        if (!validSharePort(port_spec))
            return false;
        parsed.port = port_spec;
        return !require_user || !parsed.user.empty();
    }

    const string_array port_tokens = split(port_spec, ",");
    if (port_tokens.empty())
        return false;
    uint16_t primary_port = 0;
    std::string first_remaining;
    if (!validHysteria2PortToken(port_tokens.front(), primary_port, first_remaining))
        return false;
    string_array remaining_ports;
    if (!first_remaining.empty())
        remaining_ports.emplace_back(std::move(first_remaining));
    for (size_t i = 1; i < port_tokens.size(); ++i) {
        uint16_t ignored_port = 0;
        std::string ignored_remaining;
        if (!validHysteria2PortToken(port_tokens[i], ignored_port, ignored_remaining))
            return false;
        remaining_ports.emplace_back(port_tokens[i]);
    }
    parsed.port = std::to_string(primary_port);
    additional_ports = join(remaining_ports, ",");
    return true;
}

bool isXrayUuid(const std::string &value) {
    static const std::string pattern =
            R"(^[\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12}$)";
    return regMatch(value, pattern);
}

std::string decodedUrlArg(const std::string &query, const std::string &key) {
    return urlDecode(getUrlArg(query, key));
}

std::vector<std::string> getUrlAlpnList(const std::string &query) {
    std::vector<std::string> result;
    for (std::string item : split(decodedUrlArg(query, "alpn"), ",")) {
        item = trim(item);
        if (!item.empty())
            result.emplace_back(std::move(item));
    }
    return result;
}

std::string decodedFirstUrlArg(const std::string &query,
                               std::initializer_list<const char *> keys) {
    for (const char *key : keys) {
        std::string value = decodedUrlArg(query, key);
        if (!value.empty())
            return value;
    }
    return {};
}

uint16_t parseUint16Option(const std::string &value, uint16_t fallback,
                           bool allow_seconds_suffix = false) {
    std::string normalized = trim(value);
    if (allow_seconds_suffix && normalized.size() > 1 && normalized.back() == 's')
        normalized.pop_back();
    if (normalized.empty() || normalized.size() > 5 ||
        !std::all_of(normalized.begin(), normalized.end(), [](unsigned char ch) {
            return std::isdigit(ch) != 0;
        }))
        return fallback;
    const int parsed = to_int(normalized, -1);
    return parsed >= 0 && parsed <= 65535 ? static_cast<uint16_t>(parsed) : fallback;
}

tribool getXrayAllowInsecure(const std::string &query) {
    std::string value = getUrlArg(query, "insecure");
    if (value.empty())
        value = getUrlArg(query, "allowInsecure");
    return tribool(value);
}

std::string normalizeXrayTransport(std::string network) {
    network = toLower(trim(network));
    if (network.empty() || network == "raw")
        return "tcp";
    if (network == "none")
        return "tcp";
    if (network == "websocket")
        return "ws";
    if (network == "mkcp")
        return "kcp";
    if (network == "gun")
        return "grpc";
    if (network == "h2")
        return "http";
    if (network == "splithttp")
        return "xhttp";
    return network;
}

void rememberXrayLinkOption(Proxy &node, const std::string &query, const std::string &key) {
    std::string value = decodedUrlArg(query, key);
    if (!value.empty())
        node.XrayLinkOptions.emplace_back(key, std::move(value));
}

void rememberXrayLinkOptions(Proxy &node, const std::string &query) {
    static const string_array keys = {
        "authority", "extra", "fm", "ech", "pcs", "vcn", "pqv", "spx"
    };
    for (const std::string &key : keys)
        rememberXrayLinkOption(node, query, key);
}

bool parseXrayTransport(const std::string &query, Proxy &node, std::string &network,
                        std::string &header_type, std::string &path, std::string &host,
                        std::string &mode) {
    network = normalizeXrayTransport(decodedUrlArg(query, "type"));
    header_type = decodedUrlArg(query, "headerType");
    switch (hash_(network)) {
        case "tcp"_hash:
            if (header_type == "http") {
                host = decodedUrlArg(query, "host");
                path = getUrlArg(query, "path");
            }
            break;
        case "kcp"_hash:
            path = getUrlArg(query, "seed");
            break;
        case "ws"_hash:
        case "http"_hash:
        case "httpupgrade"_hash:
            host = decodedUrlArg(query, "host");
            path = getUrlArg(query, "path");
            break;
        case "grpc"_hash:
            path = getUrlArg(query, "serviceName");
            mode = decodedUrlArg(query, "mode");
            break;
        case "xhttp"_hash:
            host = decodedUrlArg(query, "host");
            path = getUrlArg(query, "path");
            mode = decodedUrlArg(query, "mode");
            break;
        case "quic"_hash:
            host = decodedUrlArg(query, "quicSecurity");
            path = getUrlArg(query, "key");
            break;
        default:
            return false;
    }
    rememberXrayLinkOptions(node, query);
    return true;
}

} // namespace

void commonConstruct(Proxy &node, ProxyType type, const std::string &group, const std::string &remarks,
                     const std::string &server, const std::string &port, const tribool &udp, const tribool &tfo,
                     const tribool &scv, const tribool &tls13, const std::string &underlying_proxy) {
    node.Type = type;
    node.Group = group;
    node.Remark = remarks;
    node.Hostname = removeBrackets(server);
    node.Port = to_int(port);
    node.UDP = udp;
    node.TCPFastOpen = tfo;
    node.AllowInsecure = scv;
    node.TLS13 = tls13;
    node.UnderlyingProxy = underlying_proxy;
}

void vmessConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add,
                    const std::string &port, const std::string &type, const std::string &id, const std::string &aid,
                    const std::string &net, const std::string &cipher, const std::string &path, const std::string &host,
                    const std::string &edge, const std::string &tls, const std::string &sni,
                    const std::vector<std::string> &alpnList, tribool udp, tribool tfo,
                    tribool scv, tribool tls13, const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::VMess, group, remarks, add, port, udp, tfo, scv, tls13, underlying_proxy);
    node.UserId = id.empty() ? "00000000-0000-0000-0000-000000000000" : id;
    node.AlterId = to_int(aid);
    node.EncryptMethod = cipher;
    node.TransferProtocol = normalizeXrayTransport(net);
    node.Edge = edge;
    node.ServerName = sni;
    node.AlpnList = alpnList;
    node.TLSStr = tls;

    if (node.TransferProtocol == "quic") {
        node.QUICSecure = host;
        node.QUICSecret = path;
    } else {
        node.Host = (host.empty() && !isIPv4(add) && !isIPv6(add)) ? add.data() : trim(host);
        node.Path = path.empty() ? "/" : trim(path);
    }
    node.FakeType = type;
    node.TLSSecure = tls == "tls" || tls == "reality";
}

void ssrConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server,
                  const std::string &port, const std::string &protocol, const std::string &method,
                  const std::string &obfs, const std::string &password, const std::string &obfsparam,
                  const std::string &protoparam, tribool udp, tribool tfo, tribool scv,
                  const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::ShadowsocksR, group, remarks, server, port, udp, tfo, scv, tribool(),
                    underlying_proxy);
    node.Password = password;
    node.EncryptMethod = method;
    node.Protocol = protocol;
    node.ProtocolParam = protoparam;
    node.OBFS = obfs;
    node.OBFSParam = obfsparam;
}

void ssConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server,
                 const std::string &port, const std::string &password, const std::string &method,
                 const std::string &plugin, const std::string &pluginopts, tribool udp, tribool tfo, tribool scv,
                 tribool tls13, const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::Shadowsocks, group, remarks, server, port, udp, tfo, scv, tls13, underlying_proxy);
    node.Password = password;
    node.EncryptMethod = method;
    node.Plugin = plugin;
    node.PluginOption = pluginopts;
}

void socksConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server,
                    const std::string &port, const std::string &username, const std::string &password, tribool udp,
                    tribool tfo, tribool scv, const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::SOCKS5, group, remarks, server, port, udp, tfo, scv, tribool(), underlying_proxy);
    node.Username = username;
    node.Password = password;
}

void httpConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server,
                   const std::string &port, const std::string &username, const std::string &password, bool tls,
                   tribool tfo, tribool scv, tribool tls13, const std::string &underlying_proxy) {
    commonConstruct(node, tls ? ProxyType::HTTPS : ProxyType::HTTP, group, remarks, server, port, tribool(), tfo, scv,
                    tls13, underlying_proxy);
    node.Username = username;
    node.Password = password;
    node.TLSSecure = tls;
}

void trojanConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server,
                     const std::string &port, const std::string &password, const std::string &network,
                     const std::string &host, const std::string &path, const std::string &fp, const std::string &sni,
                     const std::vector<std::string> &alpnList,
                     bool tlssecure,
                     tribool udp, tribool tfo,
                     tribool scv, tribool tls13, const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::Trojan, group, remarks, server, port, udp, tfo, scv, tls13, underlying_proxy);
    node.Password = password;
    node.Host = host;
    node.TLSSecure = tlssecure;
    node.TLSStr = tlssecure ? "tls" : "none";
    node.TransferProtocol = network.empty() ? "tcp" : network;
    node.Path = path;
    node.Fingerprint = fp;
    node.ServerName = sni;
    node.AlpnList = alpnList;
}

void snellConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server,
                    const std::string &port, const std::string &password, const std::string &obfs,
                    const std::string &host, uint16_t version, tribool udp, tribool tfo, tribool scv,
                    const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::Snell, group, remarks, server, port, udp, tfo, scv, tribool(), underlying_proxy);
    node.Password = password;
    node.OBFS = obfs;
    node.Host = host;
    node.SnellVersion = version;
}

void wireguardConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server,
                        const std::string &port, const std::string &selfIp, const std::string &selfIpv6,
                        const std::string &privKey, const std::string &pubKey, const std::string &psk,
                        const string_array &dns, const std::string &mtu, const std::string &keepalive,
                        const std::string &testUrl, const std::string &clientId, const tribool &udp,
                        const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::WireGuard, group, remarks, server, port, udp, tribool(), tribool(), tribool(),
                    underlying_proxy);
    node.SelfIP = selfIp;
    node.SelfIPv6 = selfIpv6;
    node.PrivateKey = privKey;
    node.PublicKey = pubKey;
    node.PreSharedKey = psk;
    node.DnsServers = dns;
    node.Mtu = to_int(mtu);
    node.KeepAlive = to_int(keepalive);
    node.TestUrl = testUrl;
    node.ClientId = clientId;
}

void hysteriaConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add,
                       const std::string &port, const std::string &type, const std::string &auth,
                       const std::string &auth_str,
                       const std::string &host, const std::string &up, const std::string &down, const std::string &alpn,
                       const std::string &obfsParam, const std::string &insecure, const std::string &ports,
                       const std::string &sni, tribool udp,
                       tribool tfo, tribool scv,
                       tribool tls13, const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::Hysteria, group, remarks, add, port, udp, tfo, scv, tls13, underlying_proxy);
    node.Auth = auth;
    node.Host = (host.empty() && !isIPv4(add) && !isIPv6(add)) ? add.data() : trim(host);
    node.UpMbps = up;
    node.DownMbps = down;
    node.Alpn = alpn;
    node.OBFSParam = obfsParam;
    node.Insecure = insecure;
    node.FakeType = type;
    node.AuthStr = auth_str;
    node.Ports = ports;
    node.ServerName = sni;
}

void anyTlSConstruct(Proxy &node, const std::string &group, const std::string &remarks,
                     const std::string &port, const std::string &password,
                     const std::string &host, const std::vector<String> &AlpnList,
                     const std::string &fingerprint,
                     const std::string &sni, tribool udp,
                     tribool tfo, tribool scv,
                     tribool tls13, const std::string &underlying_proxy, uint16_t idleSessionCheckInterval,
                     uint16_t idleSessionTimeout, uint16_t minIdleSession) {
    commonConstruct(node, ProxyType::AnyTLS, group, remarks, host, port, udp, tfo, scv, tls13, underlying_proxy);
    node.Host = trim(host);
    node.Password = password;
    node.AlpnList = AlpnList;
    node.SNI = sni;
    node.ServerName = sni;
    node.Fingerprint = fingerprint;
    node.IdleSessionCheckInterval = idleSessionCheckInterval;
    node.IdleSessionTimeout = idleSessionTimeout;
    node.MinIdleSession = minIdleSession;
}

void mieruConstruct(Proxy &node, const std::string &group, const std::string &remarks,
                    const std::string &port, const std::string &password,
                    const std::string &host, const std::string &ports,
                    const std::string &username, const std::string &multiplexing,
                    const std::string &transfer_protocol, tribool udp,
                    tribool tfo, tribool scv,
                    tribool tls13, const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::Mieru, group, remarks, host, port, udp, tfo, scv, tls13, underlying_proxy);
    node.Host = trim(host);
    node.Password = password;
    node.Ports = ports;
    node.TransferProtocol = transfer_protocol.empty() ? "TCP" : trim(transfer_protocol);
    node.Username = username;
    node.Multiplexing = multiplexing.empty() ? "MULTIPLEXING_LOW" : trim(multiplexing);
}

void vlessConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add,
                    const std::string &port, const std::string &type, const std::string &id, const std::string &aid,
                    const std::string &net, const std::string &cipher, const std::string &flow, const std::string &mode,
                    const std::string &path, const std::string &host, const std::string &edge, const std::string &tls,
                    const std::string &pbk, const std::string &sid, const std::string &fp, const std::string &sni,
                    const std::vector<std::string> &alpnList, const std::string &packet_encoding,
                    tribool udp, tribool tfo,
                    tribool scv, tribool tls13, const std::string &underlying_proxy, tribool v2ray_http_upgrade,
                    const std::string &encryption) {
    commonConstruct(node, ProxyType::VLESS, group, remarks, add, port, udp, tfo, scv, tls13, underlying_proxy);
    node.UserId = id.empty() ? "00000000-0000-0000-0000-000000000000" : id;
    node.AlterId = to_int(aid);
    node.EncryptMethod = cipher;
    node.TransferProtocol = normalizeXrayTransport(net);
    node.Edge = edge;
    node.Flow = flow;
    node.Encryption = encryption.empty() ? "none" : encryption;
    node.FakeType = type;
    node.TLSSecure = tls == "tls" || tls == "xtls" || tls == "reality";
    node.PublicKey = pbk;
    node.ShortId = sid;
    node.Fingerprint = fp;
    node.ServerName = sni;
    node.AlpnList = alpnList;
    node.PacketEncoding = packet_encoding;
    node.TLSStr = tls;
    if (node.TransferProtocol == "xhttp")
        node.GRPCMode = mode;
    switch (hash_(node.TransferProtocol)) {
        case "grpc"_hash:
            node.Host = host;
            node.GRPCMode = mode.empty() ? "gun" : mode;
            node.GRPCServiceName = path.empty() ? "/" : urlDecode(trim(path));
            break;
        case "quic"_hash:
            node.Host = host;
            node.QUICSecret = path.empty() ? "/" : trim(path);
            break;
        default:
            node.Host = (host.empty() && !isIPv4(add) && !isIPv6(add)) ? add.data() : trim(host);
            node.Path = path.empty() ? "/" : urlDecode(trim(path));
            node.V2rayHttpUpgrade = v2ray_http_upgrade;
            break;
    }
}


void hysteria2Construct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add,
                        const std::string &port, const std::string &password, const std::string &host,
                        const std::string &up, const std::string &down, const std::string &alpn,
                        const std::string &obfsParam, const std::string &obfsPassword, const std::string &sni,
                        const std::string &publicKey, const std::string &ports,
                        tribool udp, tribool tfo,
                        tribool scv, const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::Hysteria2, group, remarks, add, port, udp, tfo, scv, tribool(), underlying_proxy);
    node.Password = password;
    node.Host = (host.empty() && !isIPv4(add) && !isIPv6(add)) ? add.data() : trim(host);
    node.UpMbps = up;
    node.DownMbps = down;
    node.Alpn = alpn;
    node.OBFSParam = obfsParam;
    node.OBFSPassword = obfsPassword;
    node.ServerName = sni;
    node.PublicKey = publicKey;
    node.Ports = ports;
}

void tuicConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add,
                   const std::string &port, const std::string &password, const std::string &congestion_control,
                   const std::string &alpn,
                   const std::string &sni, const std::string &uuid, const std::string &udpRelayMode,
                   const std::string &token,
                   tribool udp, tribool tfo,
                   tribool scv, tribool reduceRtt, tribool disableSni, uint16_t request_timeout,
                   const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::TUIC, group, remarks, add, port, udp, tfo, scv, tribool(), underlying_proxy);
    node.Password = password;
    node.Alpn = alpn;
    node.ServerName = sni;
    node.CongestionControl = congestion_control;
    node.ReduceRtt = reduceRtt;
    node.DisableSni = disableSni;
    node.UserId = uuid;
    node.UdpRelayMode = udpRelayMode;
    node.token = token;
    node.RequestTimeout = request_timeout;
}


void explodeVmess(std::string vmess, Proxy &node) {
    std::string version, ps, add, port, type, id, aid, net, path, host, tls, sni, cipher, fp, alpn;
    Document jsondata;
    std::vector<std::string> vArray;

    if (regMatch(vmess, "vmess://([A-Za-z0-9-_]+)\\?(.*)")) //shadowrocket style link
    {
        explodeShadowrocket(vmess, node);
        return;
    } else if (regMatch(vmess, "vmess://(.*?)@(.*)")) {
        explodeStdVMess(vmess, node);
        return;
    } else if (regMatch(vmess, "vmess1://(.*?)\\?(.*)")) //kitsunebi style link
    {
        explodeKitsunebi(vmess, node);
        return;
    }
    vmess = urlSafeBase64Decode(regReplace(vmess, "(vmess|vmess1)://", ""));
    if (regMatch(vmess, "(.*?) = (.*)")) {
        explodeQuan(vmess, node);
        return;
    }
    jsondata.Parse(vmess.data());
    if (jsondata.HasParseError() || !jsondata.IsObject())
        return;

    version = "1"; //link without version will treat as version 1
    GetMember(jsondata, "v", version); //try to get version

    GetMember(jsondata, "ps", ps);
    GetMember(jsondata, "add", add);
    port = GetMember(jsondata, "port");
    if (port == "0")
        return;
    GetMember(jsondata, "type", type);
    GetMember(jsondata, "id", id);
    GetMember(jsondata, "aid", aid);
    GetMember(jsondata, "net", net);
    GetMember(jsondata, "tls", tls);
    GetMember(jsondata, "scy", cipher);
    if (cipher.empty())
        GetMember(jsondata, "encryption", cipher);
    if (cipher.empty())
        cipher = "auto";

    GetMember(jsondata, "host", host);
    GetMember(jsondata, "sni", sni);
    GetMember(jsondata, "fp", fp);
    GetMember(jsondata, "alpn", alpn);
    switch (to_int(version)) {
        case 1:
            if (!host.empty()) {
                vArray = split(host, ";");
                if (vArray.size() == 2) {
                    host = vArray[0];
                    path = vArray[1];
                }
            }
            break;
        case 2:
            path = GetMember(jsondata, "path");
            break;
    }

    add = trim(add);
    net = normalizeXrayTransport(net);

    std::vector<std::string> alpn_list;
    for (std::string item : split(alpn, ",")) {
        item = trim(item);
        if (!item.empty())
            alpn_list.emplace_back(std::move(item));
    }
    vmessConstruct(node, V2RAY_DEFAULT_GROUP, ps, add, port, type, id, aid, net, cipher, path, host, "", tls, sni,
                   alpn_list);
    node.Fingerprint = fp;
    if (net == "grpc" || net == "xhttp")
        node.GRPCMode = type;
    for (const char *key : {"authority", "extra", "fm", "ech", "pcs", "vcn"}) {
        std::string value = GetMember(jsondata, key);
        if (!value.empty())
            node.XrayLinkOptions.emplace_back(key, std::move(value));
    }
}

void explodeVmessConf(std::string content, std::vector<Proxy> &nodes) {
    Document json;
    rapidjson::Value nodejson, settings;
    std::string group, ps, add, port, type, id, aid, net, path, host, edge, tls, cipher, subid, sni;
    tribool udp, tfo, scv;
    int configType;
    uint32_t index = nodes.size();
    std::map<std::string, std::string> subdata;
    std::map<std::string, std::string>::iterator iter;
    std::string streamset = "streamSettings", tcpset = "tcpSettings", wsset = "wsSettings";
    regGetMatch(content, "((?i)streamsettings)", 2, 0, &streamset);
    regGetMatch(content, "((?i)tcpsettings)", 2, 0, &tcpset);
    regGetMatch(content, "((?i)wssettings)", 2, 0, &wsset);

    json.Parse(content.data());
    if (json.HasParseError() || !json.IsObject())
        return;
    try {
        if (json.HasMember("outbounds")) //single config
        {
            if (json["outbounds"].Size() > 0 && json["outbounds"][0].HasMember("settings") &&
                json["outbounds"][0]["settings"].HasMember("vnext") &&
                json["outbounds"][0]["settings"]["vnext"].Size() > 0) {
                Proxy node;
                nodejson = json["outbounds"][0];
                add = GetMember(nodejson["settings"]["vnext"][0], "address");
                port = GetMember(nodejson["settings"]["vnext"][0], "port");
                if (port == "0")
                    return;
                if (nodejson["settings"]["vnext"][0]["users"].Size()) {
                    id = GetMember(nodejson["settings"]["vnext"][0]["users"][0], "id");
                    aid = GetMember(nodejson["settings"]["vnext"][0]["users"][0], "alterId");
                    cipher = GetMember(nodejson["settings"]["vnext"][0]["users"][0], "security");
                }
                if (nodejson.HasMember(streamset.data())) {
                    net = GetMember(nodejson[streamset.data()], "network");
                    tls = GetMember(nodejson[streamset.data()], "security");
                    if (net == "ws") {
                        if (nodejson[streamset.data()].HasMember(wsset.data()))
                            settings = nodejson[streamset.data()][wsset.data()];
                        else
                            settings.RemoveAllMembers();
                        path = GetMember(settings, "path");
                        if (settings.HasMember("headers")) {
                            host = GetMember(settings["headers"], "Host");
                            edge = GetMember(settings["headers"], "Edge");
                        }
                    }
                    if (nodejson[streamset.data()].HasMember(tcpset.data()))
                        settings = nodejson[streamset.data()][tcpset.data()];
                    else
                        settings.RemoveAllMembers();
                    if (settings.IsObject() && settings.HasMember("header")) {
                        type = GetMember(settings["header"], "type");
                        if (type == "http") {
                            if (settings["header"].HasMember("request")) {
                                if (settings["header"]["request"].HasMember("path") &&
                                    settings["header"]["request"]["path"].Size())
                                    settings["header"]["request"]["path"][0] >> path;
                                if (settings["header"]["request"].HasMember("headers")) {
                                    host = GetMember(settings["header"]["request"]["headers"], "Host");
                                    edge = GetMember(settings["header"]["request"]["headers"], "Edge");
                                }
                            }
                        }
                    }
                }
                vmessConstruct(node, V2RAY_DEFAULT_GROUP, add + ":" + port, add, port, type, id, aid, net, cipher, path,
                               host, edge, tls, "", std::vector<std::string>{}, udp, tfo, scv);
                nodes.emplace_back(std::move(node));
            }
            return;
        }
    } catch (std::exception &e) {
        //writeLog(LOG_LEVEL_WARNING, "VMessConf parser throws an error. Leaving...");
        //return;
        //ignore
        throw;
    }
    //read all subscribe remark as group name
    for (uint32_t i = 0; i < json["subItem"].Size(); i++)
        subdata.insert(std::pair<std::string, std::string>(json["subItem"][i]["id"].GetString(),
                                                           json["subItem"][i]["remarks"].GetString()));

    for (uint32_t i = 0; i < json["vmess"].Size(); i++) {
        Proxy node;
        if (json["vmess"][i]["address"].IsNull() || json["vmess"][i]["port"].IsNull() ||
            json["vmess"][i]["id"].IsNull())
            continue;

        //common info
        json["vmess"][i]["remarks"] >> ps;
        json["vmess"][i]["address"] >> add;
        port = GetMember(json["vmess"][i], "port");
        if (port == "0")
            continue;
        json["vmess"][i]["subid"] >> subid;

        if (!subid.empty()) {
            iter = subdata.find(subid);
            if (iter != subdata.end())
                group = iter->second;
        }
        if (ps.empty())
            ps = add + ":" + port;

        scv = GetMember(json["vmess"][i], "allowInsecure");
        json["vmess"][i]["configType"] >> configType;
        switch (configType) {
            case 1: //vmess config
                json["vmess"][i]["headerType"] >> type;
                json["vmess"][i]["id"] >> id;
                json["vmess"][i]["alterId"] >> aid;
                json["vmess"][i]["network"] >> net;
                json["vmess"][i]["path"] >> path;
                json["vmess"][i]["requestHost"] >> host;
                json["vmess"][i]["streamSecurity"] >> tls;
                json["vmess"][i]["security"] >> cipher;
                json["vmess"][i]["sni"] >> sni;
                vmessConstruct(node, V2RAY_DEFAULT_GROUP, ps, add, port, type, id, aid, net, cipher, path, host, "",
                               tls, sni, std::vector<std::string>{}, udp, tfo, scv);
                break;
            case 3: //ss config
                json["vmess"][i]["id"] >> id;
                json["vmess"][i]["security"] >> cipher;
                ssConstruct(node, SS_DEFAULT_GROUP, ps, add, port, id, cipher, "", "", udp, tfo, scv);
                break;
            case 4: //socks config
                socksConstruct(node, SOCKS_DEFAULT_GROUP, ps, add, port, "", "", udp, tfo, scv);
                break;
            default:
                continue;
        }
        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeSS(std::string ss, Proxy &node) {
    if (!startsWith(ss, "ss://"))
        return;

    std::string ps, password, method, server, port, plugin, pluginopts,
            addition, group = SS_DEFAULT_GROUP;
    ss.erase(0, 5);

    const size_t fragment_pos = ss.find('#');
    if (fragment_pos != std::string::npos) {
        ps = decodeShareUriUserInfo(ss.substr(fragment_pos + 1));
        ss.erase(fragment_pos);
    }
    const size_t query_pos = ss.find('?');
    if (query_pos != std::string::npos) {
        addition = ss.substr(query_pos + 1);
        ss.erase(query_pos);
        std::string plugin_value = urlDecode(getUrlArg(addition, "plugin"));
        const size_t plugin_separator = plugin_value.find(';');
        plugin = plugin_value.substr(0, plugin_separator);
        if (plugin_separator != std::string::npos)
            pluginopts = plugin_value.substr(plugin_separator + 1);

        std::string encoded_group = getUrlArg(addition, "group");
        std::string decoded_group;
        if (!encoded_group.empty() && decodeStrictBase64(encoded_group, decoded_group))
            group = std::move(decoded_group);
    }
    if (!ss.empty() && ss.back() == '/')
        ss.pop_back();

    const size_t at = ss.rfind('@');
    if (at != std::string::npos) {
        if (at == 0 || at + 1 >= ss.size() ||
            !parseUserPassword(ss.substr(0, at), true, method, password) ||
            !parseShareAuthority(ss.substr(at + 1), server, port))
            return;
    } else {
        std::string decoded;
        if (!decodeStrictBase64(ss, decoded))
            return;
        const size_t decoded_at = decoded.rfind('@');
        if (decoded_at == std::string::npos || decoded_at == 0 ||
            decoded_at + 1 >= decoded.size())
            return;
        const size_t colon = decoded.find(':');
        if (colon == std::string::npos || colon >= decoded_at ||
            !parseShareAuthority(decoded.substr(decoded_at + 1), server, port))
            return;
        method = decoded.substr(0, colon);
        password = decoded.substr(colon + 1, decoded_at - colon - 1);
    }
    if (method.empty() || password.empty() ||
        method.find_first_of("\r\n") != std::string::npos ||
        password.find_first_of("\r\n") != std::string::npos ||
        group.find_first_of("\r\n") != std::string::npos ||
        ps.find_first_of("\r\n") != std::string::npos ||
        plugin.find_first_of("\r\n") != std::string::npos ||
        pluginopts.find_first_of("\r\n") != std::string::npos)
        return;
    if (ps.empty())
        ps = server + ":" + port;

    ssConstruct(node, group, ps, server, port, password, method, plugin, pluginopts);
}

void explodeSSD(std::string link, std::vector<Proxy> &nodes) {
    Document jsondata;
    uint32_t index = nodes.size(), listType = 0, listCount = 0;
    std::string group, port, method, password, server, remarks;
    std::string plugin, pluginopts;
    std::map<uint32_t, std::string> node_map;

    link = urlSafeBase64Decode(link.substr(6));
    jsondata.Parse(link.c_str());
    if (jsondata.HasParseError() || !jsondata.IsObject())
        return;
    if (!jsondata.HasMember("servers"))
        return;
    GetMember(jsondata, "airport", group);

    if (jsondata["servers"].IsArray()) {
        listType = 0;
        listCount = jsondata["servers"].Size();
    } else if (jsondata["servers"].IsObject()) {
        listType = 1;
        listCount = jsondata["servers"].MemberCount();
        uint32_t node_index = 0;
        for (rapidjson::Value::MemberIterator iter = jsondata["servers"].MemberBegin();
             iter != jsondata["servers"].MemberEnd(); iter++) {
            node_map.emplace(node_index, iter->name.GetString());
            node_index++;
        }
    } else
        return;

    rapidjson::Value singlenode;
    for (uint32_t i = 0; i < listCount; i++) {
        //get default info
        port = GetMember(jsondata, "port");
        method = GetMember(jsondata, "encryption");
        password = GetMember(jsondata, "password");
        plugin = GetMember(jsondata, "plugin");
        pluginopts = GetMember(jsondata, "plugin_options");

        //get server-specific info
        switch (listType) {
            case 0:
                singlenode = jsondata["servers"][i];
                break;
            case 1:
                singlenode = jsondata["servers"].FindMember(node_map[i].data())->value;
                break;
            default:
                continue;
        }
        singlenode["server"] >> server;
        GetMember(singlenode, "remarks", remarks);
        GetMember(singlenode, "port", port);
        GetMember(singlenode, "encryption", method);
        GetMember(singlenode, "password", password);
        GetMember(singlenode, "plugin", plugin);
        GetMember(singlenode, "plugin_options", pluginopts);

        if (port == "0")
            continue;

        Proxy node;
        ssConstruct(node, group, remarks, server, port, password, method, plugin, pluginopts);
        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeSSAndroid(std::string ss, std::vector<Proxy> &nodes) {
    std::string ps, password, method, server, port, group = SS_DEFAULT_GROUP;
    std::string plugin, pluginopts;

    Document json;
    auto index = nodes.size();
    //first add some extra data before parsing
    ss = "{\"nodes\":" + ss + "}";
    json.Parse(ss.data());
    if (json.HasParseError() || !json.IsObject() || !json.HasMember("nodes") ||
        !json["nodes"].IsArray())
        return;

    for (uint32_t i = 0; i < json["nodes"].Size(); i++) {
        Proxy node;
        server = GetMember(json["nodes"][i], "server");
        if (server.empty())
            continue;
        ps = GetMember(json["nodes"][i], "remarks");
        port = GetMember(json["nodes"][i], "server_port");
        if (!validSharePort(port))
            continue;
        if (ps.empty())
            ps = server + ":" + port;
        password = GetMember(json["nodes"][i], "password");
        method = GetMember(json["nodes"][i], "method");
        plugin = GetMember(json["nodes"][i], "plugin");
        pluginopts = GetMember(json["nodes"][i], "plugin_opts");
        if (password.empty() || method.empty() ||
            server.find_first_of("\r\n") != std::string::npos ||
            ps.find_first_of("\r\n") != std::string::npos ||
            password.find_first_of("\r\n") != std::string::npos ||
            method.find_first_of("\r\n") != std::string::npos ||
            plugin.find_first_of("\r\n") != std::string::npos ||
            pluginopts.find_first_of("\r\n") != std::string::npos)
            continue;

        ssConstruct(node, group, ps, server, port, password, method, plugin, pluginopts);
        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeSSConf(std::string content, std::vector<Proxy> &nodes) {
    Document json;
    std::string ps, password, method, server, port, plugin, pluginopts, group = SS_DEFAULT_GROUP;
    auto index = nodes.size();

    json.Parse(content.data());
    if (json.HasParseError())
        return;

    const rapidjson::Value *server_list = nullptr;
    if (json.IsArray()) {
        server_list = &json;
    } else if (json.IsObject()) {
        if (json.HasMember("servers") && json["servers"].IsArray())
            server_list = &json["servers"];
        else if (json.HasMember("configs") && json["configs"].IsArray())
            server_list = &json["configs"];
        GetMember(json, "remarks", group);
    }
    if (server_list == nullptr || group.find_first_of("\r\n") != std::string::npos)
        return;

    for (uint32_t i = 0; i < server_list->Size(); i++) {
        const rapidjson::Value &item = (*server_list)[i];
        if (!item.IsObject())
            continue;
        Proxy node;
        server = GetMember(item, "server");
        port = GetMember(item, "server_port");
        password = GetMember(item, "password");
        method = GetMember(item, "method");
        ps = GetMember(item, "remarks");
        if (server.empty() || !validSharePort(port) || password.empty() ||
            method.empty() ||
            server.find_first_of("\r\n") != std::string::npos ||
            ps.find_first_of("\r\n") != std::string::npos ||
            password.find_first_of("\r\n") != std::string::npos ||
            method.find_first_of("\r\n") != std::string::npos)
            continue;
        if (ps.empty())
            ps = server + ":" + port;
        plugin = GetMember(item, "plugin");
        pluginopts = GetMember(item, "plugin_opts");
        if (plugin.find_first_of("\r\n") != std::string::npos ||
            pluginopts.find_first_of("\r\n") != std::string::npos)
            continue;

        node.Id = index;
        ssConstruct(node, group, ps, server, port, password, method, plugin, pluginopts);
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeSSR(std::string ssr, Proxy &node) {
    std::string strobfs;
    std::string remarks, group, server, port, method, password, protocol, protoparam, obfs, obfsparam;
    if (!startsWith(ssr, "ssr://"))
        return;
    if (!decodeStrictBase64(replaceAllDistinct(ssr.substr(6), "\r", ""), ssr))
        return;
    if (strFind(ssr, "/?")) {
        strobfs = ssr.substr(ssr.find("/?") + 2);
        ssr = ssr.substr(0, ssr.find("/?"));
        decodeStrictBase64(getUrlArg(strobfs, "group"), group);
        decodeStrictBase64(getUrlArg(strobfs, "remarks"), remarks);
        decodeStrictBase64(getUrlArg(strobfs, "obfsparam"), obfsparam);
        decodeStrictBase64(getUrlArg(strobfs, "protoparam"), protoparam);
        obfsparam = regReplace(obfsparam, "\\s", "");
        protoparam = regReplace(protoparam, "\\s", "");
    }

    size_t fields_start = 0;
    if (!ssr.empty() && ssr.front() == '[') {
        const size_t bracket = ssr.find(']');
        if (bracket == std::string::npos || bracket + 1 >= ssr.size() || ssr[bracket + 1] != ':')
            return;
        server = ssr.substr(1, bracket - 1);
        fields_start = bracket + 2;
    } else {
        const size_t colon = ssr.find(':');
        if (colon == std::string::npos)
            return;
        server = ssr.substr(0, colon);
        fields_start = colon + 1;
    }
    const string_array fields = split(ssr.substr(fields_start), ":");
    if (server.empty() || fields.size() != 5)
        return;
    port = fields[0];
    protocol = fields[1];
    method = fields[2];
    obfs = fields[3];
    if (!validSharePort(port) || protocol.empty() || method.empty() || obfs.empty() ||
        !decodeStrictBase64(fields[4], password))
        return;
    if (server.find_first_of("\r\n") != std::string::npos ||
        protocol.find_first_of("\r\n") != std::string::npos ||
        method.find_first_of("\r\n") != std::string::npos ||
        obfs.find_first_of("\r\n") != std::string::npos ||
        password.find_first_of("\r\n") != std::string::npos ||
        group.find_first_of("\r\n") != std::string::npos ||
        remarks.find_first_of("\r\n") != std::string::npos)
        return;

    if (group.empty())
        group = SSR_DEFAULT_GROUP;
    if (remarks.empty())
        remarks = server + ":" + port;

    if (find(ss_ciphers.begin(), ss_ciphers.end(), method) != ss_ciphers.end() && (obfs.empty() || obfs == "plain") &&
        (protocol.empty() || protocol == "origin")) {
        ssConstruct(node, group, remarks, server, port, password, method, "", "");
    } else {
        ssrConstruct(node, group, remarks, server, port, protocol, method, obfs, password, obfsparam, protoparam);
    }
}

void explodeSSRConf(std::string content, std::vector<Proxy> &nodes) {
    Document json;
    std::string remarks, group, server, port, method, password, protocol, protoparam, obfs, obfsparam, plugin,
            pluginopts;
    auto index = nodes.size();

    json.Parse(content.data());
    if (json.HasParseError() || !json.IsObject())
        return;

    if (json.HasMember("local_port") && json.HasMember("local_address")) //single libev config
    {
        Proxy node;
        server = GetMember(json, "server");
        port = GetMember(json, "server_port");
        password = GetMember(json, "password");
        if (server.empty() || !validSharePort(port) || password.empty())
            return;
        remarks = server + ":" + port;
        method = GetMember(json, "method");
        obfs = GetMember(json, "obfs");
        protocol = GetMember(json, "protocol");
        if (method.empty() || server.find_first_of("\r\n") != std::string::npos ||
            method.find_first_of("\r\n") != std::string::npos ||
            password.find_first_of("\r\n") != std::string::npos ||
            obfs.find_first_of("\r\n") != std::string::npos ||
            protocol.find_first_of("\r\n") != std::string::npos)
            return;
        if (find(ss_ciphers.begin(), ss_ciphers.end(), method) != ss_ciphers.end() &&
            (obfs.empty() || obfs == "plain") && (protocol.empty() || protocol == "origin")) {
            plugin = GetMember(json, "plugin");
            pluginopts = GetMember(json, "plugin_opts");
            if (plugin.find_first_of("\r\n") != std::string::npos ||
                pluginopts.find_first_of("\r\n") != std::string::npos)
                return;
            ssConstruct(node, SS_DEFAULT_GROUP, remarks, server, port, password, method, plugin, pluginopts);
        } else {
            if (protocol.empty() || obfs.empty())
                return;
            protoparam = GetMember(json, "protocol_param");
            obfsparam = GetMember(json, "obfs_param");
            if (protoparam.find_first_of("\r\n") != std::string::npos ||
                obfsparam.find_first_of("\r\n") != std::string::npos)
                return;
            ssrConstruct(node, SSR_DEFAULT_GROUP, remarks, server, port, protocol, method, obfs, password, obfsparam,
                         protoparam);
        }
        nodes.emplace_back(std::move(node));
        return;
    }

    if (!json.HasMember("configs") || !json["configs"].IsArray())
        return;
    for (uint32_t i = 0; i < json["configs"].Size(); i++) {
        if (!json["configs"][i].IsObject())
            continue;
        Proxy node;
        group = GetMember(json["configs"][i], "group");
        if (group.empty())
            group = SSR_DEFAULT_GROUP;
        remarks = GetMember(json["configs"][i], "remarks");
        server = GetMember(json["configs"][i], "server");
        port = GetMember(json["configs"][i], "server_port");
        if (server.empty() || !validSharePort(port))
            continue;
        if (remarks.empty())
            remarks = server + ":" + port;

        password = GetMember(json["configs"][i], "password");
        method = GetMember(json["configs"][i], "method");

        protocol = GetMember(json["configs"][i], "protocol");
        protoparam = GetMember(json["configs"][i], "protocolparam");
        obfs = GetMember(json["configs"][i], "obfs");
        obfsparam = GetMember(json["configs"][i], "obfsparam");

        if (password.empty() || method.empty() ||
            server.find_first_of("\r\n") != std::string::npos ||
            group.find_first_of("\r\n") != std::string::npos ||
            remarks.find_first_of("\r\n") != std::string::npos ||
            password.find_first_of("\r\n") != std::string::npos ||
            method.find_first_of("\r\n") != std::string::npos ||
            protocol.find_first_of("\r\n") != std::string::npos ||
            protoparam.find_first_of("\r\n") != std::string::npos ||
            obfs.find_first_of("\r\n") != std::string::npos ||
            obfsparam.find_first_of("\r\n") != std::string::npos)
            continue;

        ssrConstruct(node, group, remarks, server, port, protocol, method, obfs, password, obfsparam, protoparam);
        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeSocks(std::string link, Proxy &node) {
    std::string group, remarks, server, port, username, password;
    if (startsWith(link, "socks://"))
    {
        std::string encoded = link.substr(8);
        const size_t fragment_pos = encoded.find('#');
        if (fragment_pos != std::string::npos) {
            remarks = decodeShareUriUserInfo(encoded.substr(fragment_pos + 1));
            encoded.erase(fragment_pos);
        }
        if (!encoded.empty() && encoded.back() == '/')
            encoded.pop_back();

        const size_t at = encoded.rfind('@');
        if (at != std::string::npos) {
            if (at == 0 || at + 1 >= encoded.size() ||
                !parseUserPassword(encoded.substr(0, at), true, username, password) ||
                !parseShareAuthority(encoded.substr(at + 1), server, port))
                return;
        } else {
            if (parseShareAuthority(encoded, server, port)) {
                username.clear();
                password.clear();
            } else {
                std::string decoded;
                if (!decodeStrictBase64(encoded, decoded))
                    return;
                const size_t decoded_at = decoded.rfind('@');
                if (decoded_at == std::string::npos) {
                    if (!parseShareAuthority(decoded, server, port))
                        return;
                } else if (decoded_at == 0 || decoded_at + 1 >= decoded.size() ||
                           !parseUserPassword(decoded.substr(0, decoded_at), true,
                                              username, password) ||
                           !parseShareAuthority(decoded.substr(decoded_at + 1),
                                                server, port)) {
                    return;
                }
            }
        }
    } else if (strFind(link, "https://t.me/socks") || strFind(link, "tg://socks")) //telegram style socks link
    {
        server = getUrlArg(link, "server");
        port = getUrlArg(link, "port");
        username = urlDecode(getUrlArg(link, "user"));
        password = urlDecode(getUrlArg(link, "pass"));
        remarks = urlDecode(getUrlArg(link, "remarks"));
        group = urlDecode(getUrlArg(link, "group"));
    }
    if (server.empty() || !validSharePort(port) ||
        server.find_first_of("\r\n") != std::string::npos ||
        username.find_first_of("\r\n") != std::string::npos ||
        password.find_first_of("\r\n") != std::string::npos ||
        remarks.find_first_of("\r\n") != std::string::npos ||
        group.find_first_of("\r\n") != std::string::npos)
        return;
    if (group.empty())
        group = SOCKS_DEFAULT_GROUP;
    if (remarks.empty())
        remarks = server + ":" + port;
    socksConstruct(node, group, remarks, server, port, username, password);
}

void explodeHTTP(const std::string &link, Proxy &node) {
    std::string group, remarks, server, port, username, password;
    server = getUrlArg(link, "server");
    port = getUrlArg(link, "port");
    username = urlDecode(getUrlArg(link, "user"));
    password = urlDecode(getUrlArg(link, "pass"));
    remarks = urlDecode(getUrlArg(link, "remarks"));
    group = urlDecode(getUrlArg(link, "group"));

    if (server.empty() || !validSharePort(port) ||
        server.find_first_of("\r\n") != std::string::npos ||
        username.find_first_of("\r\n") != std::string::npos ||
        password.find_first_of("\r\n") != std::string::npos ||
        remarks.find_first_of("\r\n") != std::string::npos ||
        group.find_first_of("\r\n") != std::string::npos)
        return;
    if (group.empty())
        group = HTTP_DEFAULT_GROUP;
    if (remarks.empty())
        remarks = server + ":" + port;
    httpConstruct(node, group, remarks, server, port, username, password, strFind(link, "/https"));
}

void explodeHTTPSub(std::string link, Proxy &node) {
    std::string group, remarks, server, port, username, password;
    std::string addition;
    bool tls = strFind(link, "https://");
    auto pos = link.find('?');
    if (pos != std::string::npos) {
        addition = link.substr(pos + 1);
        link.erase(pos);
        remarks = urlDecode(getUrlArg(addition, "remarks"));
        group = urlDecode(getUrlArg(addition, "group"));
    }
    link.erase(0, link.find("://") + 3);
    std::string decoded_link;
    if (!decodeStrictBase64(link, decoded_link))
        return;
    link = std::move(decoded_link);
    const size_t at = link.rfind('@');
    std::string authority = link;
    if (at != std::string::npos) {
        if (at == 0 || at + 1 >= link.size())
            return;
        const std::string userinfo = link.substr(0, at);
        const size_t colon = userinfo.find(':');
        if (colon == std::string::npos)
            return;
        username = userinfo.substr(0, colon);
        password = userinfo.substr(colon + 1);
        authority = link.substr(at + 1);
    }
    if (!parseShareAuthority(authority, server, port) ||
        username.find_first_of("\r\n") != std::string::npos ||
        password.find_first_of("\r\n") != std::string::npos ||
        remarks.find_first_of("\r\n") != std::string::npos ||
        group.find_first_of("\r\n") != std::string::npos)
        return;

    if (group.empty())
        group = HTTP_DEFAULT_GROUP;
    if (remarks.empty())
        remarks = server + ":" + port;
    httpConstruct(node, group, remarks, server, port, username, password, tls);
}

bool isLegacyHttpProxyUri(const std::string &link) {
    if (!startsWith(link, "http://") && !startsWith(link, "https://"))
        return false;

    const size_t scheme_end = link.find("://") + 3;
    const size_t query_start = link.find('?', scheme_end);
    const size_t fragment_start = link.find('#', scheme_end);
    if (fragment_start != std::string::npos)
        return false;

    const size_t authority_end = query_start == std::string::npos ? link.size() : query_start;
    if (authority_end == scheme_end || link.find('/', scheme_end) < authority_end)
        return false;

    if (query_start != std::string::npos) {
        for (const std::string &item : split(link.substr(query_start + 1), "&")) {
            if (item.empty())
                continue;
            const size_t equals = item.find('=');
            const std::string key = item.substr(0, equals);
            if (key != "remarks" && key != "group")
                return false;
        }
    }

    Proxy candidate;
    explodeHTTPSub(link, candidate);
    return (candidate.Type == ProxyType::HTTP || candidate.Type == ProxyType::HTTPS) &&
           !candidate.Hostname.empty() && candidate.Port != 0;
}

void explodeTrojan(std::string trojan, Proxy &node) {
    ParsedShareUri parsed;
    const std::string scheme = startsWith(trojan, "trojan-go://") ? "trojan-go" : "trojan";
    if (!parseShareUri(trojan, scheme, parsed))
        return;

    std::string group, host, path, network, fp, sni, mode, header_type;
    tribool tfo, scv;
    if (!parseXrayTransport(parsed.query, node, network, header_type, path, host, mode))
        return;

    sni = decodedUrlArg(parsed.query, "sni");
    if (host.empty())
        host = sni;
    if (host.empty())
        host = decodedUrlArg(parsed.query, "peer");
    tfo = getUrlArg(parsed.query, "tfo");
    fp = decodedUrlArg(parsed.query, "fp");
    scv = getXrayAllowInsecure(parsed.query);
    group = decodedUrlArg(parsed.query, "group");

    if (getUrlArg(parsed.query, "ws") == "1") {
        path = getUrlArg(parsed.query, "wspath");
        network = "ws";
    }
    path = urlDecode(path);

    if (parsed.remark.empty())
        parsed.remark = parsed.host + ":" + parsed.port;
    if (group.empty())
        group = TROJAN_DEFAULT_GROUP;
    trojanConstruct(node, group, parsed.remark, parsed.host, parsed.port, parsed.user, network, host, path, fp, sni,
                    getUrlAlpnList(parsed.query), true, tribool(),
                    tfo, scv);
    node.FakeType = header_type;
    node.GRPCMode = mode;
    node.PublicKey = decodedUrlArg(parsed.query, "pbk");
    node.ShortId = decodedUrlArg(parsed.query, "sid");
    node.TLSStr = decodedUrlArg(parsed.query, "security");
    if (node.TLSStr.empty())
        node.TLSStr = "tls";
}

void explodeVless(std::string vless, Proxy &node) {
    if (regMatch(vless, "vless://(.*?)@(.*)")) {
        explodeStdVless(vless, node);
        return;
    }
}

void explodeMierus(std::string mierus, Proxy &node) {
    if (strFind(mierus, "mierus://")) {
        if (regMatch(mierus, "mierus://(.*?)@(.*)")) {
            explodeStdMieru(mierus.substr(9), node);
        } else {
            mierus = urlSafeBase64Decode(mierus.substr(9));
            explodeStdMieru("mierus://" + mierus, node);
        }
    } else if (strFind(mierus, "mieru://")) {
        if (regMatch(mierus, "mierus://(.*?)@(.*)")) {
            explodeStdMieru(mierus.substr(8), node);
        } else {
            mierus = urlSafeBase64Decode(mierus.substr(8));
            explodeStdMieru("mierus://" + mierus, node);
        }
    }
}

void explodeHysteria(std::string hysteria, Proxy &node) {
    writeLog(LOG_LEVEL_DEBUG, "正在解析 Hysteria 节点。");
    hysteria = regReplace(hysteria, "(hysteria|hy)://", "hysteria://");
    if (regMatch(hysteria, "hysteria://(.*?)[:](.*)")) {
        explodeStdHysteria(hysteria, node);
        return;
    }
}

void explodeHysteria2(std::string hysteria2, Proxy &node) {
    hysteria2 = regReplace(hysteria2, "(hysteria2|hy2)://", "hysteria2://");
    explodeStdHysteria2(hysteria2, node);
}

void explodeQuan(const std::string &quan, Proxy &node) {
    std::string strTemp, itemName, itemVal;
    std::string group = V2RAY_DEFAULT_GROUP, ps, add, port, cipher, type = "none", id, aid = "0", net = "tcp", path,
            host, edge, tls;
    string_array configs, vArray, headers;
    strTemp = regReplace(quan, "(.*?) = (.*)", "$1,$2");
    configs = split(strTemp, ",");

    if (configs[1] == "vmess") {
        if (configs.size() < 6)
            return;
        ps = trim(configs[0]);
        add = trim(configs[2]);
        port = trim(configs[3]);
        if (port == "0")
            return;
        cipher = trim(configs[4]);
        id = trim(replaceAllDistinct(configs[5], "\"", ""));

        //read link
        for (uint32_t i = 6; i < configs.size(); i++) {
            vArray = split(configs[i], "=");
            if (vArray.size() < 2)
                continue;
            itemName = trim(vArray[0]);
            itemVal = trim(vArray[1]);
            switch (hash_(itemName)) {
                case "group"_hash:
                    group = itemVal;
                    break;
                case "over-tls"_hash:
                    tls = itemVal == "true" ? "tls" : "";
                    break;
                case "tls-host"_hash:
                    host = itemVal;
                    break;
                case "obfs-path"_hash:
                    path = replaceAllDistinct(itemVal, "\"", "");
                    break;
                case "obfs-header"_hash:
                    headers = split(replaceAllDistinct(replaceAllDistinct(itemVal, "\"", ""), "[Rr][Nn]", "|"), "|");
                    for (std::string &x: headers) {
                        if (regFind(x, "(?i)Host: "))
                            host = x.substr(6);
                        else if (regFind(x, "(?i)Edge: "))
                            edge = x.substr(6);
                    }
                    break;
                case "obfs"_hash:
                    if (itemVal == "ws")
                        net = "ws";
                    break;
                default:
                    continue;
            }
        }
        if (path.empty())
            path = "/";

        vmessConstruct(node, group, ps, add, port, type, id, aid, net, cipher, path, host, edge, tls, "",
                       std::vector<std::string>{});
    }
}

void explodeNetch(std::string netch, Proxy &node) {
    Document json;
    std::string type, group, remark, address, port, username, password, method, plugin, pluginopts;
    std::string protocol, protoparam, obfs, obfsparam, id, aid, transprot, faketype, host, edge, path, tls, sni, fp;
    tribool udp, tfo, scv;
    netch = urlSafeBase64Decode(netch.substr(8));

    json.Parse(netch.data());
    if (json.HasParseError() || !json.IsObject())
        return;
    type = GetMember(json, "Type");
    group = GetMember(json, "Group");
    remark = GetMember(json, "Remark");
    address = GetMember(json, "Hostname");
    udp = GetMember(json, "EnableUDP");
    tfo = GetMember(json, "EnableTFO");
    scv = GetMember(json, "AllowInsecure");
    port = GetMember(json, "Port");
    fp = GetMember(json, "FingerPrint");
    if (port == "0")
        return;
    method = GetMember(json, "EncryptMethod");
    password = GetMember(json, "Password");
    if (remark.empty())
        remark = address + ":" + port;
    switch (hash_(type)) {
        case "SS"_hash:
            plugin = GetMember(json, "Plugin");
            pluginopts = GetMember(json, "PluginOption");
            if (group.empty())
                group = SS_DEFAULT_GROUP;
            ssConstruct(node, group, remark, address, port, password, method, plugin, pluginopts, udp, tfo, scv);
            break;
        case "SSR"_hash:
            protocol = GetMember(json, "Protocol");
            obfs = GetMember(json, "OBFS");
            if (find(ss_ciphers.begin(), ss_ciphers.end(), method) != ss_ciphers.end() &&
                (obfs.empty() || obfs == "plain") && (protocol.empty() || protocol == "origin")) {
                plugin = GetMember(json, "Plugin");
                pluginopts = GetMember(json, "PluginOption");
                if (group.empty())
                    group = SS_DEFAULT_GROUP;
                ssConstruct(node, group, remark, address, port, password, method, plugin, pluginopts, udp, tfo, scv);
            } else {
                protoparam = GetMember(json, "ProtocolParam");
                obfsparam = GetMember(json, "OBFSParam");
                if (group.empty())
                    group = SSR_DEFAULT_GROUP;
                ssrConstruct(node, group, remark, address, port, protocol, method, obfs, password, obfsparam,
                             protoparam, udp, tfo, scv);
            }
            break;
        case "VMess"_hash:
            id = GetMember(json, "UserID");
            aid = GetMember(json, "AlterID");
            transprot = GetMember(json, "TransferProtocol");
            faketype = GetMember(json, "FakeType");
            host = GetMember(json, "Host");
            path = GetMember(json, "Path");
            edge = GetMember(json, "Edge");
            tls = GetMember(json, "TLSSecure");
            sni = GetMember(json, "ServerName");

            if (group.empty())
                group = V2RAY_DEFAULT_GROUP;
            vmessConstruct(node, group, remark, address, port, faketype, id, aid, transprot, method, path, host, edge,
                           tls, sni, std::vector<std::string>{}, udp, tfo, scv);
            break;
        case "Socks5"_hash:
            username = GetMember(json, "Username");
            if (group.empty())
                group = SOCKS_DEFAULT_GROUP;
            socksConstruct(node, group, remark, address, port, username, password, udp, tfo, scv);
            break;
        case "HTTP"_hash:
        case "HTTPS"_hash:
            if (group.empty())
                group = HTTP_DEFAULT_GROUP;
            httpConstruct(node, group, remark, address, port, username, password, type == "HTTPS", tfo, scv);
            break;
        case "Trojan"_hash:
            host = GetMember(json, "Host");
            path = GetMember(json, "Path");
            transprot = GetMember(json, "TransferProtocol");
            tls = GetMember(json, "TLSSecure");
            sni = host;
            if (group.empty())
                group = TROJAN_DEFAULT_GROUP;
            trojanConstruct(node, group, remark, address, port, password, transprot, host, path, fp, sni,
                            std::vector<std::string>{}, tls == "true",
                            udp,
                            tfo, scv);
            break;
        case "Snell"_hash:
            obfs = GetMember(json, "OBFS");
            host = GetMember(json, "Host");
            aid = GetMember(json, "SnellVersion");
            if (group.empty())
                group = SNELL_DEFAULT_GROUP;
            snellConstruct(node, group, remark, address, port, password, obfs, host, to_int(aid, 0), udp, tfo, scv);
            break;
        default:
            return;
    }
}

void explodeClash(Node yamlnode, std::vector<Proxy> &nodes) {
    Node singleproxy;
    uint32_t index = nodes.size();
    const std::string section = yamlnode["proxies"].IsDefined() ? "proxies" : "Proxy";
    for (uint32_t i = 0; i < yamlnode[section].size(); i++) {
        std::string proxytype, ps, server, port, cipher, group, password = "", ports, tempPassword; //common
        std::string type = "none", id, aid = "0", net = "tcp", path, host, edge, tls, sni; //vmess
        std::string fp = "chrome", pbk, sid, packet_encoding; //vless
        std::string plugin, pluginopts, pluginopts_mode, pluginopts_host, pluginopts_mux; //ss
        std::string protocol, protoparam, obfs, obfsparam; //ssr
        std::string flow, mode; //trojan
        std::string user; //socks
        std::string ip, ipv6, private_key, public_key, mtu; //wireguard
        std::string auth, up, down, obfsParam, insecure, alpn; //hysteria
        std::string obfsPassword, certificate_fingerprint; //hysteria2
        std::string congestion_control, udp_relay_mode, token; // tuic
        string_array dns_server;
        std::vector<String> alpns;
        String alpn2;
        std::string fingerprint, multiplexing, transfer_protocol, v2ray_http_upgrade;
        tribool udp, tfo, scv;
        bool reduceRtt = false, disableSni = false; //tuic
        uint16_t request_timeout = 15000; //tuic
        uint16_t idle_check = 30, idle_timeout = 30, min_idle = 0; //anytls
        std::vector<std::string> alpnList;
        Proxy node;
        singleproxy = yamlnode[section][i];
        singleproxy["type"] >>= proxytype;
        singleproxy["name"] >>= ps;
        singleproxy["server"] >>= server;
        singleproxy["port"] >>= port;
        singleproxy["port-range"] >>= ports;

        if (port.empty() || port == "0")
            if (ports.empty())
                continue;
        udp = safe_as<std::string>(singleproxy["udp"]);
        scv = safe_as<std::string>(singleproxy["skip-cert-verify"]);
        switch (hash_(proxytype)) {
            case "vmess"_hash:
                singleproxy["uuid"] >>= id;
                if (id.length() < 36) {
                    break;
                }
                group = V2RAY_DEFAULT_GROUP;
                singleproxy["alterId"] >>= aid;
                singleproxy["cipher"] >>= cipher;
                net = singleproxy["network"].IsDefined() ? safe_as<std::string>(singleproxy["network"]) : "tcp";
                singleproxy["servername"] >>= sni;
                switch (hash_(net)) {
                    case "http"_hash:
                        singleproxy["http-opts"]["path"][0] >>= path;
                        singleproxy["http-opts"]["headers"]["Host"][0] >>= host;
                        edge.clear();
                        break;
                    case "ws"_hash:
                        if (singleproxy["ws-opts"].IsDefined()) {
                            path = singleproxy["ws-opts"]["path"].IsDefined()
                                       ? safe_as<std::string>(
                                           singleproxy["ws-opts"]["path"])
                                       : "/";
                            singleproxy["ws-opts"]["headers"]["Host"] >>= host;
                            if (host.empty()) {
                                singleproxy["ws-opts"]["headers"]["host"] >>= host;
                            }
                            singleproxy["ws-opts"]["headers"]["Edge"] >>= edge;
                        } else {
                            path = singleproxy["ws-path"].IsDefined()
                                       ? safe_as<std::string>(singleproxy["ws-path"])
                                       : "/";
                            singleproxy["ws-headers"]["Host"] >>= host;
                            singleproxy["ws-headers"]["Edge"] >>= edge;
                        }
                        break;
                    case "h2"_hash:
                        singleproxy["h2-opts"]["path"] >>= path;
                        singleproxy["h2-opts"]["host"][0] >>= host;
                        edge.clear();
                        break;
                    case "grpc"_hash:
                        singleproxy["servername"] >>= host;
                        singleproxy["grpc-opts"]["grpc-service-name"] >>= path;
                        edge.clear();
                        break;
                }
                tls = safe_as<std::string>(singleproxy["tls"]) == "true" ? "tls" : "";
                singleproxy["alpn"] >>= alpnList;
                vmessConstruct(node, group, ps, server, port, "", id, aid, net, cipher, path, host, edge, tls, sni,
                               alpnList, udp,
                               tfo, scv);
                break;
            case "ss"_hash:
                group = SS_DEFAULT_GROUP;

                singleproxy["cipher"] >>= cipher;
                singleproxy["password"] >>= password;
                if (singleproxy["plugin"].IsDefined()) {
                    switch (hash_(safe_as<std::string>(singleproxy["plugin"]))) {
                        case "obfs"_hash:
                            plugin = "obfs-local";
                            if (singleproxy["plugin-opts"].IsDefined()) {
                                singleproxy["plugin-opts"]["mode"] >>= pluginopts_mode;
                                singleproxy["plugin-opts"]["host"] >>= pluginopts_host;
                            }
                            break;
                        case "v2ray-plugin"_hash:
                            plugin = "v2ray-plugin";
                            if (singleproxy["plugin-opts"].IsDefined()) {
                                singleproxy["plugin-opts"]["mode"] >>= pluginopts_mode;
                                singleproxy["plugin-opts"]["host"] >>= pluginopts_host;
                                tls = safe_as<bool>(singleproxy["plugin-opts"]["tls"]) ? "tls;" : "";
                                singleproxy["plugin-opts"]["path"] >>= path;
                                pluginopts_mux = safe_as<bool>(singleproxy["plugin-opts"]["mux"]) ? "4" : "";
                            }
                            break;
                        default:
                            break;
                    }
                } else if (singleproxy["obfs"].IsDefined()) {
                    plugin = "obfs-local";
                    singleproxy["obfs"] >>= pluginopts_mode;
                    singleproxy["obfs-host"] >>= pluginopts_host;
                } else
                    plugin.clear();

                switch (hash_(plugin)) {
                    case "simple-obfs"_hash:
                    case "obfs-local"_hash:
                        pluginopts = "obfs=" + pluginopts_mode;
                        pluginopts += pluginopts_host.empty() ? "" : ";obfs-host=" + pluginopts_host;
                        break;
                    case "v2ray-plugin"_hash:
                        pluginopts = "mode=" + pluginopts_mode + ";" + tls;
                        if (!pluginopts_host.empty())
                            pluginopts += "host=" + pluginopts_host + ";";
                        if (!path.empty())
                            pluginopts += "path=" + path + ";";
                        if (!pluginopts_mux.empty())
                            pluginopts += "mux=" + pluginopts_mux + ";";
                        break;
                }

            //support for go-shadowsocks2
                if (cipher == "AEAD_CHACHA20_POLY1305")
                    cipher = "chacha20-ietf-poly1305";
                else if (strFind(cipher, "AEAD")) {
                    cipher = replaceAllDistinct(replaceAllDistinct(cipher, "AEAD_", ""), "_", "-");
                    std::transform(cipher.begin(), cipher.end(), cipher.begin(), ::tolower);
                }

                ssConstruct(node, group, ps, server, port, password, cipher, plugin, pluginopts, udp, tfo, scv);
                break;
            case "socks5"_hash:
                group = SOCKS_DEFAULT_GROUP;

                singleproxy["username"] >>= user;
                singleproxy["password"] >>= password;

                socksConstruct(node, group, ps, server, port, user, password);
                break;
            case "ssr"_hash:
                group = SSR_DEFAULT_GROUP;

                singleproxy["cipher"] >>= cipher;
                if (cipher == "dummy") cipher = "none";
                singleproxy["password"] >>= password;
                singleproxy["protocol"] >>= protocol;
                singleproxy["obfs"] >>= obfs;
                if (singleproxy["protocol-param"].IsDefined())
                    singleproxy["protocol-param"] >>= protoparam;
                else
                    singleproxy["protocolparam"] >>= protoparam;
                if (singleproxy["obfs-param"].IsDefined())
                    singleproxy["obfs-param"] >>= obfsparam;
                else
                    singleproxy["obfsparam"] >>= obfsparam;

                ssrConstruct(node, group, ps, server, port, protocol, cipher, obfs, password, obfsparam, protoparam,
                             udp, tfo, scv);
                break;
            case "http"_hash:
                group = HTTP_DEFAULT_GROUP;

                singleproxy["username"] >>= user;
                singleproxy["password"] >>= password;
                singleproxy["tls"] >>= tls;

                httpConstruct(node, group, ps, server, port, user, password, tls == "true", tfo, scv);
                break;
            case "trojan"_hash:
                group = TROJAN_DEFAULT_GROUP;
                singleproxy["password"] >>= password;
                singleproxy["sni"] >>= host;
                singleproxy["sni"] >>= sni;
                singleproxy["network"] >>= net;
                switch (hash_(net)) {
                    case "grpc"_hash:
                        singleproxy["grpc-opts"]["grpc-service-name"] >>= path;
                        break;
                    case "ws"_hash:
                        singleproxy["ws-opts"]["path"] >>= path;
                        break;
                    default:
                        net = "tcp";
                        path.clear();
                        break;
                }
                singleproxy["alpn"] >>= alpnList;

                trojanConstruct(node, group, ps, server, port, password, net, host, path, fp, sni, alpnList, true, udp,
                                tfo, scv);
                break;
            case "snell"_hash:
                group = SNELL_DEFAULT_GROUP;
                singleproxy["psk"] >> password;
                singleproxy["obfs-opts"]["mode"] >>= obfs;
                singleproxy["obfs-opts"]["host"] >>= host;
                singleproxy["version"] >>= aid;

                snellConstruct(node, group, ps, server, port, password, obfs, host, to_int(aid, 0), udp, tfo, scv);
                break;
            case "wireguard"_hash:
                group = WG_DEFAULT_GROUP;
                singleproxy["public-key"] >>= public_key;
                singleproxy["private-key"] >>= private_key;
                singleproxy["dns"] >>= dns_server;
                singleproxy["mtu"] >>= mtu;
                singleproxy["preshared-key"] >>= password;
                singleproxy["ip"] >>= ip;
                singleproxy["ipv6"] >>= ipv6;

                wireguardConstruct(node, group, ps, server, port, ip, ipv6, private_key, public_key, password,
                                   dns_server, mtu, "0", "", "", udp, "");
                break;
            case "vless"_hash:
                group = XRAY_DEFAULT_GROUP;
                singleproxy["uuid"] >>= id;
                singleproxy["alterId"] >>= aid;
                net = singleproxy["network"].IsDefined() ? safe_as<std::string>(singleproxy["network"]) : "tcp";
                sni = singleproxy["sni"].IsDefined()
                          ? safe_as<std::string>(singleproxy["sni"])
                          : safe_as<std::string>(
                              singleproxy["servername"]);
                switch (hash_(net)) {
                    case "tcp"_hash:
                    case "http"_hash:
                        singleproxy["http-opts"]["path"][0] >>= path;
                        singleproxy["http-opts"]["headers"]["Host"][0] >>= host;
                        edge.clear();
                        break;
                    case "ws"_hash:
                        if (singleproxy["ws-opts"].IsDefined()) {
                            path = singleproxy["ws-opts"]["path"].IsDefined()
                                       ? safe_as<std::string>(
                                           singleproxy["ws-opts"]["path"])
                                       : "/";
                            singleproxy["ws-opts"]["headers"]["Host"] >>= host;
                            if (host.empty()) {
                                singleproxy["ws-opts"]["headers"]["host"] >>= host;
                            }
                            singleproxy["ws-opts"]["headers"]["Edge"] >>= edge;
                            if (singleproxy["ws-opts"]["v2ray-http-upgrade"].IsDefined()) {
                                v2ray_http_upgrade = safe_as<std::string>(singleproxy["ws-opts"]["v2ray-http-upgrade"]);
                            }
                        } else {
                            path = singleproxy["ws-path"].IsDefined()
                                       ? safe_as<std::string>(singleproxy["ws-path"])
                                       : "/";
                            singleproxy["ws-headers"]["Host"] >>= host;
                            singleproxy["ws-headers"]["Edge"] >>= edge;
                        }

                        break;
                    case "h2"_hash:
                        singleproxy["h2-opts"]["path"] >>= path;
                        singleproxy["h2-opts"]["host"][0] >>= host;
                        edge.clear();
                        break;
                    case "grpc"_hash:
                        singleproxy["servername"] >>= host;
                        singleproxy["grpc-opts"]["grpc-service-name"] >>= path;
                        edge.clear();
                        break;
                    default:
                        continue;
                }

                tls = safe_as<std::string>(singleproxy["tls"]) == "true" ? "tls" : "";
                if (singleproxy["reality-opts"].IsDefined()) {
                    host = singleproxy["sni"].IsDefined()
                               ? safe_as<std::string>(singleproxy["sni"])
                               : safe_as<std::string>(singleproxy["servername"]);
                    writeLog(LOG_LEVEL_DEBUG, "Reality 主机：" + host);
                    singleproxy["reality-opts"]["public-key"] >>= pbk;
                    singleproxy["reality-opts"]["short-id"] >>= sid;
                }
                singleproxy["flow"] >>= flow;
                singleproxy["client-fingerprint"] >>= fp;
                singleproxy["alpn"] >>= alpnList;
                singleproxy["packet-encoding"] >>= packet_encoding;
                bool vless_udp;
                singleproxy["udp"] >> vless_udp;
                vlessConstruct(node, XRAY_DEFAULT_GROUP, ps, server, port, type, id, aid, net, "auto", flow, mode, path,
                               host, "", tls, pbk, sid, fp, sni, alpnList, packet_encoding, udp, tribool(), tribool(),
                               tribool(), "", v2ray_http_upgrade);
                break;
            case "hysteria"_hash:
                group = HYSTERIA_DEFAULT_GROUP;
                singleproxy["auth_str"] >> auth;
                if (auth.empty()) {
                    singleproxy["auth-str"] >> auth;
                    if (auth.empty()) {
                        singleproxy["password"] >> auth;
                    }
                }
                singleproxy["up"] >> up;
                singleproxy["down"] >> down;
                singleproxy["obfs"] >> obfsParam;
                singleproxy["protocol"] >> type;
                singleproxy["sni"] >> host;
                singleproxy["alpn"][0] >> alpn;
                singleproxy["alpn"] >> alpnList;
                singleproxy["protocol"] >> insecure;
                singleproxy["ports"] >> ports;
                sni = host;
                hysteriaConstruct(node, group, ps, server, port, type, auth, "", host, up, down, alpn, obfsParam,
                                  insecure, ports, sni,
                                  udp, tfo, scv);
                break;
            case "hysteria2"_hash:
                group = HYSTERIA2_DEFAULT_GROUP;
                singleproxy["password"] >>= password;
                if (password.empty())
                    singleproxy["auth"] >>= password;
                if (singleproxy["up"].IsDefined()) {
                    singleproxy["up"] >>= up;
                    if (up.empty()) {
                        try {
                            up = singleproxy["up"].as<std::string>();
                        } catch (const YAML::BadConversion& e) {
                        }
                    }
                }
                if (singleproxy["down"].IsDefined()) {
                    singleproxy["down"] >>= down;
                    if (down.empty()) {
                        try {
                            down = singleproxy["down"].as<std::string>();
                        } catch (const YAML::BadConversion& e) {
                        }
                    }
                }
                singleproxy["obfs"] >>= obfsParam;
                singleproxy["obfs-password"] >>= obfsPassword;
                singleproxy["sni"] >>= host;
                singleproxy["fingerprint"] >>= certificate_fingerprint;
                singleproxy["alpn"][0] >>= alpn;
                singleproxy["ports"] >> ports;
                sni = host;
                hysteria2Construct(node, group, ps, server, port, password, host, up, down, alpn, obfsParam,
                                   obfsPassword, sni, public_key, ports, udp, tfo, scv);
                node.Fingerprint = certificate_fingerprint;
                break;
            case "tuic"_hash:
                group = TUIC_DEFAULT_GROUP;
                singleproxy["password"] >>= password;
                singleproxy["uuid"] >>= id;
                singleproxy["congestion-controller"] >>= congestion_control;
                singleproxy["udp-relay-mode"] >>= udp_relay_mode;
                singleproxy["sni"] >>= sni;
                if (!singleproxy["alpn"].IsNull()) {
                    singleproxy["alpn"][0] >>= alpn;
                }
                singleproxy["disable-sni"] >>= disableSni;
                singleproxy["reduce-rtt"] >>= reduceRtt;
                singleproxy["token"] >>= token;
                singleproxy["request-timeout"] >>= request_timeout;
                tuicConstruct(node, TUIC_DEFAULT_GROUP, ps, server, port, password, congestion_control, alpn, sni, id,
                              udp_relay_mode, token,
                              tribool(),
                              tribool(), scv, reduceRtt, disableSni, request_timeout);

                break;
            case "anytls"_hash:
                group = ANYTLS_DEFAULT_GROUP;
                singleproxy["password"] >>= password;
                singleproxy["sni"] >>= sni;

                if (!singleproxy["alpn"].IsNull() && singleproxy["alpn"].size() >= 1) {
                    singleproxy["alpn"][0] >>= alpn;
                    alpns.push_back(alpn);
                    if (singleproxy["alpn"].size() >= 2 && !singleproxy["alpn"][1].IsNull()) {
                        singleproxy["alpn"][1] >>= alpn2;
                        alpns.push_back(alpn2);
                    }
                }
                singleproxy["client-fingerprint"] >>= fingerprint;
                idle_check = parseUint16Option(
                    safe_as<std::string>(singleproxy["idle-session-check-interval"]), 30, true);
                idle_timeout = parseUint16Option(
                    safe_as<std::string>(singleproxy["idle-session-timeout"]), 30, true);
                min_idle = parseUint16Option(
                    safe_as<std::string>(singleproxy["min-idle-session"]), 0);
                anyTlSConstruct(node, ANYTLS_DEFAULT_GROUP, ps, port, password, server, alpns, fingerprint, sni,
                                udp,
                                tribool(), scv, tribool(), "", idle_check, idle_timeout, min_idle);
                break;
            case "mieru"_hash:
                group = MIERU_DEFAULT_GROUP;
                singleproxy["password"] >>= password;
                singleproxy["username"] >>= user;
                singleproxy["port-range"] >>= ports;
                if (!singleproxy["multiplexing"].IsNull()) {
                    singleproxy["multiplexing"] >>= multiplexing;
                }
                transfer_protocol = "TCP";
                if (!singleproxy["transport"].IsNull()) {
                    singleproxy["transport"] >>= transfer_protocol;
                }
                mieruConstruct(node, MIERU_DEFAULT_GROUP, ps, port, password, server, ports, user, multiplexing,
                               transfer_protocol,
                               udp,
                               tribool(), scv, tribool(), "");
                break;
            default:
                continue;
        }

        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeStdVMess(std::string vmess, Proxy &node) {
    ParsedShareUri parsed;
    if (parseShareUri(vmess, "vmess", parsed) && isXrayUuid(parsed.user)) {
        std::string type, net, path, host, mode;
        if (!parseXrayTransport(parsed.query, node, net, type, path, host, mode))
            return;
        std::string cipher = decodedUrlArg(parsed.query, "encryption");
        if (cipher.empty())
            cipher = "auto";
        std::string tls = decodedUrlArg(parsed.query, "security");
        std::string sni = decodedUrlArg(parsed.query, "sni");
        if (parsed.remark.empty())
            parsed.remark = parsed.host + ":" + parsed.port;
        vmessConstruct(node, V2RAY_DEFAULT_GROUP, parsed.remark, parsed.host, parsed.port, type,
                       parsed.user, "0", net, cipher, urlDecode(path), host, "", tls, sni,
                       getUrlAlpnList(parsed.query));
        node.Fingerprint = decodedUrlArg(parsed.query, "fp");
        node.AllowInsecure = getXrayAllowInsecure(parsed.query);
        node.GRPCMode = mode;
        node.PublicKey = decodedUrlArg(parsed.query, "pbk");
        node.ShortId = decodedUrlArg(parsed.query, "sid");
        return;
    }

    std::string add, port, type, id, aid, net, path, host, tls, remarks;
    std::string addition;
    vmess = vmess.substr(8);

    extractRemark(vmess, remarks);
    const std::string stdvmess_matcher =
            R"(^([a-z]+)(?:\+([a-z]+))?:([\da-f]{4}(?:[\da-f]{4}-){4}[\da-f]{12})-(\d+)@(.+):(\d+)(?:\/?\?(.*))?$)";
    if (regGetMatch(vmess, stdvmess_matcher, 8, 0, &net, &tls, &id, &aid, &add, &port, &addition))
        return;

    switch (hash_(net)) {
        case "tcp"_hash:
        case "kcp"_hash:
            type = getUrlArg(addition, "type");
            break;
        case "http"_hash:
        case "ws"_hash:
            host = getUrlArg(addition, "host");
            path = getUrlArg(addition, "path");
            break;
        case "quic"_hash:
            type = getUrlArg(addition, "security");
            host = getUrlArg(addition, "type");
            path = getUrlArg(addition, "key");
            break;
        default:
            return;
    }

    if (remarks.empty())
        remarks = add + ":" + port;
    std::string alpn = getUrlArg(addition, "alpn");
    std::vector<std::string> alpnList;
    if (!alpn.empty()) {
        alpnList.push_back(alpn);
    }
    vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, add, port, type, id, aid, net, "auto", path, host, "", tls, "",
                   alpnList);
}


void explodeStdHysteria(std::string hysteria, Proxy &node) {
    std::string add, port, type, auth, host, insecure, up, down, alpn, obfsParam, remarks, auth_str, sni;
    std::string addition;
    hysteria = hysteria.substr(11);
    string_size pos;

    extractRemark(hysteria, remarks);
    const std::string stdhysteria_matcher = R"(^(.*)[:](\d+)[?](.*)$)";
    if (regGetMatch(hysteria, stdhysteria_matcher, 4, 0, &add, &port, &addition))
        return;
    type = getUrlArg(addition, "protocol");
    auth = getUrlArg(addition, "auth");
    auth_str = getUrlArg(addition, "auth_str");
    host = getUrlArg(addition, "peer");
    insecure = getUrlArg(addition, "insecure");
    up = getUrlArg(addition, "upmbps");
    down = getUrlArg(addition, "downmbps");
    alpn = getUrlArg(addition, "alpn");
    obfsParam = getUrlArg(addition, "obfsParam");
    sni = getUrlArg(addition, "peer");

    if (remarks.empty())
        remarks = add + ":" + port;
    std::vector<std::string> alpnList;
    if (!alpn.empty()) {
        alpnList.push_back(alpn);
    }
    hysteriaConstruct(node, HYSTERIA_DEFAULT_GROUP, remarks, add, port, type, auth, auth_str, host, up, down, alpn,
                      obfsParam,
                      insecure, "", sni);
    return;
}

void explodeStdMieru(std::string mieru, Proxy &node) {
    std::string username, password, host, port, ports, profile, protocol, multiplexing, mtu, remarks;
    std::string addition;
    tribool udp, tfo, scv, tls13;

    // 去除前缀
    string_size pos;

    // 提取 remarks
    extractRemark(mieru, remarks);

    // 提取参数
    pos = mieru.rfind("?");
    if (pos != mieru.npos) {
        addition = mieru.substr(pos + 1);
        mieru.erase(pos);
    }

    // 账号密码@host
    if (regGetMatch(mieru, R"(^(.*?):(.*?)@(.*)$)", 4, 0, &username, &password, &host))
        return;

    // 提取端口（port=多个情况）
    port = getUrlArg(addition, "port");
    if (port.find('-') != std::string::npos) {
        ports = port;
    }
    // 提取协议（多个 protocol）
    protocol = getUrlArg(addition, "protocol");

    multiplexing = getUrlArg(addition, "multiplexing");
    mtu = getUrlArg(addition, "mtu");

    if (remarks.empty())
        remarks = host;

    mieruConstruct(node, "MieruGroup", remarks, port,
                   password, host, ports, username, multiplexing, protocol,
                   udp, tfo, scv, tls13, "");
}

void explodeStdHysteria2(std::string hysteria2, Proxy &node) {
    ParsedShareUri parsed;
    std::string ports;
    if (!parseModernShareUri(std::move(hysteria2), "hysteria2", false, "443", true, parsed, ports))
        return;

    std::string password = parsed.user;
    if (password.empty())
        password = decodedUrlArg(parsed.query, "password");
    std::string query_ports = decodedUrlArg(parsed.query, "ports");
    if (!query_ports.empty()) {
        for (const std::string &token : split(query_ports, ",")) {
            uint16_t ignored_port = 0;
            std::string ignored_remaining;
            if (!validHysteria2PortToken(token, ignored_port,
                                         ignored_remaining))
                return;
        }
        ports = ports.empty() ? query_ports : ports + "," + query_ports;
    }
    const std::string sni = decodedUrlArg(parsed.query, "sni");
    if (parsed.remark.empty())
        parsed.remark = parsed.host + ":" + parsed.port;

    hysteria2Construct(node, HYSTERIA2_DEFAULT_GROUP, parsed.remark, parsed.host, parsed.port, password, sni,
                       decodedUrlArg(parsed.query, "up"), decodedUrlArg(parsed.query, "down"),
                       decodedUrlArg(parsed.query, "alpn"), decodedUrlArg(parsed.query, "obfs"),
                       decodedUrlArg(parsed.query, "obfs-password"), sni, "", ports,
                       tribool(), tribool(), tribool(getUrlArg(parsed.query, "insecure")));
    node.Fingerprint = decodedFirstUrlArg(parsed.query, {"pinSHA256", "pinsha256"});
    node.Hysteria2ECH = decodedUrlArg(parsed.query, "ech");
    node.Hysteria2PortsAreAdditional = !ports.empty();
}


void explodeStdVless(std::string vless, Proxy &node) {
    ParsedShareUri parsed;
    if (!parseShareUri(vless, "vless", parsed) || !isXrayUuid(parsed.user))
        return;

    std::string type, net, path, host, mode;
    if (!parseXrayTransport(parsed.query, node, net, type, path, host, mode))
        return;

    if (parsed.remark.empty())
        parsed.remark = parsed.host + ":" + parsed.port;
    std::string encryption = decodedUrlArg(parsed.query, "encryption");
    if (encryption.empty())
        encryption = "none";
    vlessConstruct(node, XRAY_DEFAULT_GROUP, parsed.remark, parsed.host, parsed.port, type, parsed.user, "0", net,
                   "auto", decodedUrlArg(parsed.query, "flow"), mode, path, host, "",
                   decodedUrlArg(parsed.query, "security"), decodedUrlArg(parsed.query, "pbk"),
                   decodedUrlArg(parsed.query, "sid"), decodedUrlArg(parsed.query, "fp"),
                   decodedUrlArg(parsed.query, "sni"), getUrlAlpnList(parsed.query),
                   decodedUrlArg(parsed.query, "packet-encoding"), tribool(), tribool(),
                   getXrayAllowInsecure(parsed.query), tribool(), "",
                   tribool(), encryption);
    return;
}

void explodeShadowrocket(std::string rocket, Proxy &node) {
    std::string add, port, type, id, aid, net = "tcp", path, host, tls, cipher, remarks;
    std::string obfs; //for other style of link
    std::string addition;
    rocket = rocket.substr(8);

    string_size pos = rocket.find('?');
    addition = rocket.substr(pos + 1);
    rocket.erase(pos);

    if (regGetMatch(urlSafeBase64Decode(rocket), "(.*?):(.*)@(.*):(.*)", 5, 0, &cipher, &id, &add, &port))
        return;
    if (port == "0")
        return;
    remarks = urlDecode(getUrlArg(addition, "remarks"));
    obfs = getUrlArg(addition, "obfs");
    if (!obfs.empty()) {
        if (obfs == "websocket") {
            net = "ws";
            host = getUrlArg(addition, "obfsParam");
            path = getUrlArg(addition, "path");
        }
    } else {
        net = getUrlArg(addition, "network");
        host = getUrlArg(addition, "wsHost");
        path = getUrlArg(addition, "wspath");
    }
    tls = getUrlArg(addition, "tls") == "1" ? "tls" : "";
    aid = getUrlArg(addition, "aid");

    if (aid.empty())
        aid = "0";

    if (remarks.empty())
        remarks = add + ":" + port;
    std::string alpn = getUrlArg(addition, "alpn");
    std::vector<std::string> alpnList;
    if (!alpn.empty()) {
        alpnList.push_back(alpn);
    }
    vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, add, port, type, id, aid, net, cipher, path, host, "", tls, "",
                   alpnList);
}

void explodeKitsunebi(std::string kit, Proxy &node) {
    std::string add, port, type, id, aid = "0", net = "tcp", path, host, tls, cipher = "auto", remarks;
    std::string addition;
    string_size pos;
    kit = kit.substr(9);

    pos = kit.find('#');
    if (pos != std::string::npos) {
        remarks = kit.substr(pos + 1);
        kit = kit.substr(0, pos);
    }

    pos = kit.find('?');
    addition = kit.substr(pos + 1);
    kit = kit.substr(0, pos);

    if (regGetMatch(kit, "(.*?)@(.*):(.*)", 4, 0, &id, &add, &port))
        return;
    pos = port.find('/');
    if (pos != std::string::npos) {
        path = port.substr(pos);
        port.erase(pos);
    }
    if (port == "0")
        return;
    net = getUrlArg(addition, "network");
    tls = getUrlArg(addition, "tls") == "true" ? "tls" : "";
    host = getUrlArg(addition, "ws.host");

    if (remarks.empty())
        remarks = add + ":" + port;
    std::string alpn = getUrlArg(addition, "alpn");
    std::vector<std::string> alpnList;
    if (!alpn.empty()) {
        alpnList.push_back(alpn);
    }
    vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, add, port, type, id, aid, net, cipher, path, host, "", tls, "",
                   alpnList);
}

// peer = (public-key = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=, allowed-ips = "0.0.0.0/0, ::/0", endpoint = engage.cloudflareclient.com:2408, client-id = 139/184/125),(public-key = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=, endpoint = engage.cloudflareclient.com:2408)
void parsePeers(Proxy &node, const std::string &data) {
    auto peers = regGetAllMatch(data, R"(\((.*?)\))", true);
    if (peers.empty())
        return;
    auto peer = peers[0];
    auto peerdata = regGetAllMatch(peer, R"(([a-z-]+) ?= ?([^" ),]+|".*?"),? ?)", true);
    if (peerdata.size() % 2 != 0)
        return;
    for (size_t i = 0; i < peerdata.size(); i += 2) {
        auto key = peerdata[i];
        auto val = peerdata[i + 1];
        switch (hash_(key)) {
            case "public-key"_hash:
                node.PublicKey = val;
                break;
            case "endpoint"_hash:
                node.Hostname = val.substr(0, val.rfind(':'));
                node.Port = to_int(val.substr(val.rfind(':') + 1));
                break;
            case "client-id"_hash:
                node.ClientId = val;
                break;
            case "allowed-ips"_hash:
                node.AllowedIPs = trimOf(val, '"');
                break;
            default:
                break;
        }
    }
}

bool explodeSurge(std::string surge, std::vector<Proxy> &nodes) {
    std::multimap<std::string, std::string> proxies;
    uint32_t i, index = nodes.size();
    INIReader ini;

    /*
    if(!strFind(surge, "[Proxy]"))
        return false;
    */

    ini.store_isolated_line = true;
    ini.keep_empty_section = false;
    ini.allow_dup_section_titles = true;
    ini.set_isolated_items_section("Proxy");
    ini.add_direct_save_section("Proxy");
    if (surge.find("[Proxy]") != surge.npos)
        surge = regReplace(surge, R"(^[\S\s]*?\[)", "[", false);
    ini.parse(surge);

    if (!ini.section_exist("Proxy"))
        return false;
    ini.enter_section("Proxy");
    ini.get_items(proxies);

    const std::string proxystr = "(.*?)\\s*=\\s*(.*)";

    for (auto &x: proxies) {
        std::string remarks, server, port, method, username, password, sni; //common
        std::string plugin, pluginopts, pluginopts_mode, pluginopts_host, mod_url, mod_md5; //ss
        std::string id, net, tls, host, edge, path, fp; //v2
        std::string protocol, protoparam; //ssr
        std::string section, ip, ipv6, private_key, public_key, mtu, test_url, client_id, peer, keepalive; //wireguard
        string_array dns_servers;
        string_multimap wireguard_config;
        std::string version, aead = "1";
        std::string itemName, itemVal, config;
        std::vector<std::string> configs, vArray, headers, header;
        tribool udp, tfo, scv, tls13;
        Proxy node;

        /*
        remarks = regReplace(x.second, proxystr, "$1");
        configs = split(regReplace(x.second, proxystr, "$2"), ",");
        */
        regGetMatch(x.second, proxystr, 3, 0, &remarks, &config);
        configs = split(config, ",");
        if (configs.size() < 3)
            continue;
        switch (hash_(configs[0])) {
            case "direct"_hash:
            case "reject"_hash:
            case "reject-tinygif"_hash:
                continue;
            case "custom"_hash: //surge 2 style custom proxy
                //remove module detection to speed up parsing and compatible with broken module
                /*
                mod_url = trim(configs[5]);
                if(parsedMD5.count(mod_url) > 0)
                {
                    mod_md5 = parsedMD5[mod_url]; //read calculated MD5 from map
                }
                else
                {
                    mod_md5 = getMD5(webGet(mod_url)); //retrieve module and calculate MD5
                    parsedMD5.insert(std::pair<std::string, std::string>(mod_url, mod_md5)); //save unrecognized module MD5 to map
                }
                */

                //if(mod_md5 == modSSMD5) //is SSEncrypt module
            {
                if (configs.size() < 5)
                    continue;
                server = trim(configs[1]);
                port = trim(configs[2]);
                if (port == "0")
                    continue;
                method = trim(configs[3]);
                password = trim(configs[4]);

                for (i = 6; i < configs.size(); i++) {
                    vArray = split(configs[i], "=");
                    if (vArray.size() < 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch (hash_(itemName)) {
                        case "obfs"_hash:
                            plugin = "simple-obfs";
                            pluginopts_mode = itemVal;
                            break;
                        case "obfs-host"_hash:
                            pluginopts_host = itemVal;
                            break;
                        case "udp-relay"_hash:
                            udp = itemVal;
                            break;
                        case "tfo"_hash:
                            tfo = itemVal;
                            break;
                        case "shadow-tls-sni"_hash:
                        case "shadow-tls-password"_hash:
                        case "shadow-tls-version"_hash:
                            port = "0";
                            break;
                        default:
                            continue;
                    }
                }
                if (port == "0")
                    continue;
                if (!plugin.empty()) {
                    pluginopts = "obfs=" + pluginopts_mode;
                    pluginopts += pluginopts_host.empty() ? "" : ";obfs-host=" + pluginopts_host;
                }

                ssConstruct(node, SS_DEFAULT_GROUP, remarks, server, port, password, method, plugin, pluginopts, udp,
                            tfo, scv);
            }
            //else
            //    continue;
            break;
            case "ss"_hash: //surge 3 style ss proxy
                server = trim(configs[1]);
                port = trim(configs[2]);
                if (port == "0")
                    continue;

                for (i = 3; i < configs.size(); i++) {
                    vArray = split(configs[i], "=");
                    if (vArray.size() < 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch (hash_(itemName)) {
                        case "encrypt-method"_hash:
                            method = itemVal;
                            break;
                        case "password"_hash:
                            password = itemVal;
                            break;
                        case "obfs"_hash:
                            plugin = "simple-obfs";
                            pluginopts_mode = itemVal;
                            break;
                        case "obfs-host"_hash:
                            pluginopts_host = itemVal;
                            break;
                        case "udp-relay"_hash:
                            udp = itemVal;
                            break;
                        case "tfo"_hash:
                            tfo = itemVal;
                            break;
                        case "shadow-tls-sni"_hash:
                        case "shadow-tls-password"_hash:
                        case "shadow-tls-version"_hash:
                            port = "0";
                            break;
                        default:
                            continue;
                    }
                }
                if (port == "0")
                    continue;
                if (!plugin.empty()) {
                    pluginopts = "obfs=" + pluginopts_mode;
                    pluginopts += pluginopts_host.empty() ? "" : ";obfs-host=" + pluginopts_host;
                }

                ssConstruct(node, SS_DEFAULT_GROUP, remarks, server, port, password, method, plugin, pluginopts, udp,
                            tfo, scv);
                break;
            case "socks5"_hash: //surge 3 style socks5 proxy
                server = trim(configs[1]);
                port = trim(configs[2]);
                if (port == "0")
                    continue;
                if (configs.size() >= 5) {
                    username = trim(configs[3]);
                    password = trim(configs[4]);
                }
                for (i = 5; i < configs.size(); i++) {
                    vArray = split(configs[i], "=");
                    if (vArray.size() < 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch (hash_(itemName)) {
                        case "udp-relay"_hash:
                            udp = itemVal;
                            break;
                        case "tfo"_hash:
                            tfo = itemVal;
                            break;
                        case "skip-cert-verify"_hash:
                            scv = itemVal;
                            break;
                        default:
                            continue;
                    }
                }
                socksConstruct(node, SOCKS_DEFAULT_GROUP, remarks, server, port, username, password, udp, tfo, scv);
                break;
            case "vmess"_hash: //surge 4 style vmess proxy
                server = trim(configs[1]);
                port = trim(configs[2]);
                if (port == "0")
                    continue;
                net = "tcp";
                method = "auto";

                for (i = 3; i < configs.size(); i++) {
                    vArray = split(configs[i], "=");
                    if (vArray.size() != 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch (hash_(itemName)) {
                        case "username"_hash:
                            id = itemVal;
                            break;
                        case "ws"_hash:
                            net = itemVal == "true" ? "ws" : "tcp";
                            break;
                        case "tls"_hash:
                            tls = itemVal == "true" ? "tls" : "";
                            break;
                        case "ws-path"_hash:
                            path = itemVal;
                            break;
                        case "obfs-host"_hash:
                            host = itemVal;
                            break;
                        case "ws-headers"_hash:
                            headers = split(itemVal, "|");
                            for (auto &y: headers) {
                                header = split(trim(y), ":");
                                if (header.size() != 2)
                                    continue;
                                else if (regMatch(header[0], "(?i)host"))
                                    host = trimQuote(header[1]);
                                else if (regMatch(header[0], "(?i)edge"))
                                    edge = trimQuote(header[1]);
                            }
                            break;
                        case "udp-relay"_hash:
                            udp = itemVal;
                            break;
                        case "tfo"_hash:
                            tfo = itemVal;
                            break;
                        case "skip-cert-verify"_hash:
                            scv = itemVal;
                            break;
                        case "tls13"_hash:
                            tls13 = itemVal;
                            break;
                        case "vmess-aead"_hash:
                            aead = itemVal == "true" ? "0" : "1";
                        default:
                            continue;
                    }
                }

                vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, server, port, "", id, aead, net, method, path, host,
                               edge, tls, "", std::vector<std::string>{}, udp, tfo, scv, tls13);
                break;
            case "http"_hash: //http proxy
                server = trim(configs[1]);
                port = trim(configs[2]);
                if (port == "0")
                    continue;
                for (i = 3; i < configs.size(); i++) {
                    vArray = split(configs[i], "=");
                    if (vArray.size() < 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch (hash_(itemName)) {
                        case "username"_hash:
                            username = itemVal;
                            break;
                        case "password"_hash:
                            password = itemVal;
                            break;
                        case "skip-cert-verify"_hash:
                            scv = itemVal;
                            break;
                        default:
                            continue;
                    }
                }
                httpConstruct(node, HTTP_DEFAULT_GROUP, remarks, server, port, username, password, false, tfo, scv);
                break;
            case "trojan"_hash: // surge 4 style trojan proxy
                server = trim(configs[1]);
                port = trim(configs[2]);
                if (port == "0")
                    continue;

                for (i = 3; i < configs.size(); i++) {
                    vArray = split(configs[i], "=");
                    if (vArray.size() != 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch (hash_(itemName)) {
                        case "password"_hash:
                            password = itemVal;
                            break;
                        case "sni"_hash:
                            host = itemVal;
                            sni = itemVal;
                            break;
                        case "udp-relay"_hash:
                            udp = itemVal;
                            break;
                        case "tfo"_hash:
                            tfo = itemVal;
                            break;
                        case "skip-cert-verify"_hash:
                            scv = itemVal;
                            break;
                        case "fingerprint"_hash:
                            fp = itemVal;
                            break;
                        default:
                            continue;
                    }
                }

                trojanConstruct(node, TROJAN_DEFAULT_GROUP, remarks, server, port, password, "", host, "", fp, sni,
                                std::vector<std::string>{},
                                true,
                                udp,
                                tfo, scv);
                break;
            case "snell"_hash:
                server = trim(configs[1]);
                port = trim(configs[2]);
                if (port == "0")
                    continue;

                for (i = 3; i < configs.size(); i++) {
                    vArray = split(configs[i], "=");
                    if (vArray.size() != 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch (hash_(itemName)) {
                        case "psk"_hash:
                            password = itemVal;
                            break;
                        case "obfs"_hash:
                            plugin = itemVal;
                            break;
                        case "obfs-host"_hash:
                            host = itemVal;
                            break;
                        case "udp-relay"_hash:
                            udp = itemVal;
                            break;
                        case "tfo"_hash:
                            tfo = itemVal;
                            break;
                        case "skip-cert-verify"_hash:
                            scv = itemVal;
                            break;
                        case "version"_hash:
                            version = itemVal;
                            break;
                        default:
                            continue;
                    }
                }

                snellConstruct(node, SNELL_DEFAULT_GROUP, remarks, server, port, password, plugin, host,
                               to_int(version, 0), udp, tfo, scv);
                break;
            case "wireguard"_hash:
                for (i = 1; i < configs.size(); i++) {
                    vArray = split(trim(configs[i]), "=");
                    if (vArray.size() != 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch (hash_(itemName)) {
                        case "section-name"_hash:
                            section = itemVal;
                            break;
                        case "test-url"_hash:
                            test_url = itemVal;
                            break;
                    }
                }
                if (section.empty())
                    continue;
                ini.get_items("WireGuard " + section, wireguard_config);
                if (wireguard_config.empty())
                    continue;

                for (auto &c: wireguard_config) {
                    itemName = trim(c.first);
                    itemVal = trim(c.second);
                    switch (hash_(itemName)) {
                        case "self-ip"_hash:
                            ip = itemVal;
                            break;
                        case "self-ip-v6"_hash:
                            ipv6 = itemVal;
                            break;
                        case "private-key"_hash:
                            private_key = itemVal;
                            break;
                        case "dns-server"_hash:
                            vArray = split(itemVal, ",");
                            for (auto &y: vArray)
                                dns_servers.emplace_back(trim(y));
                            break;
                        case "mtu"_hash:
                            mtu = itemVal;
                            break;
                        case "peer"_hash:
                            peer = itemVal;
                            break;
                        case "keepalive"_hash:
                            keepalive = itemVal;
                            break;
                    }
                }

                wireguardConstruct(node, WG_DEFAULT_GROUP, remarks, "", "0", ip, ipv6, private_key, "", "", dns_servers,
                                   mtu, keepalive, test_url, "", udp, "");
                parsePeers(node, peer);
                break;
            case "anytls"_hash: //Surge style anytls proxy
                server = trim(configs[1]);
                port = trim(configs[2]);
                if (port == "0")
                    continue;

                for (i = 3; i < configs.size(); i++) {
                    vArray = split(configs[i], "=");
                    if (vArray.size() != 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch (hash_(itemName)) {
                        case "password"_hash:
                            password = itemVal;
                            break;
                        case "sni"_hash:
                            sni = itemVal;
                            break;
                        case "skip-cert-verify"_hash:
                            scv = itemVal;
                            break;
                        case "fingerprint"_hash:
                            fp = itemVal;
                            break;
                        case "tls13"_hash:
                            tls13 = itemVal;
                            break;
                        default:
                            continue;
                    }
                }

                anyTlSConstruct(node, ANYTLS_DEFAULT_GROUP, remarks, port, password, server,
                                std::vector<std::string>{}, fp, sni,
                                udp, tribool(), scv, tribool(), "", 30, 30, 0);
                break;
            default:
                switch (hash_(remarks)) {
                    case "shadowsocks"_hash: //quantumult x style ss/ssr link
                        server = trim(configs[0].substr(0, configs[0].rfind(":")));
                        port = trim(configs[0].substr(configs[0].rfind(":") + 1));
                        if (port == "0")
                            continue;

                        for (i = 1; i < configs.size(); i++) {
                            vArray = split(trim(configs[i]), "=");
                            if (vArray.size() != 2)
                                continue;
                            itemName = trim(vArray[0]);
                            itemVal = trim(vArray[1]);
                            switch (hash_(itemName)) {
                                case "method"_hash:
                                    method = itemVal;
                                    break;
                                case "password"_hash:
                                    password = itemVal;
                                    break;
                                case "tag"_hash:
                                    remarks = itemVal;
                                    break;
                                case "ssr-protocol"_hash:
                                    protocol = itemVal;
                                    break;
                                case "ssr-protocol-param"_hash:
                                    protoparam = itemVal;
                                    break;
                                case "obfs"_hash: {
                                    switch (hash_(itemVal)) {
                                        case "http"_hash:
                                        case "tls"_hash:
                                            plugin = "simple-obfs";
                                            pluginopts_mode = itemVal;
                                            break;
                                        case "wss"_hash:
                                            tls = "tls";
                                            [[fallthrough]];
                                        case "ws"_hash:
                                            pluginopts_mode = "websocket";
                                            plugin = "v2ray-plugin";
                                            break;
                                        default:
                                            pluginopts_mode = itemVal;
                                    }
                                    break;
                                }
                                case "obfs-host"_hash:
                                    pluginopts_host = itemVal;
                                    break;
                                case "obfs-uri"_hash:
                                    path = itemVal;
                                    break;
                                case "udp-relay"_hash:
                                    udp = itemVal;
                                    break;
                                case "fast-open"_hash:
                                    tfo = itemVal;
                                    break;
                                case "tls13"_hash:
                                    tls13 = itemVal;
                                    break;
                                default:
                                    continue;
                            }
                        }
                        if (remarks.empty())
                            remarks = server + ":" + port;
                        switch (hash_(plugin)) {
                            case "simple-obfs"_hash:
                                pluginopts = "obfs=" + pluginopts_mode;
                                if (!pluginopts_host.empty())
                                    pluginopts += ";obfs-host=" + pluginopts_host;
                                break;
                            case "v2ray-plugin"_hash:
                                if (pluginopts_host.empty() && !isIPv4(server) && !isIPv6(server))
                                    pluginopts_host = server;
                                pluginopts = "mode=" + pluginopts_mode;
                                if (!pluginopts_host.empty())
                                    pluginopts += ";host=" + pluginopts_host;
                                if (!path.empty())
                                    pluginopts += ";path=" + path;
                                pluginopts += ";" + tls;
                                break;
                        }

                        if (!protocol.empty()) {
                            ssrConstruct(node, SSR_DEFAULT_GROUP, remarks, server, port, protocol, method,
                                         pluginopts_mode, password, pluginopts_host, protoparam, udp, tfo, scv);
                        } else {
                            ssConstruct(node, SS_DEFAULT_GROUP, remarks, server, port, password, method, plugin,
                                        pluginopts, udp, tfo, scv, tls13);
                        }
                        break;
                    case "vmess"_hash: //quantumult x style vmess link
                        server = trim(configs[0].substr(0, configs[0].rfind(":")));
                        port = trim(configs[0].substr(configs[0].rfind(":") + 1));
                        if (port == "0")
                            continue;
                        net = "tcp";

                        for (i = 1; i < configs.size(); i++) {
                            vArray = split(trim(configs[i]), "=");
                            if (vArray.size() != 2)
                                continue;
                            itemName = trim(vArray[0]);
                            itemVal = trim(vArray[1]);
                            switch (hash_(itemName)) {
                                case "method"_hash:
                                    method = itemVal;
                                    break;
                                case "password"_hash:
                                    id = itemVal;
                                    break;
                                case "tag"_hash:
                                    remarks = itemVal;
                                    break;
                                case "obfs"_hash:
                                    switch (hash_(itemVal)) {
                                        case "ws"_hash:
                                            net = "ws";
                                            break;
                                        case "over-tls"_hash:
                                            tls = "tls";
                                            break;
                                        case "wss"_hash:
                                            net = "ws";
                                            tls = "tls";
                                            break;
                                    }
                                    break;
                                case "obfs-host"_hash:
                                    host = itemVal;
                                    break;
                                case "obfs-uri"_hash:
                                    path = itemVal;
                                    break;
                                case "over-tls"_hash:
                                    tls = itemVal == "true" ? "tls" : "";
                                    break;
                                case "udp-relay"_hash:
                                    udp = itemVal;
                                    break;
                                case "fast-open"_hash:
                                    tfo = itemVal;
                                    break;
                                case "tls13"_hash:
                                    tls13 = itemVal;
                                    break;
                                case "aead"_hash:
                                    aead = itemVal == "true" ? "0" : "1";
                                default:
                                    continue;
                            }
                        }
                        if (remarks.empty())
                            remarks = server + ":" + port;

                        vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, server, port, "", id, aead, net, method,
                                       path, host, "", tls, "", std::vector<std::string>{}, udp, tfo, scv, tls13);
                        break;
                    case "vless"_hash: //quantumult x style vless link
                        server = trim(configs[0].substr(0, configs[0].rfind(":")));
                        port = trim(configs[0].substr(configs[0].rfind(":") + 1));
                        if (port == "0")
                            continue;
                        net = "tcp";

                        for (i = 1; i < configs.size(); i++) {
                            vArray = split(trim(configs[i]), "=");
                            if (vArray.size() != 2)
                                continue;
                            itemName = trim(vArray[0]);
                            itemVal = trim(vArray[1]);
                            switch (hash_(itemName)) {
                                case "method"_hash:
                                    method = itemVal;
                                    break;
                                case "password"_hash:
                                    id = itemVal;
                                    break;
                                case "tag"_hash:
                                    remarks = itemVal;
                                    break;
                                case "obfs"_hash:
                                    switch (hash_(itemVal)) {
                                        case "ws"_hash:
                                            net = "ws";
                                            break;
                                        case "over-tls"_hash:
                                            tls = "tls";
                                            break;
                                        case "wss"_hash:
                                            net = "ws";
                                            tls = "tls";
                                            break;
                                    }
                                    break;
                                case "obfs-host"_hash:
                                    host = itemVal;
                                    break;
                                case "obfs-uri"_hash:
                                    path = itemVal;
                                    break;
                                case "over-tls"_hash:
                                    tls = itemVal == "true" ? "tls" : "";
                                    break;
                                case "udp-relay"_hash:
                                    udp = itemVal;
                                    break;
                                case "fast-open"_hash:
                                    tfo = itemVal;
                                    break;
                                case "tls13"_hash:
                                    tls13 = itemVal;
                                    break;
                                case "aead"_hash:
                                    aead = itemVal == "true" ? "0" : "1";
                                default:
                                    continue;
                            }
                        }
                        if (remarks.empty())
                            remarks = server + ":" + port;
                        vlessConstruct(node, XRAY_DEFAULT_GROUP, remarks, server, port, "", id, aead, net, method,
                                       "chrome", "", path, host, "",
                                       tls, "", "", fp, sni, std::vector<std::string>{}, "", udp, tfo, scv, tls13);
                        break;
                    case "trojan"_hash: //quantumult x style trojan link
                        server = trim(configs[0].substr(0, configs[0].rfind(':')));
                        port = trim(configs[0].substr(configs[0].rfind(':') + 1));
                        if (port == "0")
                            continue;

                        for (i = 1; i < configs.size(); i++) {
                            vArray = split(trim(configs[i]), "=");
                            if (vArray.size() != 2)
                                continue;
                            itemName = trim(vArray[0]);
                            itemVal = trim(vArray[1]);
                            switch (hash_(itemName)) {
                                case "password"_hash:
                                    password = itemVal;
                                    break;
                                case "tag"_hash:
                                    remarks = itemVal;
                                    break;
                                case "over-tls"_hash:
                                    tls = itemVal;
                                    break;
                                case "tls-host"_hash:
                                    host = itemVal;
                                    sni = itemVal;
                                    break;
                                case "udp-relay"_hash:
                                    udp = itemVal;
                                    break;
                                case "fast-open"_hash:
                                    tfo = itemVal;
                                    break;
                                case "tls-verification"_hash:
                                    scv = itemVal == "false";
                                    break;
                                case "tls13"_hash:
                                    tls13 = itemVal;
                                    break;
                                case "fp"_hash:
                                    fp = itemVal;
                                    break;
                                default:
                                    continue;
                            }
                        }
                        if (remarks.empty())
                            remarks = server + ":" + port;

                        trojanConstruct(node, TROJAN_DEFAULT_GROUP, remarks, server, port, password, "", host, "", fp,
                                        sni, std::vector<std::string>{},
                                        tls == "true", udp, tfo, scv, tls13);
                        break;
                    case "http"_hash: //quantumult x style http links
                        server = trim(configs[0].substr(0, configs[0].rfind(':')));
                        port = trim(configs[0].substr(configs[0].rfind(':') + 1));
                        if (port == "0")
                            continue;

                        for (i = 1; i < configs.size(); i++) {
                            vArray = split(trim(configs[i]), "=");
                            if (vArray.size() != 2)
                                continue;
                            itemName = trim(vArray[0]);
                            itemVal = trim(vArray[1]);
                            switch (hash_(itemName)) {
                                case "username"_hash:
                                    username = itemVal;
                                    break;
                                case "password"_hash:
                                    password = itemVal;
                                    break;
                                case "tag"_hash:
                                    remarks = itemVal;
                                    break;
                                case "over-tls"_hash:
                                    tls = itemVal;
                                    break;
                                case "tls-verification"_hash:
                                    scv = itemVal == "false";
                                    break;
                                case "tls13"_hash:
                                    tls13 = itemVal;
                                    break;
                                case "fast-open"_hash:
                                    tfo = itemVal;
                                    break;
                                default:
                                    continue;
                            }
                        }
                        if (remarks.empty())
                            remarks = server + ":" + port;

                        if (username == "none")
                            username.clear();
                        if (password == "none")
                            password.clear();

                        httpConstruct(node, HTTP_DEFAULT_GROUP, remarks, server, port, username, password,
                                      tls == "true", tfo, scv, tls13);
                        break;
                    default:
                        continue;
                }
                break;
        }

        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
    return index;
}

void explodeSSTap(std::string sstap, std::vector<Proxy> &nodes) {
    std::string configType, group, remarks, server, port;
    std::string cipher;
    std::string user, pass;
    std::string protocol, protoparam, obfs, obfsparam;
    Document json;
    uint32_t index = nodes.size();
    json.Parse(sstap.data());
    if (json.HasParseError() || !json.IsObject())
        return;

    for (uint32_t i = 0; i < json["configs"].Size(); i++) {
        Proxy node;
        json["configs"][i]["group"] >> group;
        json["configs"][i]["remarks"] >> remarks;
        json["configs"][i]["server"] >> server;
        port = GetMember(json["configs"][i], "server_port");
        if (port == "0")
            continue;

        if (remarks.empty())
            remarks = server + ":" + port;

        json["configs"][i]["password"] >> pass;
        json["configs"][i]["type"] >> configType;
        switch (to_int(configType, 0)) {
            case 5: //socks 5
                json["configs"][i]["username"] >> user;
                socksConstruct(node, group, remarks, server, port, user, pass);
                break;
            case 6: //ss/ssr
                json["configs"][i]["protocol"] >> protocol;
                json["configs"][i]["obfs"] >> obfs;
                json["configs"][i]["method"] >> cipher;
                if (find(ss_ciphers.begin(), ss_ciphers.end(), cipher) != ss_ciphers.end() && protocol == "origin" &&
                    obfs == "plain") //is ss
                {
                    ssConstruct(node, group, remarks, server, port, pass, cipher, "", "");
                } else //is ssr cipher
                {
                    json["configs"][i]["obfsparam"] >> obfsparam;
                    json["configs"][i]["protocolparam"] >> protoparam;
                    ssrConstruct(node, group, remarks, server, port, protocol, cipher, obfs, pass, obfsparam,
                                 protoparam);
                }
                break;
            default:
                continue;
        }

        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeNetchConf(std::string netch, std::vector<Proxy> &nodes) {
    Document json;
    uint32_t index = nodes.size();

    json.Parse(netch.data());
    if (json.HasParseError() || !json.IsObject())
        return;

    if (!json.HasMember("Server"))
        return;

    for (uint32_t i = 0; i < json["Server"].Size(); i++) {
        Proxy node;
        explodeNetch("Netch://" + base64Encode(json["Server"][i] | SerializeObject()), node);

        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
}

int explodeConfContent(const std::string &content, std::vector<Proxy> &nodes) {
    ConfType filetype = ConfType::Unknow;

    const auto first_non_space = std::find_if_not(
        content.begin(), content.end(),
        [](unsigned char ch) { return std::isspace(ch) != 0; });
    if (first_non_space != content.end() && *first_non_space == '[') {
        rapidjson::Document structured_json;
        structured_json.Parse(content.c_str());
        const auto looks_like_ss_server = [](const rapidjson::Value &value) {
            return value.IsObject() && value.HasMember("server") &&
                   value.HasMember("server_port") && value.HasMember("method") &&
                   value.HasMember("password");
        };
        if (!structured_json.HasParseError() && structured_json.IsArray() &&
            std::any_of(structured_json.Begin(), structured_json.End(),
                        looks_like_ss_server))
            filetype = ConfType::SS;
    }

    if (filetype == ConfType::Unknow && strFind(content, "\"version\""))
        filetype = ConfType::SS;
    else if (strFind(content, "\"serverSubscribes\""))
        filetype = ConfType::SSR;
    else if (strFind(content, "\"uiItem\"") || strFind(content, "vnext"))
        filetype = ConfType::V2Ray;
    else if (strFind(content, "\"proxy_apps\""))
        filetype = ConfType::SSConf;
    else if (strFind(content, "\"idInUse\""))
        filetype = ConfType::SSTap;
    else if (strFind(content, "\"local_address\"") && strFind(content, "\"local_port\""))
        filetype = ConfType::SSR; //use ssr config parser
    else if (strFind(content, "\"ModeFileNameType\""))
        filetype = ConfType::Netch;

    switch (filetype) {
        case ConfType::SS:
            explodeSSConf(content, nodes);
            break;
        case ConfType::SSR:
            explodeSSRConf(content, nodes);
            break;
        case ConfType::V2Ray:
            explodeVmessConf(content, nodes);
            break;
        case ConfType::SSConf:
            explodeSSAndroid(content, nodes);
            break;
        case ConfType::SSTap:
            explodeSSTap(content, nodes);
            break;
        case ConfType::Netch:
            explodeNetchConf(content, nodes);
            break;
        default:
            //try to parse as a local subscription
            explodeSub(content, nodes);
    }

    return !nodes.empty();
}

void explodeSingboxTransport(rapidjson::Value &singboxNode, std::string &net, std::string &host, std::string &path,
                             std::string edge) {
    if (singboxNode.HasMember("transport") && singboxNode["transport"].IsObject()) {
        rapidjson::Value transport = singboxNode["transport"].GetObject();
        net = GetMember(transport, "type");
        switch (hash_(net)) {
            case "http"_hash: {
                host = GetMember(transport, "host");
                break;
            }
            case "ws"_hash: {
                path = GetMember(transport, "path");
                if (transport.HasMember("headers") && transport["headers"].IsObject()) {
                    rapidjson::Value headers = transport["headers"].GetObject();
                    host = GetMember(headers, "Host");
                    edge = GetMember(headers, "Edge");
                }
                break;
            }
            case "grpc"_hash: {
                path = GetMember(transport, "service_name");
                break;
            }
            default:
                net = "tcp";
                path.clear();
                break;
        }
    } else {
        net = "tcp";
        host.clear();
        edge.clear();
        path.clear();
    }
}

void explodeSingbox(rapidjson::Value &outbounds, std::vector<Proxy> &nodes) {
    uint32_t index = nodes.size();
    for (rapidjson::SizeType i = 0; i < outbounds.Size(); ++i) {
        if (outbounds[i].IsObject()) {
            std::string proxytype, ps, server, port, cipher, group, password, ports, tempPassword; //common
            std::string type = "none", id, aid = "0", net = "tcp", path, host, edge, tls, sni; //vmess
            std::string fp = "chrome", pbk, sid, packet_encoding; //vless
            std::string plugin, pluginopts, pluginopts_mode, pluginopts_host, pluginopts_mux; //ss
            std::string protocol, protoparam, obfs, obfsparam; //ssr
            std::string flow, mode; //trojan
            std::string user; //socks
            std::string ip, ipv6, private_key, public_key, mtu; //wireguard
            std::string auth, up, down, obfsParam, insecure, alpn; //hysteria
            std::string obfsPassword; //hysteria2
            string_array dns_server;
            std::string fingerprint;
            std::string congestion_control, udp_relay_mode; //quic
            tribool udp, tfo, scv, rrt, disableSni;
            uint16_t idle_check = 30, idle_timeout = 30, min_idle = 0;
            rapidjson::Value singboxNode = outbounds[i].GetObject();
            if (singboxNode.HasMember("type") && singboxNode["type"].IsString()) {
                Proxy node;
                proxytype = singboxNode["type"].GetString();
                ps = GetMember(singboxNode, "tag");
                server = GetMember(singboxNode, "server");
                port = GetMember(singboxNode, "server_port");
                tfo = GetMember(singboxNode, "tcp_fast_open");
                std::vector<std::string> alpnList;
                if (singboxNode.HasMember("tls") && singboxNode["tls"].IsObject()) {
                    rapidjson::Value tlsObj = singboxNode["tls"].GetObject();
                    if (tlsObj.HasMember("enabled") && tlsObj["enabled"].IsBool() && tlsObj["enabled"].GetBool()) {
                        tls = "tls";
                    }
                    sni = GetMember(tlsObj, "server_name");
                    if (tlsObj.HasMember("alpn") && tlsObj["alpn"].IsArray() && !tlsObj["alpn"].Empty()) {
                        rapidjson::Value alpns = tlsObj["alpn"].GetArray();
                        if (alpns.Size() > 0) {
                            alpn = alpns[0].GetString();
                            for (auto &item: tlsObj["alpn"].GetArray()) {
                                if (item.IsString())
                                    alpnList.emplace_back(item.GetString());
                            }
                        }
                    }
                    if (tlsObj.HasMember("insecure") && tlsObj["insecure"].IsBool()) {
                        scv = tlsObj["insecure"].GetBool();
                    }
                    if (tlsObj.HasMember("disable_sni") && tlsObj["disable_sni"].IsBool()) {
                        disableSni = tlsObj["disable_sni"].GetBool();
                    }
                    if (tlsObj.HasMember("certificate") && tlsObj["certificate"].IsString()) {
                        public_key = tlsObj["certificate"].GetString();
                    }
                    if (tlsObj.HasMember("reality") && tlsObj["reality"].IsObject()) {
                        tls = "reality";
                        rapidjson::Value reality = tlsObj["reality"].GetObject();
                        if (reality.HasMember("server_name") && reality["server_name"].IsString()) {
                            host = reality["server_name"].GetString();
                        }
                        if (reality.HasMember("public_key") && reality["public_key"].IsString()) {
                            pbk = reality["public_key"].GetString();
                        }
                        if (reality.HasMember("short_id") && reality["short_id"].IsString()) {
                            sid = reality["short_id"].GetString();
                        }
                    }
                    if (tlsObj.HasMember("utls") && tlsObj["utls"].IsObject()) {
                        if (rapidjson::Value reality = tlsObj["utls"].GetObject();
                            reality.HasMember("fingerprint") && reality["fingerprint"].IsString()) {
                            fingerprint = reality["fingerprint"].GetString();
                        }
                    }
                } else {
                    tls = "false";
                }
                switch (hash_(proxytype)) {
                    case "vmess"_hash:
                        group = V2RAY_DEFAULT_GROUP;
                        id = GetMember(singboxNode, "uuid");
                        if (id.length() < 36) {
                            break;
                        }
                        aid = GetMember(singboxNode, "alter_id");
                        cipher = GetMember(singboxNode, "security");
                        explodeSingboxTransport(singboxNode, net, host, path, edge);
                        vmessConstruct(node, group, ps, server, port, "", id, aid, net, cipher, path, host, edge, tls,
                                       sni, alpnList, udp,
                                       tfo, scv);
                        break;
                    case "shadowsocks"_hash:
                        group = SS_DEFAULT_GROUP;
                        cipher = GetMember(singboxNode, "method");
                        password = GetMember(singboxNode, "password");
                        plugin = GetMember(singboxNode, "plugin");
                        pluginopts = GetMember(singboxNode, "plugin_opts");
                        ssConstruct(node, group, ps, server, port, password, cipher, plugin, pluginopts, udp, tfo, scv);
                        break;
                    case "trojan"_hash:
                        group = TROJAN_DEFAULT_GROUP;
                        password = GetMember(singboxNode, "password");
                        explodeSingboxTransport(singboxNode, net, host, path, edge);
                        trojanConstruct(node, group, ps, server, port, password, net, host, path, fp, sni, alpnList,
                                        true, udp,
                                        tfo,
                                        scv);
                        break;
                    case "vless"_hash:
                        group = XRAY_DEFAULT_GROUP;
                        id = GetMember(singboxNode, "uuid");
                        flow = GetMember(singboxNode, "flow");
                        packet_encoding = GetMember(singboxNode, "packet_encoding");
                        if (singboxNode.HasMember("transport") && singboxNode["transport"].IsObject()) {
                            rapidjson::Value transport = singboxNode["transport"].GetObject();
                            net = GetMember(transport, "type");
                            switch (hash_(net)) {
                                case "tcp"_hash: {
                                    break;
                                }
                                case "ws"_hash: {
                                    path = GetMember(transport, "path");
                                    if (transport.HasMember("headers") && transport["headers"].IsObject()) {
                                        rapidjson::Value headers = transport["headers"].GetObject();
                                        host = GetMember(headers, "Host");
                                        edge = GetMember(headers, "Edge");
                                    }
                                    break;
                                }
                                case "http"_hash: {
                                    host = GetMember(transport, "host");
                                    path = GetMember(transport, "path");
                                    edge.clear();
                                    break;
                                }
                                case "httpupgrade"_hash: {
                                    net = "httpupgrade";
                                    host = GetMember(transport, "host");
                                    path = GetMember(transport, "path");
                                    edge.clear();
                                    break;
                                }
                                case "grpc"_hash: {
                                    host = server;
                                    path = GetMember(transport, "service_name");
                                    break;
                                }
                            }
                        }

                        vlessConstruct(node, group, ps, server, port, type, id, aid, net, "auto", flow, mode, path,
                                       host, "", tls, pbk, sid, fp, sni, alpnList, packet_encoding, udp);
                        break;
                    case "http"_hash:
                        password = GetMember(singboxNode, "password");
                        user = GetMember(singboxNode, "username");
                        httpConstruct(node, group, ps, server, port, user, password, tls == "tls", tfo, scv);
                        break;
                    case "wireguard"_hash:
                        group = WG_DEFAULT_GROUP;
                        ip = GetMember(singboxNode, "inet4_bind_address");
                        ipv6 = GetMember(singboxNode, "inet6_bind_address");
                        public_key = GetMember(singboxNode, "private_key");
                        private_key = GetMember(singboxNode, "public_key");
                        mtu = GetMember(singboxNode, "mtu");
                        password = GetMember(singboxNode, "pre_shared_key");
                        dns_server = {"8.8.8.8"};
                        wireguardConstruct(node, group, ps, server, port, ip, ipv6, private_key, public_key, password,
                                           dns_server, mtu, "0", "", "", udp, "");
                        break;
                    case "socks"_hash:
                        group = SOCKS_DEFAULT_GROUP;
                        user = GetMember(singboxNode, "username");
                        password = GetMember(singboxNode, "password");
                        socksConstruct(node, group, ps, server, port, user, password);
                        break;
                    case "hysteria"_hash:
                        group = HYSTERIA_DEFAULT_GROUP;
                        up = GetMember(singboxNode, "up");
                        if (up.empty()) {
                            up = GetMember(singboxNode, "up_mbps");
                        }
                        down = GetMember(singboxNode, "down");
                        if (down.empty()) {
                            down = GetMember(singboxNode, "down_mbps");
                        }
                        auth = GetMember(singboxNode, "auth_str");
                        type = GetMember(singboxNode, "network");
                        obfsParam = GetMember(singboxNode, "obfs");
                        hysteriaConstruct(node, group, ps, server, port, type, auth, "", host, up, down, alpn,
                                          obfsParam, insecure, ports, sni,
                                          udp, tfo, scv);
                        break;
                    case "anytls"_hash:
                        group = ANYTLS_DEFAULT_GROUP;
                        password = GetMember(singboxNode, "password");
                        idle_check = parseUint16Option(
                            GetMember(singboxNode, "idle_session_check_interval"), 30, true);
                        idle_timeout = parseUint16Option(
                            GetMember(singboxNode, "idle_session_timeout"), 30, true);
                        min_idle = parseUint16Option(
                            GetMember(singboxNode, "min_idle_session"), 0);
                        anyTlSConstruct(node, ANYTLS_DEFAULT_GROUP, ps, port, password, server, alpnList, fingerprint,
                                        sni,
                                        udp,
                                        tribool(), scv, tribool(), "", idle_check, idle_timeout, min_idle);
                        break;
                    case "hysteria2"_hash:
                        group = HYSTERIA2_DEFAULT_GROUP;
                        password = GetMember(singboxNode, "password");
                        up = GetMember(singboxNode, "up");
                        if (up.empty())
                            up = GetMember(singboxNode, "up_mbps");
                        down = GetMember(singboxNode, "down");
                        if (down.empty())
                            down = GetMember(singboxNode, "down_mbps");
                        if (singboxNode.HasMember("server_ports") && singboxNode["server_ports"].IsArray()) {
                            string_array port_ranges;
                            bool valid_port_ranges = true;
                            for (const auto &item : singboxNode["server_ports"].GetArray()) {
                                if (!item.IsString()) {
                                    valid_port_ranges = false;
                                    break;
                                }
                                std::string range =
                                    replaceAllDistinct(item.GetString(), ":", "-");
                                uint16_t first_port = 0;
                                std::string remaining;
                                if (!validHysteria2PortToken(
                                        range, first_port, remaining)) {
                                    valid_port_ranges = false;
                                    break;
                                }
                                port_ranges.emplace_back(std::move(range));
                            }
                            if (!valid_port_ranges || port_ranges.empty())
                                continue;
                            ports = join(port_ranges, ",");
                            uint16_t first_port = 0;
                            std::string remaining;
                            validHysteria2PortToken(port_ranges.front(),
                                                   first_port, remaining);
                            port = std::to_string(first_port);
                        }
                        if (singboxNode.HasMember("obfs") && singboxNode["obfs"].IsObject()) {
                            rapidjson::Value obfsOpt = singboxNode["obfs"].GetObject();
                            obfsParam = GetMember(obfsOpt, "type");
                            obfsPassword = GetMember(obfsOpt, "password");
                        }
                        hysteria2Construct(node, group, ps, server, port, password, host, up, down, alpn, obfsParam,
                                           obfsPassword, sni, public_key, ports, udp, tfo, scv);
                        break;
                    case "tuic"_hash:
                        group = TUIC_DEFAULT_GROUP;
                        password = GetMember(singboxNode, "password");
                        id = GetMember(singboxNode, "uuid");
                        congestion_control = GetMember(singboxNode, "congestion_control");
                        if (singboxNode.HasMember("zero_rtt_handshake") && singboxNode["zero_rtt_handshake"].IsBool()) {
                            rrt = singboxNode["zero_rtt_handshake"].GetBool();
                        }
                        udp_relay_mode = GetMember(singboxNode, "udp_relay_mode");
                        tuicConstruct(node, TUIC_DEFAULT_GROUP, ps, server, port, password, congestion_control, alpn,
                                      sni, id, udp_relay_mode, "",
                                      tribool(),
                                      tribool(), scv, rrt, disableSni);
                        break;
                    default:
                        continue;
                }
                node.Id = index;
                nodes.emplace_back(std::move(node));
                index++;
            }
        }
    }
}

void explodeTuic(const std::string &tuic, Proxy &node) {
    ParsedShareUri parsed;
    std::string ignored_ports;
    if (!parseModernShareUri(tuic, "tuic", true, "", false, parsed, ignored_ports))
        return;

    std::string uuid, password, token;
    const size_t credential_separator = parsed.user.find(':');
    if (credential_separator == std::string::npos) {
        token = parsed.user;
    } else {
        uuid = parsed.user.substr(0, credential_separator);
        password = parsed.user.substr(credential_separator + 1);
        if (!isXrayUuid(uuid) || password.empty())
            return;
    }
    const std::string query_token = decodedUrlArg(parsed.query, "token");
    if (!query_token.empty())
        token = query_token;
    if (parsed.remark.empty())
        parsed.remark = parsed.host + ":" + parsed.port;

    std::string udp_relay_mode = decodedFirstUrlArg(parsed.query, {"udp_relay_mode", "udp-relay-mode"});
    if (udp_relay_mode.empty())
        udp_relay_mode = "native";
    std::string insecure = decodedFirstUrlArg(parsed.query, {"insecure", "allow_insecure", "allow-insecure"});
    std::string reduce_rtt = decodedFirstUrlArg(parsed.query,
                                                {"zero_rtt_handshake", "zero-rtt-handshake", "reduce_rtt", "reduce-rtt"});
    std::string disable_sni = decodedFirstUrlArg(parsed.query, {"disable_sni", "disable-sni"});
    const uint16_t request_timeout = parseUint16Option(
        decodedFirstUrlArg(parsed.query, {"request_timeout", "request-timeout"}), 15000);

    tuicConstruct(node, TUIC_DEFAULT_GROUP, parsed.remark, parsed.host, parsed.port, password,
                  decodedFirstUrlArg(parsed.query, {"congestion_control", "congestion-controller"}),
                  decodedUrlArg(parsed.query, "alpn"), decodedUrlArg(parsed.query, "sni"), uuid,
                  udp_relay_mode, token, tribool(), tribool(), tribool(insecure), tribool(reduce_rtt),
                  tribool(disable_sni), request_timeout);
}

void explodeAnyTLS(std::string anytls, Proxy &node) {
    ParsedShareUri parsed;
    std::string ignored_ports;
    if (!parseModernShareUri(std::move(anytls), "anytls", true, "443", false, parsed, ignored_ports))
        return;
    if (parsed.remark.empty())
        parsed.remark = parsed.host + ":" + parsed.port;

    const uint16_t idle_check = parseUint16Option(
        decodedFirstUrlArg(parsed.query, {"idle_session_check_interval", "idle-session-check-interval"}), 30, true);
    const uint16_t idle_timeout = parseUint16Option(
        decodedFirstUrlArg(parsed.query, {"idle_session_timeout", "idle-session-timeout"}), 30, true);
    const uint16_t min_idle = parseUint16Option(
        decodedFirstUrlArg(parsed.query, {"min_idle_session", "min-idle-session"}), 0);
    const std::string insecure = decodedFirstUrlArg(parsed.query, {"insecure", "allow_insecure", "allow-insecure"});

    anyTlSConstruct(node, ANYTLS_DEFAULT_GROUP, parsed.remark, parsed.port, parsed.user, parsed.host,
                    getUrlAlpnList(parsed.query), decodedFirstUrlArg(parsed.query, {"fp", "fingerprint"}),
                    decodedUrlArg(parsed.query, "sni"), tribool(decodedUrlArg(parsed.query, "udp")),
                    tribool(decodedUrlArg(parsed.query, "tfo")), tribool(insecure), tribool(), "",
                    idle_check, idle_timeout, min_idle);
}

void explode(const std::string &link, Proxy &node) {
    if (startsWith(link, "ssr://"))
        explodeSSR(link, node);
    else if (startsWith(link, "vmess://") || startsWith(link, "vmess1://"))
        explodeVmess(link, node);
    else if (startsWith(link, "ss://"))
        explodeSS(link, node);
    else if (startsWith(link, "socks://") || startsWith(link, "https://t.me/socks") ||
             startsWith(link, "tg://socks"))
        explodeSocks(link, node);
    else if (startsWith(link, "https://t.me/http") || startsWith(link, "tg://http")) //telegram style http link
        explodeHTTP(link, node);
    else if (startsWith(link, "Netch://"))
        explodeNetch(link, node);
    else if (startsWith(link, "trojan://") || startsWith(link, "trojan-go://"))
        explodeTrojan(link, node);
    else if (strFind(link, "vless://") || strFind(link, "vless1://"))
        explodeVless(link, node);
    else if (strFind(link, "hysteria://") || strFind(link, "hy://"))
        explodeHysteria(link, node);
    else if (strFind(link, "tuic://"))
        explodeTuic(link, node);
    else if (strFind(link, "anytls://"))
        explodeAnyTLS(link, node);
    else if (strFind(link, "hysteria2://") || strFind(link, "hy2://"))
        explodeHysteria2(link, node);
    else if (strFind(link, "mierus://") || strFind(link, "mieru://"))
        explodeMierus(link, node);
    else if (isLink(link))
        explodeHTTPSub(link, node);
}

void explodeSub(std::string sub, std::vector<Proxy> &nodes) {
    std::stringstream strstream;
    std::string strLink;
    bool processed = false;

    //try to parse as SSD configuration
    if (startsWith(sub, "ssd://")) {
        explodeSSD(sub, nodes);
        processed = true;
    }

    //try to parse as clash configuration
    try {
        if (!processed && regFind(sub, "\"?(Proxy|proxies)\"?:")) {
            regGetMatch(sub, R"(^(?:Proxy|proxies):$\s(?:(?:^ +?.*$| *?-.*$|)\s?)+)", 1, &sub);
            Node yamlnode = Load(sub);
            if (yamlnode.size() && (yamlnode["Proxy"].IsDefined() || yamlnode["proxies"].IsDefined())) {
                explodeClash(yamlnode, nodes);
                processed = true;
            }
        }
    } catch (std::exception &e) {
        //writeLog(LOG_LEVEL_DEBUG, e.what());
        //ignore
        throw;
    }
    try {
        std::string pattern = "\"?(inbounds)\"?:";
        if (!processed &&
            regFind(sub, pattern)) {
            pattern = "\"?(outbounds)\"?:";
            if (regFind(sub, pattern)) {
                pattern = "\"?(route)\"?:";
                if (regFind(sub, pattern)) {
                    rapidjson::Document document;
                    document.Parse(sub.c_str());
                    if (!document.HasParseError() || document.IsObject()) {
                        rapidjson::Value &value = document["outbounds"];
                        if (value.IsArray() && !value.Empty()) {
                            explodeSingbox(value, nodes);
                            processed = true;
                        }
                    }
                }
            }
        }
    } catch (std::exception &e) {
        writeLog(LOG_LEVEL_ERROR,
                 "SINGBOX_PARSE_FAILED detail=" +
                     summarizeSensitiveTextForLog(e.what()));
        //writeLog(LOG_LEVEL_DEBUG, e.what());
        //ignore
        throw;
    }
    //try to parse as surge configuration
    if (!processed && explodeSurge(sub, nodes)) {
        processed = true;
    }

    //try to parse as normal subscription
    if (!processed) {
        sub = urlSafeBase64Decode(sub);
        if (regFind(sub, "(vmess|shadowsocks|http|trojan)\\s*?=")) {
            if (explodeSurge(sub, nodes))
                return;
        }
        strstream << sub;
        char delimiter =
                count(sub.begin(), sub.end(), '\n') < 1 ? count(sub.begin(), sub.end(), '\r') < 1 ? ' ' : '\r' : '\n';
        while (getline(strstream, strLink, delimiter)) {
            Proxy node;
            if (strLink.rfind('\r') != std::string::npos)
                strLink.erase(strLink.size() - 1);
            explode(strLink, node);
            if (strLink.empty() || node.Type == ProxyType::Unknown) {
                continue;
            }
            nodes.emplace_back(std::move(node));
        }
    }
}
