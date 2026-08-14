#include <algorithm>
#include <atomic>
#include <cctype>
#include <initializer_list>
#include <limits>
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
#include "mieru_uri.h"
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

std::string nextMieruSourceId() {
    static std::atomic<uint64_t> next_id{1};
    return std::to_string(next_id.fetch_add(1, std::memory_order_relaxed));
}

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

bool validHysteriaUriMbps(const std::string &value) {
    if (value.empty() ||
        !std::all_of(value.begin(), value.end(), [](unsigned char ch) {
            return std::isdigit(ch) != 0;
        }))
        return false;
    try {
        const unsigned long long parsed = std::stoull(value);
        return parsed > 0 &&
               parsed <= static_cast<unsigned long long>(
                             std::numeric_limits<int>::max());
    } catch (const std::exception &) {
        return false;
    }
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

bool normalizeHysteriaPortSpec(const std::string &value,
                               std::string &normalized,
                               uint16_t &first_port) {
    string_array normalized_ranges;
    first_port = 0;
    for (std::string range : split(value, ",")) {
        range = trim(range);
        if (range.empty())
            return false;
        if (range.find(':') != std::string::npos) {
            if (range.find(':') != range.rfind(':'))
                return false;
            range[range.find(':')] = '-';
        }
        uint16_t range_first = 0;
        std::string ignored_remaining;
        if (!validHysteria2PortToken(range, range_first, ignored_remaining))
            return false;
        if (normalized_ranges.empty())
            first_port = range_first;
        normalized_ranges.emplace_back(std::move(range));
    }
    if (normalized_ranges.empty())
        return false;
    normalized = join(normalized_ranges, ",");
    return true;
}

bool normalizeHysteriaProtocol(std::string &protocol) {
    protocol = toLower(trim(protocol));
    if (protocol.empty())
        protocol = "udp";
    return protocol == "udp" || protocol == "wechat-video" ||
           protocol == "faketcp";
}

bool normalizeHysteriaNetwork(std::string &network) {
    network = toLower(trim(network));
    return network.empty() || network == "tcp" || network == "udp";
}

bool validHysteriaHopInterval(const std::string &interval) {
    return interval.empty() ||
           regMatch(interval, R"(^([1-9][0-9]*(?:ns|us|ms|s|m|h))+$)");
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

std::string stripWireGuardQuotes(std::string value) {
    value = trim(value);
    if (value.size() >= 2 &&
        ((value.front() == '"' && value.back() == '"') ||
         (value.front() == '\'' && value.back() == '\'')))
        value = value.substr(1, value.size() - 2);
    return trim(value);
}

std::vector<std::string> splitWireGuardFields(const std::string &value) {
    std::vector<std::string> result;
    size_t start = 0;
    int round_depth = 0, square_depth = 0, brace_depth = 0;
    char quote = 0;
    bool escaped = false;
    for (size_t i = 0; i < value.size(); ++i) {
        const char ch = value[i];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (quote != 0) {
            if (ch == '\\')
                escaped = true;
            else if (ch == quote)
                quote = 0;
            continue;
        }
        if (ch == '"' || ch == '\'') {
            quote = ch;
            continue;
        }
        switch (ch) {
            case '(': ++round_depth; break;
            case ')': --round_depth; break;
            case '[': ++square_depth; break;
            case ']': --square_depth; break;
            case '{': ++brace_depth; break;
            case '}': --brace_depth; break;
            case ',':
                if (round_depth == 0 && square_depth == 0 && brace_depth == 0) {
                    result.emplace_back(trim(value.substr(start, i - start)));
                    start = i + 1;
                }
                break;
            default: break;
        }
        if (round_depth < 0 || square_depth < 0 || brace_depth < 0)
            return {};
    }
    if (quote != 0 || round_depth != 0 || square_depth != 0 || brace_depth != 0)
        return {};
    result.emplace_back(trim(value.substr(start)));
    return result;
}

bool parseWireGuardEndpoint(std::string endpoint, std::string &host,
                            uint16_t &port) {
    endpoint = stripWireGuardQuotes(std::move(endpoint));
    std::string port_text;
    if (endpoint.size() > 2 && endpoint.front() == '[') {
        const size_t bracket = endpoint.find(']');
        if (bracket == std::string::npos || bracket + 2 >= endpoint.size() ||
            endpoint[bracket + 1] != ':')
            return false;
        host = endpoint.substr(1, bracket - 1);
        port_text = endpoint.substr(bracket + 2);
    } else {
        const size_t colon = endpoint.rfind(':');
        if (colon == std::string::npos || colon == 0 || colon + 1 >= endpoint.size())
            return false;
        host = endpoint.substr(0, colon);
        port_text = endpoint.substr(colon + 1);
    }
    if (!validSharePort(port_text) || host.find_first_of("\r\n") != std::string::npos)
        return false;
    port = static_cast<uint16_t>(to_int(port_text, 0));
    return !host.empty();
}

std::string normalizeWireGuardAllowedIPs(const std::string &value) {
    string_array networks;
    for (std::string network : split(value, ",")) {
        network = trim(network);
        if (network.empty())
            return {};
        const size_t slash = network.find('/');
        const std::string address = slash == std::string::npos
                                        ? network
                                        : network.substr(0, slash);
        const bool ipv4 = isIPv4(address);
        const bool ipv6 = isIPv6(address);
        if (!ipv4 && !ipv6)
            return {};
        if (slash == std::string::npos) {
            network += ipv6 ? "/128" : "/32";
        } else {
            const std::string prefix = network.substr(slash + 1);
            if (prefix.empty() ||
                !std::all_of(prefix.begin(), prefix.end(), [](unsigned char ch) {
                    return std::isdigit(ch) != 0;
                }))
                return {};
            const int bits = to_int(prefix, -1);
            if (bits < 0 || bits > (ipv6 ? 128 : 32))
                return {};
        }
        networks.emplace_back(std::move(network));
    }
    return join(networks, ", ");
}

bool validWireGuardPeer(const WireGuardPeer &peer) {
    return !peer.Hostname.empty() && peer.Port > 0 && !peer.PublicKey.empty() &&
           !peer.AllowedIPs.empty();
}

std::string normalizeWireGuardReserved(std::string value) {
    value = replaceAllDistinct(stripWireGuardQuotes(std::move(value)), "/", ",");
    string_array bytes;
    for (std::string item : split(value, ",")) {
        item = trim(item);
        if (item.empty() || item.size() > 3 ||
            !std::all_of(item.begin(), item.end(), [](unsigned char ch) {
                return std::isdigit(ch) != 0;
            }))
            return {};
        const int byte = to_int(item, -1);
        if (byte < 0 || byte > 255)
            return {};
        bytes.emplace_back(std::to_string(byte));
    }
    return join(bytes, ",");
}

void syncLegacyWireGuardProjection(Proxy &node) {
    if (node.WireGuardLocalAddresses.empty()) {
        if (!node.SelfIP.empty())
            node.WireGuardLocalAddresses.emplace_back(node.SelfIP);
        if (!node.SelfIPv6.empty())
            node.WireGuardLocalAddresses.emplace_back(node.SelfIPv6);
    }
    if (node.WireGuardPeers.empty()) {
        WireGuardPeer peer;
        peer.Hostname = node.Hostname;
        peer.Port = node.Port;
        peer.PublicKey = node.PublicKey;
        peer.PreSharedKey = node.PreSharedKey;
        peer.AllowedIPs = node.AllowedIPs;
        peer.Reserved = node.ClientId;
        peer.KeepAlive = node.KeepAlive;
        if (validWireGuardPeer(peer))
            node.WireGuardPeers.emplace_back(std::move(peer));
    }
    if (!node.WireGuardPeers.empty()) {
        const WireGuardPeer &peer = node.WireGuardPeers.front();
        node.Hostname = peer.Hostname;
        node.Port = peer.Port;
        node.PublicKey = peer.PublicKey;
        node.PreSharedKey = peer.PreSharedKey;
        node.AllowedIPs = peer.AllowedIPs;
        node.ClientId = peer.Reserved;
        node.KeepAlive = peer.KeepAlive;
    }
}

std::vector<std::string> jsonStringArray(const rapidjson::Value &value) {
    std::vector<std::string> result;
    if (value.IsString()) {
        result.emplace_back(value.GetString());
        return result;
    }
    if (!value.IsArray())
        return result;
    for (const auto &item : value.GetArray()) {
        std::string text;
        item >> text;
        if (!text.empty())
            result.emplace_back(std::move(text));
    }
    return result;
}

std::string jsonWireGuardReserved(const rapidjson::Value &value) {
    if (value.IsArray())
        return normalizeWireGuardReserved(join(jsonStringArray(value), ","));
    std::string result;
    value >> result;
    return normalizeWireGuardReserved(std::move(result));
}

WireGuardPeer parseSingBoxWireGuardPeer(const rapidjson::Value &value,
                                        bool endpoint_schema) {
    WireGuardPeer peer;
    if (!value.IsObject())
        return peer;
    peer.Hostname = GetMember(value, endpoint_schema ? "address" : "server");
    peer.Port = parseUint16Option(
        GetMember(value, endpoint_schema ? "port" : "server_port"), 0);
    peer.PublicKey = GetMember(value, "public_key");
    peer.PreSharedKey = GetMember(value, "pre_shared_key");
    if (value.HasMember("allowed_ips"))
        peer.AllowedIPs = normalizeWireGuardAllowedIPs(
            join(jsonStringArray(value["allowed_ips"]), ", "));
    if (value.HasMember("reserved"))
        peer.Reserved = jsonWireGuardReserved(value["reserved"]);
    std::string keepalive = GetMember(value, "persistent_keepalive_interval");
    if (!keepalive.empty() && keepalive.back() == 's')
        keepalive.pop_back();
    peer.KeepAlive = parseUint16Option(keepalive, 0);
    return peer;
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
                    const std::string &host, const std::string &obfs_uri, uint16_t version,
                    tribool reuse, tribool udp, tribool tfo, tribool scv,
                    const std::string &underlying_proxy) {
    commonConstruct(node, ProxyType::Snell, group, remarks, server, port, udp, tfo, scv, tribool(), underlying_proxy);
    node.Password = password;
    node.OBFS = obfs;
    node.Host = host;
    node.Path = obfs_uri;
    node.SnellVersion = version;
    node.SnellReuse = reuse;
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
    node.Mtu = parseUint16Option(mtu, 0);
    node.KeepAlive = parseUint16Option(keepalive, 0);
    node.TestUrl = testUrl;
    node.ClientId = normalizeWireGuardReserved(clientId);
    syncLegacyWireGuardProjection(node);
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

void naiveConstruct(Proxy &node, const std::string &group,
                    const std::string &remarks, const std::string &port,
                    const std::string &username,
                    const std::string &password, const std::string &host,
                    const std::vector<String> &alpn_list,
                    const std::string &fingerprint,
                    const std::string &sni, tribool scv,
                    bool quic, uint32_t insecure_concurrency) {
    commonConstruct(node, ProxyType::Naive, group, remarks, host, port,
                    tribool(), tribool(), scv, tribool(), "");
    node.Username = username;
    node.Password = password;
    node.TLSSecure = true;
    node.TLSStr = "tls";
    node.ServerName = sni;
    node.SNI = sni;
    node.AlpnList = alpn_list;
    node.Fingerprint = fingerprint;
    node.NaiveQuic = quic;
    node.NaiveInsecureConcurrency = insecure_concurrency;
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

    bool has_legacy_metadata = false;
    if (query_start != std::string::npos) {
        for (const std::string &item : split(link.substr(query_start + 1), "&")) {
            if (item.empty())
                continue;
            const size_t equals = item.find('=');
            const std::string key = item.substr(0, equals);
            if (key != "remarks" && key != "group")
                return false;
            has_legacy_metadata = true;
        }
    }

    Proxy candidate;
    explodeHTTPSub(link, candidate);
    if ((candidate.Type == ProxyType::HTTP || candidate.Type == ProxyType::HTTPS) &&
        !candidate.Hostname.empty() && candidate.Port != 0)
        return true;

    // A no-path HTTP(S) URI carrying only the legacy remarks/group metadata is
    // still a direct-node candidate when its Base64 payload is malformed. Keep
    // it on the local parser path so it fails closed instead of being fetched as
    // a remote subscription.
    return has_legacy_metadata;
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
    if (!startsWith(mierus, "mierus://"))
        return;
    std::vector<Proxy> parsed_nodes;
    explodeMierusNodes(mierus, parsed_nodes);
    if (parsed_nodes.size() == 1)
        node = std::move(parsed_nodes.front());
}

void explodeHysteria(std::string hysteria, Proxy &node) {
    writeLog(LOG_LEVEL_DEBUG, "正在解析 Hysteria 节点。");
    if (startsWith(hysteria, "hy://"))
        hysteria.replace(0, 5, "hysteria://");
    explodeStdHysteria(std::move(hysteria), node);
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

namespace {

std::string firstNetchMember(const rapidjson::Value &value,
                             std::initializer_list<const char *> keys) {
    for (const char *key : keys) {
        const std::string result = GetMember(value, key);
        if (!result.empty())
            return result;
    }
    return {};
}

std::string normalizeNetchTLS(const rapidjson::Value &value,
                              const std::string &fallback = {}) {
    std::string tls = toLower(trim(firstNetchMember(
        value, {"TLSSecureType", "TLSSecure", "Security"})));
    if (tls.empty())
        return fallback;
    if (tls == "true" || tls == "1")
        return "tls";
    if (tls == "false" || tls == "0")
        return "none";
    return tls;
}

bool parseNetchNode(const rapidjson::Value &json, Proxy &node) {
    if (!json.IsObject())
        return false;

    const std::string type = toLower(trim(GetMember(json, "Type")));
    std::string group = GetMember(json, "Group");
    std::string remark = GetMember(json, "Remark");
    const std::string address = trim(GetMember(json, "Hostname"));
    const std::string port = GetMember(json, "Port");
    if (type.empty() || address.empty() ||
        address.find_first_of("\r\n") != std::string::npos ||
        !validSharePort(port))
        return false;

    const tribool udp(GetMember(json, "EnableUDP"));
    const tribool tfo(GetMember(json, "EnableTFO"));
    const tribool scv(GetMember(json, "AllowInsecure"));
    const std::string password = GetMember(json, "Password");
    const std::string method = GetMember(json, "EncryptMethod");
    const std::string fingerprint = firstNetchMember(
        json, {"FingerPrint", "Fingerprint"});
    if (remark.empty())
        remark = address + ":" + port;

    if (type == "ss") {
        if (method.empty() || password.empty())
            return false;
        if (group.empty())
            group = SS_DEFAULT_GROUP;
        ssConstruct(node, group, remark, address, port, password, method,
                    GetMember(json, "Plugin"), GetMember(json, "PluginOption"),
                    udp, tfo, scv);
    } else if (type == "ssr") {
        const std::string protocol = GetMember(json, "Protocol");
        const std::string obfs = GetMember(json, "OBFS");
        if (method.empty() || password.empty())
            return false;
        if (find(ss_ciphers.begin(), ss_ciphers.end(), method) != ss_ciphers.end() &&
            (obfs.empty() || obfs == "plain") &&
            (protocol.empty() || protocol == "origin")) {
            if (group.empty())
                group = SS_DEFAULT_GROUP;
            ssConstruct(node, group, remark, address, port, password, method,
                        GetMember(json, "Plugin"), GetMember(json, "PluginOption"),
                        udp, tfo, scv);
        } else {
            if (protocol.empty() || obfs.empty())
                return false;
            if (group.empty())
                group = SSR_DEFAULT_GROUP;
            ssrConstruct(node, group, remark, address, port, protocol, method,
                         obfs, password, GetMember(json, "OBFSParam"),
                         GetMember(json, "ProtocolParam"), udp, tfo, scv);
        }
    } else if (type == "vmess" || type == "vless") {
        std::string transport = normalizeXrayTransport(
            GetMember(json, "TransferProtocol"));
        const std::string fake_type = GetMember(json, "FakeType");
        const std::string regular_host = GetMember(json, "Host");
        const std::string regular_path = GetMember(json, "Path");
        const std::string quic_security = GetMember(json, "QUICSecure");
        const std::string quic_secret = GetMember(json, "QUICSecret");
        const std::string transport_host =
            transport == "quic" ? quic_security : regular_host;
        const std::string transport_path =
            transport == "quic" ? quic_secret : regular_path;
        const std::string tls = normalizeNetchTLS(json, "none");
        const std::string user_id = GetMember(json, "UserID");
        const std::string alter_id = GetMember(json, "AlterID");
        const std::string server_name = GetMember(json, "ServerName");
        const std::string packet_encoding = firstNetchMember(
            json, {"PacketEncoding", "packetEncoding"});
        std::string cipher = method;
        if (cipher.empty())
            cipher = type == "vless" ? "none" : "auto";
        if (!isXrayUuid(user_id))
            return false;

        if (type == "vmess") {
            if (group.empty())
                group = V2RAY_DEFAULT_GROUP;
            vmessConstruct(node, group, remark, address, port, fake_type,
                           user_id, alter_id, transport, cipher, transport_path,
                           transport_host, GetMember(json, "Edge"), tls,
                           server_name, {}, udp, tfo, scv);
        } else {
            if (group.empty())
                group = XRAY_DEFAULT_GROUP;
            vlessConstruct(node, group, remark, address, port, fake_type,
                           user_id, alter_id, transport, cipher,
                           GetMember(json, "Flow"), fake_type, transport_path,
                           transport_host, GetMember(json, "Edge"), tls, "", "",
                           fingerprint, server_name, {}, packet_encoding, udp,
                           tfo, scv);
        }
        node.PacketEncoding = packet_encoding;
        node.Fingerprint = fingerprint;
        if (transport == "grpc") {
            node.GRPCMode = fake_type.empty() ? "gun" : fake_type;
            node.GRPCServiceName = regular_path;
        } else if (transport == "quic") {
            node.QUICSecure = quic_security;
            node.QUICSecret = quic_secret;
        }
    } else if (type == "socks" || type == "socks5") {
        const std::string version = GetMember(json, "Version");
        if (!version.empty() && version != "5")
            return false;
        if (group.empty())
            group = SOCKS_DEFAULT_GROUP;
        socksConstruct(node, group, remark, address, port,
                       GetMember(json, "Username"), password, udp, tfo, scv);
    } else if (type == "http" || type == "https") {
        if (group.empty())
            group = HTTP_DEFAULT_GROUP;
        httpConstruct(node, group, remark, address, port,
                      GetMember(json, "Username"), password, type == "https",
                      tfo, scv);
    } else if (type == "trojan") {
        if (password.empty())
            return false;
        const std::string tls = normalizeNetchTLS(json, "tls");
        const std::string host = GetMember(json, "Host");
        std::string server_name = GetMember(json, "ServerName");
        if (server_name.empty())
            server_name = host;
        if (group.empty())
            group = TROJAN_DEFAULT_GROUP;
        trojanConstruct(node, group, remark, address, port, password,
                        GetMember(json, "TransferProtocol"), host,
                        GetMember(json, "Path"), fingerprint, server_name, {},
                        tls != "none", udp, tfo, scv);
        node.TLSStr = tls;
    } else if (type == "snell") {
        if (password.empty())
            return false;
        if (group.empty())
            group = SNELL_DEFAULT_GROUP;
        snellConstruct(node, group, remark, address, port, password,
                       GetMember(json, "OBFS"), GetMember(json, "Host"), "",
                       parseUint16Option(GetMember(json, "SnellVersion"), 0),
                       tribool(), udp, tfo, scv);
    } else if (type == "wireguard") {
        const std::string private_key = GetMember(json, "PrivateKey");
        const std::string public_key = GetMember(json, "PeerPublicKey");
        const std::string local_addresses = normalizeWireGuardAllowedIPs(
            GetMember(json, "LocalAddresses"));
        if (private_key.empty() || public_key.empty() || local_addresses.empty() ||
            private_key.find_first_of("\r\n") != std::string::npos ||
            public_key.find_first_of("\r\n") != std::string::npos)
            return false;

        string_array addresses = split(local_addresses, ",");
        std::string self_ip, self_ipv6;
        for (std::string &local_address : addresses) {
            local_address = trim(local_address);
            const std::string bare = local_address.substr(0, local_address.find('/'));
            if (self_ip.empty() && isIPv4(bare))
                self_ip = bare;
            else if (self_ipv6.empty() && isIPv6(bare))
                self_ipv6 = bare;
        }
        if (group.empty())
            group = WG_DEFAULT_GROUP;
        wireguardConstruct(node, group, remark, address, port, self_ip,
                           self_ipv6, private_key, public_key,
                           GetMember(json, "PreSharedKey"), {},
                           GetMember(json, "MTU"), "0", "", "", udp, "");
        node.WireGuardLocalAddresses = std::move(addresses);
        syncLegacyWireGuardProjection(node);
        if (node.WireGuardPeers.empty())
            return false;
    } else {
        // Netch also serializes SSH nodes, but the shared Proxy model has no
        // SSH representation. Reject instead of silently converting it to a
        // different protocol.
        return false;
    }

    return node.Type != ProxyType::Unknown;
}

} // namespace

void explodeNetch(std::string netch, Proxy &node) {
    if (!startsWith(netch, "Netch://"))
        return;
    std::string decoded;
    if (!decodeStrictBase64(netch.substr(8), decoded))
        return;
    Document json;
    json.Parse(decoded.data());
    if (json.HasParseError())
        return;
    parseNetchNode(json, node);
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
        std::string ip, ipv6, private_key, public_key, mtu, wg_allowed_ips,
                    wg_reserved, wg_keepalive; //wireguard
        std::string auth, auth_str, up, down, obfsParam, insecure, alpn,
                    hop_interval, reuse_text; //hysteria
        std::string obfsPassword, certificate_fingerprint; //hysteria2
        std::string congestion_control, udp_relay_mode, token; // tuic
        string_array dns_server;
        std::vector<String> alpns;
        String alpn2;
        std::string fingerprint, snell_fingerprint, multiplexing,
                    transfer_protocol, v2ray_http_upgrade,
                    mieru_handshake_mode, mieru_traffic_pattern;
        tribool udp, tfo, scv, reuse;
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

        if ((port.empty() || port == "0") && proxytype != "wireguard")
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
                singleproxy["reuse"] >> reuse_text;
                reuse = reuse_text;
                if (!reuse_text.empty() && reuse.is_undef())
                    continue;
                singleproxy["client-fingerprint"] >>= snell_fingerprint;
                snellConstruct(node, group, ps, server, port, password, obfs,
                               host, "", to_int(aid, 0), reuse, udp, tfo, scv);
                if (obfs == "shadow-tls") {
                    singleproxy["obfs-opts"]["password"] >>=
                        node.ShadowTLSPassword;
                    node.ShadowTLSSNI = host;
                    std::string shadow_version;
                    singleproxy["obfs-opts"]["version"] >>=
                        shadow_version;
                    node.ShadowTLSVersion = parseUint16Option(
                        shadow_version, 0);
                    singleproxy["obfs-opts"]["alpn"] >>=
                        node.AlpnList;
                }
                node.Fingerprint = snell_fingerprint;
                break;
            case "wireguard"_hash: {
                group = WG_DEFAULT_GROUP;
                singleproxy["public-key"] >>= public_key;
                singleproxy["private-key"] >>= private_key;
                singleproxy["dns"] >>= dns_server;
                singleproxy["mtu"] >>= mtu;
                singleproxy["pre-shared-key"] >>= password;
                if (password.empty())
                    singleproxy["preshared-key"] >>= password;
                singleproxy["ip"] >>= ip;
                singleproxy["ipv6"] >>= ipv6;
                if (singleproxy["allowed-ips"].IsSequence()) {
                    string_array allowed;
                    singleproxy["allowed-ips"] >>= allowed;
                    wg_allowed_ips = normalizeWireGuardAllowedIPs(join(allowed, ", "));
                } else {
                    singleproxy["allowed-ips"] >>= wg_allowed_ips;
                    wg_allowed_ips = normalizeWireGuardAllowedIPs(wg_allowed_ips);
                }
                if (singleproxy["reserved"].IsSequence()) {
                    string_array reserved;
                    singleproxy["reserved"] >>= reserved;
                    wg_reserved = normalizeWireGuardReserved(join(reserved, ","));
                } else {
                    singleproxy["reserved"] >>= wg_reserved;
                    wg_reserved = normalizeWireGuardReserved(wg_reserved);
                }
                singleproxy["persistent-keepalive"] >>= wg_keepalive;

                wireguardConstruct(node, group, ps, server, port, ip, ipv6, private_key, public_key, password,
                                   dns_server, mtu, wg_keepalive, "", wg_reserved, udp, "");
                if (!node.WireGuardPeers.empty() && !wg_allowed_ips.empty()) {
                    node.WireGuardPeers.front().AllowedIPs = wg_allowed_ips;
                    syncLegacyWireGuardProjection(node);
                }
                if (singleproxy["peers"].IsSequence()) {
                    node.WireGuardPeers.clear();
                    for (const auto &yaml_peer_value : singleproxy["peers"]) {
                        YAML::Node yaml_peer = yaml_peer_value;
                        WireGuardPeer peer;
                        yaml_peer["server"] >>= peer.Hostname;
                        std::string peer_port;
                        yaml_peer["port"] >>= peer_port;
                        peer.Port = parseUint16Option(peer_port, 0);
                        yaml_peer["public-key"] >>= peer.PublicKey;
                        yaml_peer["pre-shared-key"] >>= peer.PreSharedKey;
                        if (peer.PreSharedKey.empty())
                            yaml_peer["preshared-key"] >>= peer.PreSharedKey;
                        if (yaml_peer["allowed-ips"].IsSequence()) {
                            string_array allowed;
                            yaml_peer["allowed-ips"] >>= allowed;
                            peer.AllowedIPs = normalizeWireGuardAllowedIPs(join(allowed, ", "));
                        } else if (yaml_peer["allowed-ips"].IsDefined()) {
                            yaml_peer["allowed-ips"] >>= peer.AllowedIPs;
                            if (!peer.AllowedIPs.empty())
                                peer.AllowedIPs = normalizeWireGuardAllowedIPs(peer.AllowedIPs);
                        }
                        if (yaml_peer["reserved"].IsSequence()) {
                            string_array reserved;
                            yaml_peer["reserved"] >>= reserved;
                            peer.Reserved = normalizeWireGuardReserved(join(reserved, ","));
                        } else {
                            yaml_peer["reserved"] >>= peer.Reserved;
                            peer.Reserved = normalizeWireGuardReserved(peer.Reserved);
                        }
                        std::string peer_keepalive;
                        yaml_peer["persistent-keepalive"] >>= peer_keepalive;
                        peer.KeepAlive = parseUint16Option(peer_keepalive, 0);
                        if (validWireGuardPeer(peer))
                            node.WireGuardPeers.emplace_back(std::move(peer));
                    }
                    syncLegacyWireGuardProjection(node);
                }
                if (node.PrivateKey.empty() || node.WireGuardLocalAddresses.empty() ||
                    node.WireGuardPeers.empty())
                    continue;
                break;
            }
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
                singleproxy["auth_str"] >> auth_str;
                if (auth_str.empty())
                    singleproxy["auth-str"] >> auth_str;
                if (auth_str.empty())
                    singleproxy["password"] >> auth_str;
                singleproxy["auth"] >> auth;
                singleproxy["up"] >> up;
                if (up.empty())
                    singleproxy["up_mbps"] >> up;
                singleproxy["down"] >> down;
                if (down.empty())
                    singleproxy["down_mbps"] >> down;
                if (up.empty() || down.empty())
                    continue;
                singleproxy["obfs"] >> obfsParam;
                singleproxy["protocol"] >> type;
                if (!normalizeHysteriaProtocol(type))
                    continue;
                singleproxy["sni"] >> sni;
                if (sni.empty())
                    singleproxy["server-name"] >> sni;
                singleproxy["alpn"][0] >> alpn;
                singleproxy["alpn"] >> alpnList;
                singleproxy["skip-cert-verify"] >> insecure;
                singleproxy["ports"] >> ports;
                if (!ports.empty()) {
                    uint16_t first_port = 0;
                    std::string normalized_ports;
                    if (!normalizeHysteriaPortSpec(ports, normalized_ports,
                                                   first_port))
                        continue;
                    ports = std::move(normalized_ports);
                    if (port.empty() || port == "0")
                        port = std::to_string(first_port);
                }
                singleproxy["hop-interval"] >> hop_interval;
                if (hop_interval.empty())
                    singleproxy["hop_interval"] >> hop_interval;
                if (!validHysteriaHopInterval(hop_interval))
                    continue;
                hysteriaConstruct(node, group, ps, server, port, type, auth, auth_str, sni, up, down, alpn, obfsParam,
                                  insecure, ports, sni,
                                  udp, tfo, scv);
                node.AlpnList = alpnList;
                node.HysteriaHopInterval = hop_interval;
                node.TLSSecure = true;
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
                if (!singleproxy["multiplexing"].IsNull()) {
                    singleproxy["multiplexing"] >>= multiplexing;
                }
                transfer_protocol = "TCP";
                if (!singleproxy["transport"].IsNull()) {
                    singleproxy["transport"] >>= transfer_protocol;
                }
                singleproxy["handshake-mode"] >>= mieru_handshake_mode;
                singleproxy["traffic-pattern"] >>= mieru_traffic_pattern;
                {
                    MieruPortBinding binding;
                    if (user.empty() || password.empty() || server.empty() ||
                        (!ports.empty() && !port.empty() && port != "0") ||
                        !isValidMieruMultiplexing(multiplexing) ||
                        !isValidMieruHandshakeMode(mieru_handshake_mode) ||
                        !isValidMieruTrafficPattern(mieru_traffic_pattern) ||
                        !parseMieruPortBinding(ports.empty() ? port : ports,
                                               transfer_protocol, binding))
                        continue;
                    const std::string normalized_port =
                        binding.is_range ? "0" : binding.port;
                    const std::string normalized_range =
                        binding.is_range ? binding.port : std::string();
                    mieruConstruct(node, MIERU_DEFAULT_GROUP, ps,
                                   normalized_port, password, server,
                                   normalized_range, user, multiplexing,
                                   binding.protocol, udp, tribool(), scv,
                                   tribool(), "");
                    node.MieruHandshakeMode = mieru_handshake_mode;
                    node.MieruTrafficPattern = mieru_traffic_pattern;
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
    ParsedShareUri parsed;
    std::string ignored_ports;
    if (!parseModernShareUri(std::move(hysteria), "hysteria", false, "",
                             false, parsed, ignored_ports))
        return;

    std::string protocol = decodedUrlArg(parsed.query, "protocol");
    if (!normalizeHysteriaProtocol(protocol))
        return;
    const std::string up = decodedFirstUrlArg(
        parsed.query, {"upmbps", "up_mbps", "up"});
    const std::string down = decodedFirstUrlArg(
        parsed.query, {"downmbps", "down_mbps", "down"});
    if (!validHysteriaUriMbps(up) || !validHysteriaUriMbps(down))
        return;

    std::string obfs_mode = toLower(trim(decodedUrlArg(parsed.query, "obfs")));
    if (!obfs_mode.empty() && obfs_mode != "xplus")
        return;
    const std::string auth = decodedFirstUrlArg(
        parsed.query, {"auth_str", "auth-str", "auth"});
    const std::string sni = decodedFirstUrlArg(
        parsed.query, {"peer", "sni", "server_name", "server-name"});
    const std::string insecure = decodedFirstUrlArg(
        parsed.query, {"insecure", "allow_insecure", "allow-insecure"});
    const std::vector<std::string> alpn_list = getUrlAlpnList(parsed.query);
    const std::string alpn = alpn_list.empty() ? std::string() : alpn_list.front();
    const std::string hop_interval = decodedFirstUrlArg(
        parsed.query, {"hop_interval", "hop-interval"});
    if (!validHysteriaHopInterval(hop_interval))
        return;

    if (parsed.remark.empty())
        parsed.remark = parsed.host + ":" + parsed.port;
    hysteriaConstruct(
        node, HYSTERIA_DEFAULT_GROUP, parsed.remark, parsed.host, parsed.port,
        protocol, "", auth, sni, up, down, alpn,
        decodedFirstUrlArg(parsed.query, {"obfsParam", "obfs-param"}),
        insecure, "", sni, tribool(), tribool(), tribool(insecure));
    node.OBFS = obfs_mode;
    node.AlpnList = alpn_list;
    node.HysteriaHopInterval = hop_interval;
    node.TLSSecure = true;
}

void explodeStdMieru(std::string mieru, Proxy &node) {
    std::vector<Proxy> parsed_nodes;
    explodeMierusNodes(mieru, parsed_nodes);
    if (parsed_nodes.size() == 1)
        node = std::move(parsed_nodes.front());
}

void explodeMierusNodes(const std::string &mieru, std::vector<Proxy> &nodes) {
    MieruSimpleConfig config;
    if (!parseMieruSimpleUri(mieru, config))
        return;

    nodes.reserve(nodes.size() + config.port_bindings.size());
    const std::string remark_base = config.remark.empty() ? config.profile : config.remark;
    const std::string source_id = nextMieruSourceId();
    for (size_t binding_index = 0;
         binding_index < config.port_bindings.size(); ++binding_index) {
        const MieruPortBinding &binding = config.port_bindings[binding_index];
        Proxy node;
        const std::string port = binding.is_range ? "0" : binding.port;
        const std::string ports = binding.is_range ? binding.port : std::string();
        const std::string remark = remark_base + ":" + binding.port + "/" + binding.protocol;
        mieruConstruct(node, MIERU_DEFAULT_GROUP, remark, port,
                       config.password, config.host, ports, config.username,
                       config.multiplexing, binding.protocol, tribool(true),
                       tribool(), tribool(), tribool(), "");
        node.Mtu = config.mtu;
        node.MieruProfile = config.profile;
        node.MieruSourceId = source_id;
        node.MieruSourceRemark = config.remark;
        node.MieruBindingIndex = static_cast<uint32_t>(binding_index);
        node.MieruHasUnknownParameters = config.has_unknown_parameters;
        node.MieruHandshakeMode = config.handshake_mode;
        node.MieruTrafficPattern = config.traffic_pattern;
        nodes.emplace_back(std::move(node));
    }
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
    if (toLower(trim(node.OBFSParam)) == "gecko") {
        node.Hysteria2GeckoMinPacketSize = decodedFirstUrlArg(
            parsed.query, {"minPacketSize", "min_packet_size"});
        node.Hysteria2GeckoMaxPacketSize = decodedFirstUrlArg(
            parsed.query, {"maxPacketSize", "max_packet_size"});
    }
}

void explodeHysteria2Realm(std::string hysteria2, Proxy &node) {
    const bool http = startsWith(hysteria2, "hysteria2+realm+http://");
    const std::string prefix =
        http ? "hysteria2+realm+http://" : "hysteria2+realm://";
    if (!startsWith(hysteria2, prefix))
        return;
    hysteria2.erase(0, prefix.size());

    std::string remark;
    extractRemark(hysteria2, remark);
    std::string query;
    const size_t query_pos = hysteria2.find('?');
    if (query_pos != std::string::npos) {
        query = hysteria2.substr(query_pos + 1);
        hysteria2.erase(query_pos);
    }

    const size_t at = hysteria2.rfind('@');
    const size_t path = at == std::string::npos
                            ? std::string::npos
                            : hysteria2.find('/', at + 1);
    if (at == std::string::npos || at == 0 || path == std::string::npos ||
        path == at + 1 || path + 1 >= hysteria2.size())
        return;
    const std::string token =
        decodeShareUriUserInfo(hysteria2.substr(0, at));
    const std::string authority = hysteria2.substr(at + 1, path - at - 1);
    const std::string realm_name = hysteria2.substr(path + 1);
    if (token.empty() || token.find_first_of("\r\n") != std::string::npos ||
        realm_name.find_first_of("/\r\n") != std::string::npos)
        return;

    std::string host;
    std::string port;
    if (!authority.empty() && authority.front() == '[') {
        const size_t bracket = authority.find(']');
        if (bracket == std::string::npos || bracket == 1)
            return;
        host = authority.substr(1, bracket - 1);
        if (bracket + 1 < authority.size()) {
            if (authority[bracket + 1] != ':' ||
                !validSharePort(authority.substr(bracket + 2)))
                return;
            port = authority.substr(bracket + 2);
        }
    } else {
        const size_t colon = authority.rfind(':');
        if (colon != std::string::npos && authority.find(':') == colon) {
            const std::string candidate_port = authority.substr(colon + 1);
            if (!validSharePort(candidate_port))
                return;
            host = authority.substr(0, colon);
            port = candidate_port;
        } else {
            host = authority;
        }
    }
    if (host.empty() || host.find_first_of("\r\n") != std::string::npos)
        return;
    if (port.empty())
        port = http ? "80" : "443";

    const std::string auth = decodedUrlArg(query, "auth");
    if (auth.empty())
        return;
    const std::string sni = decodedUrlArg(query, "sni");
    if (remark.empty())
        remark = host + ":" + port;

    std::string realm_url = http ? "realm+http://" : "realm://";
    realm_url += hysteria2;
    string_array stun_query;
    for (const std::string &entry : split(query, "&")) {
        const size_t equal = entry.find('=');
        if (equal == std::string::npos)
            continue;
        if (toLower(urlDecode(entry.substr(0, equal))) != "stun")
            continue;
        const std::string stun = urlDecode(entry.substr(equal + 1));
        if (stun.empty() || stun.find_first_of("\r\n") != std::string::npos)
            return;
        stun_query.emplace_back(entry);
    }
    if (!stun_query.empty())
        realm_url += "?" + join(stun_query, "&");

    hysteria2Construct(
        node, HYSTERIA2_DEFAULT_GROUP, remark, host, port, auth, sni,
        decodedUrlArg(query, "up"), decodedUrlArg(query, "down"),
        decodedUrlArg(query, "alpn"), decodedUrlArg(query, "obfs"),
        decodedUrlArg(query, "obfs-password"), sni, "", "", tribool(),
        tribool(), tribool(decodedUrlArg(query, "insecure")));
    node.TLSSecure = true;
    node.TLSStr = "tls";
    node.Fingerprint = decodedFirstUrlArg(query, {"pinSHA256", "pinsha256"});
    node.Hysteria2ECH = decodedUrlArg(query, "ech");
    node.Hysteria2RealmUrl = std::move(realm_url);
    if (toLower(trim(node.OBFSParam)) == "gecko") {
        node.Hysteria2GeckoMinPacketSize = decodedFirstUrlArg(
            query, {"minPacketSize", "min_packet_size"});
        node.Hysteria2GeckoMaxPacketSize = decodedFirstUrlArg(
            query, {"maxPacketSize", "max_packet_size"});
    }
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
    for (const std::string &peer_text : peers) {
        WireGuardPeer peer;
        for (const std::string &field : splitWireGuardFields(peer_text)) {
            const size_t equal = field.find('=');
            if (equal == std::string::npos)
                continue;
            const std::string key = toLower(trim(field.substr(0, equal)));
            const std::string value = stripWireGuardQuotes(field.substr(equal + 1));
            switch (hash_(key)) {
                case "public-key"_hash:
                    peer.PublicKey = value;
                    break;
                case "endpoint"_hash:
                    parseWireGuardEndpoint(value, peer.Hostname, peer.Port);
                    break;
                case "client-id"_hash:
                case "reserved"_hash:
                    peer.Reserved = normalizeWireGuardReserved(
                        trimOf(trimOf(value, '['), ']'));
                    break;
                case "allowed-ips"_hash:
                    peer.AllowedIPs = normalizeWireGuardAllowedIPs(value);
                    break;
                case "preshared-key"_hash:
                case "pre-shared-key"_hash:
                    peer.PreSharedKey = value;
                    break;
                case "keepalive"_hash:
                case "persistent-keepalive"_hash:
                    peer.KeepAlive = parseUint16Option(value, 0);
                    break;
                default:
                    break;
            }
        }
        if (validWireGuardPeer(peer))
            node.WireGuardPeers.emplace_back(std::move(peer));
    }
    syncLegacyWireGuardProjection(node);
}

enum class LoonProxyParseResult { NotLoon, Invalid, Parsed };

struct LoonProxyValue {
    std::string value;
    bool quoted = false;
};

using LoonProxyOptions = std::map<std::string, LoonProxyValue>;

bool parseLoonProxyValue(std::string input, LoonProxyValue &result,
                         bool require_quotes = false) {
    input = trim(input);
    if (input.empty() || input.find_first_of("\r\n") != std::string::npos)
        return false;
    if (input.front() == '"') {
        if (input.size() < 2 || input.back() != '"')
            return false;
        input = input.substr(1, input.size() - 2);
        if (input.find_first_of("\\\"\r\n") != std::string::npos)
            return false;
        result.quoted = true;
        result.value = std::move(input);
        return true;
    }
    if (require_quotes || input.front() == '\'' || input.back() == '\'' ||
        input.find('"') != std::string::npos)
        return false;
    result.value = std::move(input);
    return true;
}

bool parseLoonProxyOptions(const std::vector<std::string> &configs, size_t start,
                           LoonProxyOptions &options) {
    for (size_t i = start; i < configs.size(); ++i) {
        const size_t equal = configs[i].find('=');
        if (equal == std::string::npos || equal == 0)
            return false;
        const std::string key = toLower(trim(configs[i].substr(0, equal)));
        if (key.empty() || !std::all_of(key.begin(), key.end(), [](unsigned char ch) {
                return std::isalnum(ch) != 0 || ch == '-';
            }) || options.count(key) != 0)
            return false;
        LoonProxyValue value;
        const std::string raw_value = trim(configs[i].substr(equal + 1));
        if (!raw_value.empty() && !parseLoonProxyValue(raw_value, value))
            return false;
        options.emplace(key, std::move(value));
    }
    return true;
}

bool loonOptionsAreKnown(const LoonProxyOptions &options,
                         std::initializer_list<const char *> known) {
    for (const auto &item : options) {
        if (std::none_of(known.begin(), known.end(), [&](const char *key) {
                return item.first == key;
            }))
            return false;
    }
    return true;
}

bool loonOption(const LoonProxyOptions &options, const std::string &key,
                std::string &value, bool require_quotes = false) {
    const auto found = options.find(key);
    if (found == options.end()) {
        value.clear();
        return true;
    }
    if (require_quotes && !found->second.quoted)
        return false;
    value = found->second.value;
    return true;
}

bool loonAliasedOption(const LoonProxyOptions &options, const std::string &first,
                       const std::string &second, std::string &value) {
    const auto a = options.find(first), b = options.find(second);
    if (a != options.end() && b != options.end() && a->second.value != b->second.value)
        return false;
    value = a != options.end() ? a->second.value
                               : b != options.end() ? b->second.value : std::string();
    return true;
}

bool loonBoolOption(const LoonProxyOptions &options, const std::string &first,
                    const std::string &second, tribool &value) {
    const auto a = options.find(first), b = options.find(second);
    if (a != options.end() && b != options.end() && a != b &&
        a->second.value != b->second.value)
        return false;
    if (a == options.end() && b == options.end()) {
        value = tribool();
        return true;
    }
    const std::string &text = a != options.end() ? a->second.value : b->second.value;
    if (text != "true" && text != "false")
        return false;
    value = tribool(text);
    return true;
}

bool validLoonPort(const std::string &port) {
    return validSharePort(port);
}

bool validLoonAlterId(const std::string &alter_id) {
    if (alter_id.empty() || alter_id.size() > 5 ||
        !std::all_of(alter_id.begin(), alter_id.end(), [](unsigned char ch) {
            return std::isdigit(ch) != 0;
        }))
        return false;
    return to_int(alter_id, -1) <= 65535;
}

bool isLoonPositionalCandidate(const std::vector<std::string> &configs,
                               const std::string &kind) {
    const size_t minimum = kind == "vmess" ? 5 : 4;
    if (configs.size() < minimum)
        return false;
    // Surge's same-named forms begin their fourth field with a named option
    // (`username=` / `password=`); Loon uses a positional cipher/password.
    const std::string &positional = configs[3];
    if (!positional.empty() && positional.front() == '"')
        return true;
    return positional.find('=') == std::string::npos;
}

LoonProxyParseResult parseLoonProxyLine(const std::vector<std::string> &configs,
                                        std::string remarks, Proxy &node) {
    if (configs.empty())
        return LoonProxyParseResult::NotLoon;
    const std::string kind = toLower(trim(configs.front()));
    if (kind != "vmess" && kind != "vless" && kind != "trojan" &&
        kind != "anytls" && kind != "hysteria2")
        return LoonProxyParseResult::NotLoon;
    if (!isLoonPositionalCandidate(configs, kind))
        return LoonProxyParseResult::NotLoon;

    LoonProxyValue remark_value, server_value, credential_value;
    if (!parseLoonProxyValue(std::move(remarks), remark_value) ||
        !parseLoonProxyValue(configs[1], server_value) ||
        server_value.quoted || !validLoonPort(trim(configs[2])))
        return LoonProxyParseResult::Invalid;
    const std::string server = server_value.value;
    const std::string port = trim(configs[2]);
    const size_t option_start = kind == "vmess" ? 5 : 4;
    if (!parseLoonProxyValue(configs[kind == "vmess" ? 4 : 3],
                             credential_value, true) ||
        credential_value.value.empty())
        return LoonProxyParseResult::Invalid;

    LoonProxyOptions options;
    if (!parseLoonProxyOptions(configs, option_start, options))
        return LoonProxyParseResult::Invalid;
    for (const auto &option : options) {
        if (option.second.quoted && option.first != "public-key" &&
            option.first != "salamander-password")
            return LoonProxyParseResult::Invalid;
    }
    tribool udp, tfo, scv;
    std::string sni, fingerprint;
    if (!loonAliasedOption(options, "sni", "tls-name", sni) ||
        !loonOption(options, "tls-profile", fingerprint) ||
        !loonBoolOption(options, "udp", "udp-relay", udp) ||
        !loonBoolOption(options, "fast-open", "tfo", tfo) ||
        !loonBoolOption(options, "skip-cert-verify", "skip-cert-verify", scv))
        return LoonProxyParseResult::Invalid;

    if (kind == "vmess") {
        if (!loonOptionsAreKnown(options, {"transport", "alterid", "path", "host", "over-tls",
                                            "sni", "tls-name", "skip-cert-verify", "tls-profile",
                                            "fast-open", "tfo", "udp", "udp-relay"}))
            return LoonProxyParseResult::Invalid;
        LoonProxyValue method_value;
        std::string transport, alter_id, path, host, over_tls;
        if (!parseLoonProxyValue(configs[3], method_value) || method_value.quoted ||
            method_value.value.empty() || !isXrayUuid(credential_value.value) ||
            !loonOption(options, "transport", transport) ||
            !loonOption(options, "alterid", alter_id) ||
            !loonOption(options, "path", path) || !loonOption(options, "host", host) ||
            !loonOption(options, "over-tls", over_tls) ||
            (transport != "tcp" && transport != "ws" && transport != "http") ||
            (over_tls != "true" && over_tls != "false") ||
            !validLoonAlterId(alter_id) ||
            (transport == "tcp" && (!path.empty() || !host.empty())) ||
            (!fingerprint.empty() && over_tls != "true") ||
            (!sni.empty() && over_tls != "true"))
            return LoonProxyParseResult::Invalid;
        vmessConstruct(node, V2RAY_DEFAULT_GROUP, remark_value.value, server, port, "",
                       credential_value.value, alter_id, transport, method_value.value,
                       path, host, "", over_tls == "true" ? "tls" : "", sni,
                       {}, udp, tfo, scv);
        node.Fingerprint = fingerprint;
        return LoonProxyParseResult::Parsed;
    }

    if (kind == "vless") {
        if (!loonOptionsAreKnown(options, {"transport", "path", "host", "flow", "public-key", "short-id",
                                            "over-tls", "sni", "tls-name", "skip-cert-verify",
                                            "tls-profile", "fast-open", "tfo", "udp", "udp-relay"}))
            return LoonProxyParseResult::Invalid;
        std::string transport, path, host, flow, public_key, short_id, over_tls;
        if (!isXrayUuid(credential_value.value) ||
            !loonOption(options, "transport", transport) ||
            !loonOption(options, "path", path) || !loonOption(options, "host", host) ||
            !loonOption(options, "flow", flow) ||
            !loonOption(options, "public-key", public_key, true) ||
            !loonOption(options, "short-id", short_id) ||
            !loonOption(options, "over-tls", over_tls) ||
            (transport != "tcp" && transport != "ws" && transport != "http") ||
            (over_tls != "true" && over_tls != "false") ||
            (transport == "tcp" && (!path.empty() || !host.empty())) ||
            (!fingerprint.empty() && over_tls != "true"))
            return LoonProxyParseResult::Invalid;
        const bool reality = !public_key.empty() || !flow.empty() || !short_id.empty();
        if (reality ? (transport != "tcp" || over_tls != "true" ||
                       flow != "xtls-rprx-vision" || public_key.empty() || sni.empty())
                    : (!flow.empty() || !public_key.empty() || !short_id.empty()))
            return LoonProxyParseResult::Invalid;
        vlessConstruct(node, XRAY_DEFAULT_GROUP, remark_value.value, server, port, "",
                       credential_value.value, "0", transport, "auto", flow, "", path,
                       host, "", reality ? "reality" : over_tls == "true" ? "tls" : "",
                       public_key, short_id, fingerprint, sni, {}, "none", udp, tfo, scv);
        return LoonProxyParseResult::Parsed;
    }

    if (kind == "trojan") {
        if (!loonOptionsAreKnown(options, {"transport", "path", "host", "alpn", "sni", "tls-name",
                                            "skip-cert-verify", "tls-profile", "fast-open", "tfo",
                                            "udp", "udp-relay"}))
            return LoonProxyParseResult::Invalid;
        std::string transport, path, host, alpn;
        if (!loonOption(options, "transport", transport) ||
            !loonOption(options, "path", path) || !loonOption(options, "host", host) ||
            !loonOption(options, "alpn", alpn) ||
            (transport.empty() ? false : transport != "tcp" && transport != "ws" && transport != "http") ||
            ((transport.empty() || transport == "tcp") && (!path.empty() || !host.empty())))
            return LoonProxyParseResult::Invalid;
        if (transport.empty())
            transport = "tcp";
        std::vector<std::string> alpn_list;
        if (!alpn.empty())
            alpn_list.emplace_back(alpn);
        trojanConstruct(node, TROJAN_DEFAULT_GROUP, remark_value.value, server, port,
                        credential_value.value, transport, host, path, fingerprint, sni,
                        alpn_list, true, udp, tfo, scv);
        return LoonProxyParseResult::Parsed;
    }

    if (kind == "anytls") {
        if (!loonOptionsAreKnown(options, {"sni", "tls-name", "skip-cert-verify", "tls-profile",
                                            "fast-open", "tfo", "udp", "udp-relay", "block-quic"}))
            return LoonProxyParseResult::Invalid;
        std::string block_quic;
        if (!loonOption(options, "block-quic", block_quic) ||
            (options.count("block-quic") != 0 && block_quic != "false"))
            return LoonProxyParseResult::Invalid;
        anyTlSConstruct(node, ANYTLS_DEFAULT_GROUP, remark_value.value, port,
                        credential_value.value, server, {}, fingerprint, sni, udp, tfo,
                        scv, tribool(), "", 30, 30, 0);
        return LoonProxyParseResult::Parsed;
    }

    if (!loonOptionsAreKnown(options, {"sni", "tls-name", "skip-cert-verify", "tls-cert-sha256",
                                        "download-bandwidth", "salamander-password", "fast-open",
                                        "tfo", "udp", "udp-relay"}))
        return LoonProxyParseResult::Invalid;
    std::string certificate, down, salamander_password;
    if (!loonOption(options, "tls-cert-sha256", certificate) ||
        !loonOption(options, "download-bandwidth", down) ||
        !loonOption(options, "salamander-password", salamander_password, true) ||
        (!down.empty() && !validHysteriaUriMbps(down)) ||
        (!certificate.empty() && !scv.is_undef() && scv.get()))
        return LoonProxyParseResult::Invalid;
    hysteria2Construct(node, HYSTERIA2_DEFAULT_GROUP, remark_value.value, server, port,
                       credential_value.value, sni, "", down, "",
                       salamander_password.empty() ? "" : "salamander",
                       salamander_password, sni, "", "", udp, tfo, scv);
    node.Fingerprint = certificate;
    return LoonProxyParseResult::Parsed;
}

enum class QuanXProxyParseResult { NotQuanX, Invalid, Parsed };

using QuanXProxyOptions = std::map<std::string, std::string>;

bool parseQuanXProxyOptions(const std::vector<std::string> &configs, size_t start,
                            QuanXProxyOptions &options) {
    for (size_t i = start; i < configs.size(); ++i) {
        const size_t equal = configs[i].find('=');
        if (equal == std::string::npos || equal == 0)
            return false;
        const std::string key = toLower(trim(configs[i].substr(0, equal)));
        std::string value = trim(configs[i].substr(equal + 1));
        if (key.empty() || value.find_first_of("\r\n") != std::string::npos ||
            !std::all_of(key.begin(), key.end(), [](unsigned char ch) {
                return std::isalnum(ch) != 0 || ch == '-';
            }) || options.count(key) != 0)
            return false;
        options.emplace(key, std::move(value));
    }
    return true;
}

bool quanXOptionsAreKnown(const QuanXProxyOptions &options,
                          std::initializer_list<const char *> known) {
    return std::all_of(options.begin(), options.end(), [&](const auto &item) {
        return std::any_of(known.begin(), known.end(), [&](const char *key) {
            return item.first == key;
        });
    });
}

bool quanXOption(const QuanXProxyOptions &options, const std::string &key,
                 std::string &value) {
    const auto found = options.find(key);
    value = found == options.end() ? std::string() : found->second;
    return true;
}

bool quanXBoolOption(const QuanXProxyOptions &options, const std::string &key,
                     tribool &value) {
    const auto found = options.find(key);
    if (found == options.end()) {
        value = tribool();
        return true;
    }
    if (found->second != "true" && found->second != "false")
        return false;
    value = tribool(found->second);
    return true;
}

bool parseQuanXEndpoint(const std::string &input, std::string &server,
                        std::string &port) {
    const std::string endpoint = trim(input);
    if (endpoint.empty() || endpoint.find_first_of(",\r\n") != std::string::npos)
        return false;
    if (endpoint.front() == '[') {
        const size_t closing = endpoint.find("]:");
        if (closing == std::string::npos)
            return false;
        server = endpoint.substr(1, closing - 1);
        port = endpoint.substr(closing + 2);
    } else {
        const size_t colon = endpoint.rfind(':');
        if (colon == std::string::npos)
            return false;
        server = endpoint.substr(0, colon);
        port = endpoint.substr(colon + 1);
    }
    return !server.empty() && validSharePort(port);
}

bool parseQuanXTlsAlpn(const std::string &hex, std::vector<std::string> &alpn_list) {
    alpn_list.clear();
    if (hex.empty())
        return true;
    if (hex.size() % 2 != 0 ||
        !std::all_of(hex.begin(), hex.end(), [](unsigned char ch) {
            return std::isxdigit(ch) != 0;
        }))
        return false;
    std::string bytes;
    bytes.reserve(hex.size() / 2);
    const auto nibble = [](unsigned char ch) -> unsigned char {
        if (ch >= '0' && ch <= '9')
            return ch - '0';
        ch = static_cast<unsigned char>(std::tolower(ch));
        return static_cast<unsigned char>(ch - 'a' + 10);
    };
    for (size_t i = 0; i < hex.size(); i += 2)
        bytes.push_back(static_cast<char>((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
    for (size_t offset = 0; offset < bytes.size();) {
        const size_t length = static_cast<unsigned char>(bytes[offset++]);
        if (length == 0 || length > bytes.size() - offset)
            return false;
        alpn_list.emplace_back(bytes.substr(offset, length));
        offset += length;
    }
    return !alpn_list.empty();
}

bool validQuanXReality(const std::string &public_key, const std::string &short_id) {
    if (public_key.size() != 43 ||
        !std::all_of(public_key.begin(), public_key.end(), [](unsigned char ch) {
            return std::isalnum(ch) != 0 || ch == '-' || ch == '_';
        }))
        return false;
    const std::string decoded = urlSafeBase64Decode(public_key);
    if (decoded.size() != 32 || urlSafeBase64Encode(decoded) != public_key)
        return false;
    return short_id.empty() ||
           (short_id.size() <= 16 && short_id.size() % 2 == 0 &&
            std::all_of(short_id.begin(), short_id.end(), [](unsigned char ch) {
                return std::isxdigit(ch) != 0;
            }));
}

struct QuanXTransport {
    std::string network = "tcp";
    std::string fake_type;
    std::string host;
    std::string path;
    std::string sni;
    std::string tls;
};

bool parseQuanXTransport(const QuanXProxyOptions &options, bool reality,
                         QuanXTransport &transport) {
    std::string obfs, host, path;
    quanXOption(options, "obfs", obfs);
    quanXOption(options, "obfs-host", host);
    quanXOption(options, "obfs-uri", path);
    if (obfs.empty())
        return host.empty() && path.empty() && !reality;
    if (obfs == "http") {
        if (reality)
            return false;
        transport.fake_type = "http";
        transport.host = host;
        transport.path = path;
        return true;
    }
    if (obfs == "ws") {
        if (reality)
            return false;
        transport.network = "ws";
        transport.host = host;
        transport.path = path;
        return true;
    }
    if (obfs == "over-tls") {
        if (!path.empty() || host.empty())
            return false;
        transport.sni = host;
        transport.tls = reality ? "reality" : "tls";
        return true;
    }
    if (obfs == "wss") {
        if (host.empty())
            return false;
        transport.network = "ws";
        transport.host = host;
        transport.path = path;
        transport.sni = host;
        transport.tls = reality ? "reality" : "tls";
        return true;
    }
    return false;
}

QuanXProxyParseResult parseQuanXProxyLine(const std::vector<std::string> &configs,
                                          std::string kind, Proxy &node) {
    kind = toLower(trim(kind));
    if (kind != "vmess" && kind != "vless" && kind != "trojan" &&
        kind != "anytls")
        return QuanXProxyParseResult::NotQuanX;
    if (configs.size() < 2)
        return QuanXProxyParseResult::Invalid;
    const std::string first = toLower(trim(configs.front()));
    if (first == "vmess" || first == "vless" || first == "trojan" ||
        first == "anytls" || first == "ss" || first == "socks5" ||
        first == "http" || first == "wireguard" || first == "snell" ||
        first == "custom" || first == "direct" || first == "reject" ||
        first == "reject-tinygif")
        return QuanXProxyParseResult::NotQuanX;

    std::string server, port;
    QuanXProxyOptions options;
    if (!parseQuanXEndpoint(configs.front(), server, port) ||
        !parseQuanXProxyOptions(configs, 1, options))
        return QuanXProxyParseResult::Invalid;

    std::string remarks, password, public_key, short_id, alpn_hex;
    quanXOption(options, "tag", remarks);
    quanXOption(options, "password", password);
    quanXOption(options, "reality-base64-pubkey", public_key);
    quanXOption(options, "reality-hex-shortid", short_id);
    quanXOption(options, "tls-alpn", alpn_hex);
    const bool reality = !public_key.empty() || !short_id.empty();
    if (remarks.empty() || password.empty() ||
        (reality && !validQuanXReality(public_key, short_id)))
        return QuanXProxyParseResult::Invalid;

    tribool udp, tfo, tls_verification;
    if (!quanXBoolOption(options, "udp-relay", udp) ||
        !quanXBoolOption(options, "fast-open", tfo) ||
        !quanXBoolOption(options, "tls-verification", tls_verification) ||
        (reality && !tfo.is_undef() && tfo.get()))
        return QuanXProxyParseResult::Invalid;
    tribool scv;
    if (!tls_verification.is_undef())
        scv = !tls_verification.get();
    std::vector<std::string> alpn_list;
    if (!parseQuanXTlsAlpn(alpn_hex, alpn_list) ||
        (reality && (!alpn_list.empty() || !tls_verification.is_undef())))
        return QuanXProxyParseResult::Invalid;

    if (kind == "vmess" || kind == "vless") {
        const bool vmess = kind == "vmess";
        if (!quanXOptionsAreKnown(
                options,
                vmess ? std::initializer_list<const char *>{
                            "method", "password", "aead", "obfs", "obfs-host", "obfs-uri",
                            "reality-base64-pubkey", "reality-hex-shortid", "tls-alpn",
                            "fast-open", "udp-relay", "tls-verification", "tag"}
                      : std::initializer_list<const char *>{
                            "method", "password", "obfs", "obfs-host", "obfs-uri",
                            "reality-base64-pubkey", "reality-hex-shortid", "vless-flow",
                            "tls-alpn", "fast-open", "udp-relay", "tls-verification", "tag"}) ||
            !isXrayUuid(password))
            return QuanXProxyParseResult::Invalid;
        std::string method, aead_text, flow;
        quanXOption(options, "method", method);
        quanXOption(options, "aead", aead_text);
        quanXOption(options, "vless-flow", flow);
        tribool aead;
        if (method.empty() || (!vmess && method != "none") ||
            (!aead_text.empty() && !aead.set(aead_text)) ||
            (!flow.empty() && flow != "xtls-rprx-vision"))
            return QuanXProxyParseResult::Invalid;
        QuanXTransport transport;
        if (!parseQuanXTransport(options, reality, transport) ||
            (!alpn_list.empty() && transport.tls != "tls") ||
            (!tls_verification.is_undef() && transport.tls != "tls") ||
            (!flow.empty() && (!reality || transport.network != "tcp")))
            return QuanXProxyParseResult::Invalid;
        if (vmess) {
            vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, server, port,
                           transport.fake_type, password,
                           !aead.is_undef() && !aead.get() ? "1" : "0",
                           transport.network, method, transport.path, transport.host, "",
                           transport.tls, transport.sni, alpn_list, udp, tfo, scv);
            node.PublicKey = public_key;
            node.ShortId = short_id;
        } else {
            vlessConstruct(node, XRAY_DEFAULT_GROUP, remarks, server, port,
                           transport.fake_type, password, "0", transport.network, method,
                           flow, "", transport.path, transport.host, "", transport.tls,
                           public_key, short_id, "", transport.sni, alpn_list, "none",
                           udp, tfo, scv);
        }
        return QuanXProxyParseResult::Parsed;
    }

    if (kind == "trojan") {
        if (!quanXOptionsAreKnown(options, {"password", "over-tls", "tls-host", "obfs",
                                             "obfs-host", "obfs-uri", "reality-base64-pubkey",
                                             "reality-hex-shortid", "tls-alpn", "fast-open",
                                             "udp-relay", "tls-verification", "tag"}))
            return QuanXProxyParseResult::Invalid;
        std::string over_tls, tls_host, obfs;
        quanXOption(options, "over-tls", over_tls);
        quanXOption(options, "tls-host", tls_host);
        quanXOption(options, "obfs", obfs);
        QuanXTransport transport;
        if (obfs.empty()) {
            if (over_tls != "true" || tls_host.empty())
                return QuanXProxyParseResult::Invalid;
            transport.tls = reality ? "reality" : "tls";
            transport.sni = tls_host;
        } else if (!over_tls.empty() || !tls_host.empty() || obfs != "wss" ||
                   !parseQuanXTransport(options, reality, transport)) {
            return QuanXProxyParseResult::Invalid;
        }
        if ((!alpn_list.empty() && transport.tls != "tls") ||
            (!tls_verification.is_undef() && transport.tls != "tls"))
            return QuanXProxyParseResult::Invalid;
        trojanConstruct(node, TROJAN_DEFAULT_GROUP, remarks, server, port, password,
                        transport.network, transport.host, transport.path, "", transport.sni,
                        alpn_list, true, udp, tfo, scv);
        node.TLSStr = transport.tls;
        node.PublicKey = public_key;
        node.ShortId = short_id;
        return QuanXProxyParseResult::Parsed;
    }

    if (!quanXOptionsAreKnown(options, {"password", "over-tls", "tls-host",
                                         "reality-base64-pubkey", "reality-hex-shortid",
                                         "tls-alpn", "fast-open", "udp-relay",
                                         "tls-verification", "tag"}))
        return QuanXProxyParseResult::Invalid;
    std::string over_tls, tls_host;
    quanXOption(options, "over-tls", over_tls);
    quanXOption(options, "tls-host", tls_host);
    if (over_tls != "true" || (reality && tls_host.empty()))
        return QuanXProxyParseResult::Invalid;
    anyTlSConstruct(node, ANYTLS_DEFAULT_GROUP, remarks, port, password, server,
                    alpn_list, "", tls_host, udp, tfo, scv, tribool(), "", 30, 30, 0);
    node.TLSStr = reality ? "reality" : "tls";
    node.TLSSecure = true;
    node.PublicKey = public_key;
    node.ShortId = short_id;
    return QuanXProxyParseResult::Parsed;
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
    ini.add_direct_save_section("server_local");
    if (surge.find("[Proxy]") != surge.npos)
        surge = regReplace(surge, R"(^[\S\s]*?\[)", "[", false);
    ini.parse(surge);

    if (!ini.section_exist("Proxy") && !ini.section_exist("server_local"))
        return false;
    if (ini.section_exist("Proxy")) {
        string_multimap section_proxies;
        ini.get_items("Proxy", section_proxies);
        proxies.insert(section_proxies.begin(), section_proxies.end());
    }
    if (ini.section_exist("server_local")) {
        string_multimap section_proxies;
        ini.get_items("server_local", section_proxies);
        proxies.insert(section_proxies.begin(), section_proxies.end());
    }

    const std::string proxystr = "(.*?)\\s*=\\s*(.*)";

    for (auto &x: proxies) {
        std::string remarks, server, port, method, username, password, sni; //common
        std::string plugin, pluginopts, pluginopts_mode, pluginopts_host, mod_url, mod_md5; //ss
        std::string id, net, tls, host, edge, path, fp; //v2
        std::string protocol, protoparam; //ssr
        std::string section, ip, ipv6, private_key, public_key, mtu, test_url, client_id, peer, keepalive; //wireguard
        string_array dns_servers;
        string_multimap wireguard_config;
        std::string version, aead = "1", obfs_uri, reuse_text, snell_mode,
                    snell_udp_port, shadow_tls_password, shadow_tls_sni,
                    shadow_tls_version;
        std::string itemName, itemVal, config;
        std::vector<std::string> configs, vArray, headers, header;
        tribool udp, tfo, scv, tls13, reuse;
        Proxy node;

        /*
        remarks = regReplace(x.second, proxystr, "$1");
        configs = split(regReplace(x.second, proxystr, "$2"), ",");
        */
        regGetMatch(x.second, proxystr, 3, 0, &remarks, &config);
        configs = splitWireGuardFields(config);
        if (configs.empty() || (configs.size() < 3 && configs[0] != "wireguard"))
            continue;
        const LoonProxyParseResult loon_result =
                parseLoonProxyLine(configs, remarks, node);
        if (loon_result == LoonProxyParseResult::Invalid)
            continue;
        if (loon_result == LoonProxyParseResult::Parsed) {
            node.Id = index;
            nodes.emplace_back(std::move(node));
            index++;
            continue;
        }
        const QuanXProxyParseResult quanx_result =
                parseQuanXProxyLine(configs, remarks, node);
        if (quanx_result == QuanXProxyParseResult::Invalid)
            continue;
        if (quanx_result == QuanXProxyParseResult::Parsed) {
            node.Id = index;
            nodes.emplace_back(std::move(node));
            index++;
            continue;
        }
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
                    const size_t equal = configs[i].find('=');
                    if (equal == std::string::npos)
                        continue;
                    itemName = toLower(trim(configs[i].substr(0, equal)));
                    itemVal = stripWireGuardQuotes(
                        configs[i].substr(equal + 1));
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
                        case "obfs-uri"_hash:
                            obfs_uri = itemVal;
                            break;
                        case "reuse"_hash:
                            reuse_text = itemVal;
                            reuse = itemVal;
                            break;
                        case "mode"_hash:
                            snell_mode = toLower(itemVal);
                            break;
                        case "udp-port"_hash:
                            snell_udp_port = itemVal;
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
                        case "shadow-tls-password"_hash:
                            shadow_tls_password = itemVal;
                            break;
                        case "shadow-tls-sni"_hash:
                            shadow_tls_sni = itemVal;
                            break;
                        case "shadow-tls-version"_hash:
                            shadow_tls_version = itemVal;
                            break;
                        default:
                            continue;
                    }
                }

                {
                    const int snell_version = version.empty()
                                                  ? 1
                                                  : to_int(version, 0);
                    const uint16_t parsed_udp_port = parseUint16Option(
                        snell_udp_port, 0);
                    const uint16_t parsed_shadow_version = parseUint16Option(
                        shadow_tls_version, 0);
                    const bool has_shadow_tls =
                        !shadow_tls_password.empty() ||
                        !shadow_tls_sni.empty() ||
                        !shadow_tls_version.empty();
                    const bool valid_obfs =
                        plugin.empty() || plugin == "http" ||
                        (plugin == "tls" && snell_version <= 3);
                    if (password.empty() || snell_version < 1 ||
                        snell_version > 6 ||
                        (!reuse_text.empty() && reuse.is_undef()) ||
                        !valid_obfs ||
                        (snell_version >= 4 && plugin == "tls") ||
                        (snell_version == 6 &&
                         (!plugin.empty() || !host.empty() ||
                          !obfs_uri.empty())) ||
                        (!obfs_uri.empty() && plugin != "http") ||
                        (!snell_udp_port.empty() &&
                         (parsed_udp_port == 0 || snell_version < 3)) ||
                        (snell_version == 6
                             ? (!snell_mode.empty() &&
                                snell_mode != "default" &&
                                snell_mode != "unshaped" &&
                                snell_mode != "unsafe-raw")
                             : !snell_mode.empty()) ||
                        (has_shadow_tls &&
                         (shadow_tls_password.empty() || !plugin.empty() ||
                          (parsed_shadow_version != 0 &&
                           parsed_shadow_version != 2 &&
                           parsed_shadow_version != 3) ||
                          (parsed_shadow_version == 3 &&
                           shadow_tls_sni.empty()))))
                        continue;
                    snellConstruct(node, SNELL_DEFAULT_GROUP, remarks, server,
                                   port, password, plugin, host, obfs_uri,
                                   static_cast<uint16_t>(snell_version), reuse,
                                   udp, tfo, scv);
                    node.SnellMode = snell_mode;
                    node.SnellUDPPort = parsed_udp_port;
                    node.ShadowTLSPassword = shadow_tls_password;
                    node.ShadowTLSSNI = shadow_tls_sni;
                    node.ShadowTLSVersion = parsed_shadow_version;
                }
                break;
            case "wireguard"_hash: {
                for (i = 1; i < configs.size(); i++) {
                    const size_t equal = configs[i].find('=');
                    if (equal == std::string::npos)
                        continue;
                    itemName = toLower(trim(configs[i].substr(0, equal)));
                    itemVal = stripWireGuardQuotes(configs[i].substr(equal + 1));
                    switch (hash_(itemName)) {
                        case "section-name"_hash:
                            section = itemVal;
                            break;
                        case "test-url"_hash:
                            test_url = itemVal;
                            break;
                        case "interface-ip"_hash:
                            ip = itemVal;
                            break;
                        case "interface-ipv6"_hash:
                        case "interface-ip-v6"_hash:
                            ipv6 = itemVal;
                            break;
                        case "private-key"_hash:
                            private_key = itemVal;
                            break;
                        case "dns"_hash:
                        case "dnsv6"_hash:
                            if (!itemVal.empty())
                                dns_servers.emplace_back(itemVal);
                            break;
                        case "mtu"_hash:
                            mtu = itemVal;
                            break;
                        case "keepalive"_hash:
                            keepalive = itemVal;
                            break;
                        case "peers"_hash:
                            peer = itemVal;
                            break;
                        case "udp"_hash:
                        case "udp-relay"_hash:
                            udp = itemVal;
                            break;
                    }
                }
                if (!section.empty()) {
                    ini.get_items("WireGuard " + section, wireguard_config);
                    if (wireguard_config.empty())
                        continue;

                    for (auto &c: wireguard_config) {
                        itemName = toLower(trim(c.first));
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
                                if (!peer.empty())
                                    peer += ",";
                                peer += itemVal;
                                break;
                            case "keepalive"_hash:
                                keepalive = itemVal;
                                break;
                            case "preshared-key"_hash:
                            case "pre-shared-key"_hash:
                                password = itemVal;
                                break;
                        }
                    }
                }

                wireguardConstruct(node, WG_DEFAULT_GROUP, remarks, "", "0", ip, ipv6, private_key, "", "", dns_servers,
                                   mtu, keepalive, test_url, "", udp, "");
                if (!section.empty())
                    node.WireGuardInterfaceName = section;
                if (!peer.empty() && peer.find('{') != std::string::npos) {
                    peer = replaceAllDistinct(replaceAllDistinct(peer, "{", "("), "}", ")");
                }
                parsePeers(node, peer);
                if (!password.empty()) {
                    for (WireGuardPeer &parsed_peer : node.WireGuardPeers)
                        if (parsed_peer.PreSharedKey.empty())
                            parsed_peer.PreSharedKey = password;
                }
                const uint16_t common_keepalive = parseUint16Option(keepalive, 0);
                if (common_keepalive > 0) {
                    for (WireGuardPeer &parsed_peer : node.WireGuardPeers)
                        if (parsed_peer.KeepAlive == 0)
                            parsed_peer.KeepAlive = common_keepalive;
                }
                syncLegacyWireGuardProjection(node);
                if (node.PrivateKey.empty() || node.WireGuardLocalAddresses.empty() ||
                    node.WireGuardPeers.empty())
                    continue;
                break;
            }
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

    if (!json.HasMember("Server") || !json["Server"].IsArray())
        return;

    for (rapidjson::SizeType i = 0; i < json["Server"].Size(); i++) {
        Proxy node;
        if (!parseNetchNode(json["Server"][i], node))
            continue;

        node.Id = index;
        nodes.emplace_back(std::move(node));
        index++;
    }
}

int explodeConfContent(const std::string &content, std::vector<Proxy> &nodes) {
    ConfType filetype = ConfType::Unknow;
    bool looks_like_singbox = false;

    const auto first_non_space = std::find_if_not(
        content.begin(), content.end(),
        [](unsigned char ch) { return std::isspace(ch) != 0; });
    if (first_non_space != content.end() &&
        (*first_non_space == '[' || *first_non_space == '{')) {
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
        else if (!structured_json.HasParseError() && structured_json.IsObject() &&
                 structured_json.HasMember("Server") &&
                 structured_json["Server"].IsArray() &&
                 std::any_of(structured_json["Server"].Begin(),
                             structured_json["Server"].End(),
                             [](const rapidjson::Value &value) {
                                 return value.IsObject() &&
                                        value.HasMember("Type") &&
                                        value.HasMember("Hostname") &&
                                        value.HasMember("Port");
                             }))
            filetype = ConfType::Netch;
        if (!structured_json.HasParseError() && structured_json.IsObject()) {
            looks_like_singbox =
                (structured_json.HasMember("outbounds") &&
                 structured_json["outbounds"].IsArray()) ||
                (structured_json.HasMember("endpoints") &&
                 structured_json["endpoints"].IsArray());
        }
    }

    if (!looks_like_singbox) {
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
        else if (strFind(content, "\"local_address\"") &&
                 strFind(content, "\"local_port\""))
            filetype = ConfType::SSR; //use ssr config parser
        else if (strFind(content, "\"ModeFileNameType\""))
            filetype = ConfType::Netch;
    }

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

bool explodeSingboxTransport(const rapidjson::Value &singboxNode, std::string &net, std::string &host,
                             std::string &path, std::string &edge) {
    if (singboxNode.HasMember("transport") && singboxNode["transport"].IsObject()) {
        const rapidjson::Value &transport = singboxNode["transport"];
        net = GetMember(transport, "type");
        switch (hash_(net)) {
            case "tcp"_hash:
                break;
            case "http"_hash: {
                if (transport.HasMember("host")) {
                    const rapidjson::Value &host_value = transport["host"];
                    if (host_value.IsString())
                        host = host_value.GetString();
                    else if (host_value.IsArray() && !host_value.Empty() && host_value[0].IsString())
                        host = host_value[0].GetString();
                    else
                        return false;
                }
                path = GetMember(transport, "path");
                break;
            }
            case "ws"_hash: {
                path = GetMember(transport, "path");
                if (transport.HasMember("headers") && transport["headers"].IsObject()) {
                    const rapidjson::Value &headers = transport["headers"];
                    host = GetMember(headers, "Host");
                    edge = GetMember(headers, "Edge");
                }
                break;
            }
            case "grpc"_hash: {
                path = GetMember(transport, "service_name");
                break;
            }
            case "httpupgrade"_hash: {
                host = GetMember(transport, "host");
                path = GetMember(transport, "path");
                break;
            }
            default:
                return false;
        }
    } else {
        net = "tcp";
        host.clear();
        edge.clear();
        path.clear();
    }
    return true;
}

namespace {

std::string wireGuardAddressWithoutPrefix(const std::string &address) {
    const std::string cleaned = trim(address);
    const size_t slash = cleaned.find('/');
    return slash == std::string::npos ? cleaned : cleaned.substr(0, slash);
}

bool explodeSingboxWireGuardNode(const rapidjson::Value &singboxNode,
                                 bool endpoint_schema, Proxy &node) {
    if (!singboxNode.IsObject())
        return false;
    const std::string remarks = GetMember(singboxNode, "tag");
    string_array local_addresses;
    const char *address_key = endpoint_schema ? "address" : "local_address";
    if (singboxNode.HasMember(address_key))
        local_addresses = jsonStringArray(singboxNode[address_key]);
    if (local_addresses.empty()) {
        const std::string ip = GetMember(singboxNode, "inet4_bind_address");
        const std::string ipv6 = GetMember(singboxNode, "inet6_bind_address");
        if (!ip.empty())
            local_addresses.emplace_back(ip);
        if (!ipv6.empty())
            local_addresses.emplace_back(ipv6);
    }

    std::string self_ip, self_ipv6;
    for (const std::string &address : local_addresses) {
        const std::string bare = wireGuardAddressWithoutPrefix(address);
        if (self_ip.empty() && isIPv4(bare))
            self_ip = bare;
        else if (self_ipv6.empty() && isIPv6(bare))
            self_ipv6 = bare;
    }

    wireguardConstruct(node, WG_DEFAULT_GROUP, remarks, "", "0", self_ip,
                       self_ipv6, GetMember(singboxNode, "private_key"), "", "",
                       {}, GetMember(singboxNode, "mtu"), "0", "", "",
                       tribool(), "");
    node.WireGuardLocalAddresses = local_addresses;
    node.WireGuardInterfaceName = GetMember(singboxNode, "name");
    if (node.WireGuardInterfaceName.empty())
        node.WireGuardInterfaceName = GetMember(singboxNode, "interface_name");
    node.WireGuardListenPort = parseUint16Option(
        GetMember(singboxNode, "listen_port"), 0);
    node.WireGuardWorkers = parseUint16Option(
        GetMember(singboxNode, "workers"), 0);
    const char *system_key = endpoint_schema ? "system" : "system_interface";
    if (singboxNode.HasMember(system_key) && singboxNode[system_key].IsBool())
        node.WireGuardSystem = singboxNode[system_key].GetBool();

    node.WireGuardPeers.clear();
    if (singboxNode.HasMember("peers") && singboxNode["peers"].IsArray()) {
        for (const auto &peer_value : singboxNode["peers"].GetArray()) {
            WireGuardPeer peer = parseSingBoxWireGuardPeer(peer_value, endpoint_schema);
            if (validWireGuardPeer(peer))
                node.WireGuardPeers.emplace_back(std::move(peer));
        }
    } else if (!endpoint_schema) {
        WireGuardPeer peer;
        peer.Hostname = GetMember(singboxNode, "server");
        peer.Port = parseUint16Option(GetMember(singboxNode, "server_port"), 0);
        peer.PublicKey = GetMember(singboxNode, "peer_public_key");
        if (peer.PublicKey.empty())
            peer.PublicKey = GetMember(singboxNode, "public_key");
        peer.PreSharedKey = GetMember(singboxNode, "pre_shared_key");
        if (singboxNode.HasMember("reserved"))
            peer.Reserved = jsonWireGuardReserved(singboxNode["reserved"]);
        if (validWireGuardPeer(peer))
            node.WireGuardPeers.emplace_back(std::move(peer));
    }
    syncLegacyWireGuardProjection(node);
    return !node.PrivateKey.empty() && !node.WireGuardLocalAddresses.empty() &&
           !node.WireGuardPeers.empty();
}

bool singBoxSnellMembersSupported(const rapidjson::Value &value) {
    static constexpr const char *allowed[] = {
        "type",       "tag",          "server",      "server_port",
        "version",    "psk",          "userkey",     "reuse",
        "network",    "obfs_mode",    "obfs_host",   "mode",
        "tcp_fast_open",
    };
    for (auto member = value.MemberBegin(); member != value.MemberEnd(); ++member) {
        bool known = false;
        for (const char *name : allowed) {
            if (std::string(member->name.GetString(),
                            member->name.GetStringLength()) == name) {
                known = true;
                break;
            }
        }
        if (!known)
            return false;
    }
    return true;
}

bool parseSingBoxSnellNetwork(const rapidjson::Value &value,
                              std::string &network) {
    bool has_tcp = false, has_udp = false;
    auto add_network = [&](const rapidjson::Value &item) {
        if (!item.IsString())
            return false;
        const std::string candidate = item.GetString();
        if (candidate == "tcp") {
            if (has_tcp)
                return false;
            has_tcp = true;
            return true;
        }
        if (candidate == "udp") {
            if (has_udp)
                return false;
            has_udp = true;
            return true;
        }
        return false;
    };

    if (value.IsString()) {
        if (!add_network(value))
            return false;
    } else if (value.IsArray()) {
        if (value.Empty())
            return false;
        for (const auto &item : value.GetArray()) {
            if (!add_network(item))
                return false;
        }
    } else {
        return false;
    }

    network = has_tcp && has_udp ? std::string() : has_tcp ? "tcp" : "udp";
    return has_tcp || has_udp;
}

bool explodeSingboxSnellNode(const rapidjson::Value &singboxNode,
                             Proxy &node) {
    auto reject = [](const char *reason) {
        writeLog(LOG_LEVEL_DEBUG,
                 "SINGBOX_SNELL_IMPORT_REJECTED reason=" +
                     std::string(reason));
        return false;
    };
    if (!singboxNode.IsObject() ||
        !singBoxSnellMembersSupported(singboxNode) ||
        !singboxNode.HasMember("server") ||
        !singboxNode["server"].IsString() ||
        !singboxNode.HasMember("server_port") ||
        !singboxNode["server_port"].IsUint() ||
        !singboxNode.HasMember("version") ||
        !singboxNode["version"].IsUint() ||
        !singboxNode.HasMember("psk") || !singboxNode["psk"].IsString())
        return reject("schema");

    const std::string server = singboxNode["server"].GetString();
    const unsigned int port = singboxNode["server_port"].GetUint();
    const unsigned int version = singboxNode["version"].GetUint();
    const std::string password = singboxNode["psk"].GetString();
    if (server.empty() || port == 0 || port > 65535 || password.empty() ||
        (version != 4 && version != 6))
        return reject("required-field");

    std::string remarks;
    if (singboxNode.HasMember("tag")) {
        if (!singboxNode["tag"].IsString())
            return reject("tag-type");
        remarks = singboxNode["tag"].GetString();
    }

    std::string userkey;
    if (singboxNode.HasMember("userkey")) {
        if (!singboxNode["userkey"].IsString())
            return reject("userkey-type");
        userkey = singboxNode["userkey"].GetString();
        if (userkey.size() > 255)
            return reject("userkey-length");
    }

    tribool reuse, tfo;
    if (singboxNode.HasMember("reuse")) {
        if (!singboxNode["reuse"].IsBool())
            return reject("reuse-type");
        reuse = singboxNode["reuse"].GetBool();
    }
    if (singboxNode.HasMember("tcp_fast_open")) {
        if (!singboxNode["tcp_fast_open"].IsBool())
            return reject("tcp-fast-open-type");
        tfo = singboxNode["tcp_fast_open"].GetBool();
    }

    std::string network;
    if (singboxNode.HasMember("network") &&
        !parseSingBoxSnellNetwork(singboxNode["network"], network))
        return reject("network");

    std::string obfs, obfs_host, mode;
    if (singboxNode.HasMember("obfs_mode")) {
        if (!singboxNode["obfs_mode"].IsString())
            return reject("obfs-mode-type");
        obfs = singboxNode["obfs_mode"].GetString();
    }
    if (singboxNode.HasMember("obfs_host")) {
        if (!singboxNode["obfs_host"].IsString())
            return reject("obfs-host-type");
        obfs_host = singboxNode["obfs_host"].GetString();
    }
    if (singboxNode.HasMember("mode")) {
        if (!singboxNode["mode"].IsString())
            return reject("mode-type");
        mode = singboxNode["mode"].GetString();
    }

    if (version == 4) {
        if (!mode.empty() || (obfs != "" && obfs != "none" && obfs != "http") ||
            (!obfs_host.empty() && obfs != "http"))
            return reject("version-4-fields");
        if (obfs == "none")
            obfs.clear();
    } else {
        if (password.size() < 12 || password.size() > 255 || !obfs.empty() ||
            !obfs_host.empty() ||
            (mode != "" && mode != "default" && mode != "unshaped" &&
             mode != "unsafe-raw"))
            return reject("version-6-fields");
    }

    snellConstruct(node, SNELL_DEFAULT_GROUP, remarks, server,
                   std::to_string(port), password, obfs, obfs_host, "",
                   static_cast<uint16_t>(version), reuse,
                   network == "tcp" ? tribool(false) : tribool(true), tfo,
                   tribool());
    node.SnellUserKey = userkey;
    node.SnellNetwork = network;
    node.SnellMode = mode;
    return true;
}

} // namespace

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
            std::string auth, auth_str, up, down, obfsParam, insecure, alpn,
                        hysteria_network, hop_interval; //hysteria
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
                    if (tlsObj.HasMember("alpn")) {
                        if (!tlsObj["alpn"].IsArray())
                            continue;
                        for (const auto &item : tlsObj["alpn"].GetArray()) {
                            if (!item.IsString()) {
                                alpnList.clear();
                                break;
                            }
                            alpnList.emplace_back(item.GetString());
                        }
                        if (alpnList.empty() && !tlsObj["alpn"].Empty())
                            continue;
                        if (!alpnList.empty())
                            alpn = alpnList.front();
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
                        if (id.length() < 36)
                            continue;
                        aid = GetMember(singboxNode, "alter_id");
                        cipher = GetMember(singboxNode, "security");
                        if (!explodeSingboxTransport(singboxNode, net, host, path, edge))
                            continue;
                        vmessConstruct(node, group, ps, server, port, "", id, aid, net, cipher, path, host, edge, tls,
                                       sni, alpnList, udp,
                                       tfo, scv);
                        node.Fingerprint = fingerprint;
                        node.PublicKey = pbk;
                        node.ShortId = sid;
                        if (net == "grpc") {
                            node.GRPCServiceName = path;
                            node.GRPCMode = "gun";
                        }
                        break;
                    case "shadowsocks"_hash:
                        group = SS_DEFAULT_GROUP;
                        cipher = GetMember(singboxNode, "method");
                        password = GetMember(singboxNode, "password");
                        plugin = GetMember(singboxNode, "plugin");
                        pluginopts = GetMember(singboxNode, "plugin_opts");
                        ssConstruct(node, group, ps, server, port, password, cipher, plugin, pluginopts, udp, tfo, scv);
                        break;
                    case "snell"_hash:
                        if (!explodeSingboxSnellNode(singboxNode, node))
                            continue;
                        break;
                    case "trojan"_hash:
                        if (tls != "tls" && tls != "reality")
                            continue;
                        group = TROJAN_DEFAULT_GROUP;
                        password = GetMember(singboxNode, "password");
                        if (!explodeSingboxTransport(singboxNode, net, host, path, edge))
                            continue;
                        trojanConstruct(node, group, ps, server, port, password, net, host, path, fingerprint, sni, alpnList,
                                        true, udp,
                                        tfo,
                                        scv);
                        node.TLSStr = tls;
                        node.PublicKey = pbk;
                        node.ShortId = sid;
                        if (net == "grpc") {
                            node.GRPCServiceName = path;
                            node.GRPCMode = "gun";
                        }
                        break;
                    case "vless"_hash:
                        group = XRAY_DEFAULT_GROUP;
                        id = GetMember(singboxNode, "uuid");
                        flow = GetMember(singboxNode, "flow");
                        packet_encoding = GetMember(singboxNode, "packet_encoding");
                        if (!explodeSingboxTransport(singboxNode, net, host, path, edge))
                            continue;

                        vlessConstruct(node, group, ps, server, port, type, id, aid, net, "auto", flow, mode, path,
                                       host, "", tls, pbk, sid, fingerprint, sni, alpnList, packet_encoding, udp);
                        if (net == "grpc") {
                            node.GRPCServiceName = path;
                            node.GRPCMode = "gun";
                        }
                        break;
                    case "http"_hash:
                        password = GetMember(singboxNode, "password");
                        user = GetMember(singboxNode, "username");
                        httpConstruct(node, group, ps, server, port, user, password, tls == "tls", tfo, scv);
                        break;
                    case "wireguard"_hash:
                        if (!explodeSingboxWireGuardNode(singboxNode, false, node))
                            continue;
                        break;
                    case "socks"_hash:
                        group = SOCKS_DEFAULT_GROUP;
                        user = GetMember(singboxNode, "username");
                        password = GetMember(singboxNode, "password");
                        socksConstruct(node, group, ps, server, port, user, password);
                        break;
                    case "hysteria"_hash:
                        group = HYSTERIA_DEFAULT_GROUP;
                        if (tls != "tls")
                            continue;
                        up = GetMember(singboxNode, "up");
                        if (up.empty()) {
                            up = GetMember(singboxNode, "up_mbps");
                        }
                        down = GetMember(singboxNode, "down");
                        if (down.empty()) {
                            down = GetMember(singboxNode, "down_mbps");
                        }
                        if (up.empty() || down.empty())
                            continue;
                        auth_str = GetMember(singboxNode, "auth_str");
                        auth = GetMember(singboxNode, "auth");
                        if (singboxNode.HasMember("network")) {
                            const auto &network_value = singboxNode["network"];
                            if (network_value.IsString()) {
                                hysteria_network = network_value.GetString();
                                if (!normalizeHysteriaNetwork(
                                        hysteria_network))
                                    continue;
                            } else if (network_value.IsArray()) {
                                bool has_tcp = false, has_udp = false;
                                bool valid_networks = true;
                                for (const auto &network_item :
                                     network_value.GetArray()) {
                                    if (!network_item.IsString()) {
                                        valid_networks = false;
                                        break;
                                    }
                                    std::string network =
                                        network_item.GetString();
                                    if (!normalizeHysteriaNetwork(network) ||
                                        network.empty()) {
                                        valid_networks = false;
                                        break;
                                    }
                                    has_tcp = has_tcp || network == "tcp";
                                    has_udp = has_udp || network == "udp";
                                }
                                if (!valid_networks ||
                                    (!has_tcp && !has_udp))
                                    continue;
                                hysteria_network = has_tcp && has_udp
                                                       ? std::string()
                                                       : has_tcp ? "tcp" : "udp";
                            } else {
                                continue;
                            }
                        }
                        if (singboxNode.HasMember("server_ports")) {
                            string_array port_ranges;
                            const auto &server_ports =
                                singboxNode["server_ports"];
                            if (server_ports.IsString()) {
                                port_ranges.emplace_back(
                                    server_ports.GetString());
                            } else if (server_ports.IsArray()) {
                                for (const auto &item :
                                     server_ports.GetArray()) {
                                    if (!item.IsString()) {
                                        port_ranges.clear();
                                        break;
                                    }
                                    port_ranges.emplace_back(item.GetString());
                                }
                            } else {
                                continue;
                            }
                            uint16_t first_port = 0;
                            if (port_ranges.empty() ||
                                !normalizeHysteriaPortSpec(
                                    join(port_ranges, ","), ports,
                                    first_port))
                                continue;
                            port = std::to_string(first_port);
                        }
                        if (!validSharePort(port))
                            continue;
                        hop_interval = GetMember(singboxNode, "hop_interval");
                        if (!validHysteriaHopInterval(hop_interval))
                            continue;
                        obfsParam = GetMember(singboxNode, "obfs");
                        hysteriaConstruct(node, group, ps, server, port, "udp", auth, auth_str, sni, up, down, alpn,
                                          obfsParam, insecure, ports, sni,
                                          udp, tfo, scv);
                        node.AlpnList = alpnList;
                        node.TransferProtocol = hysteria_network;
                        node.HysteriaHopInterval = hop_interval;
                        node.TLSSecure = true;
                        break;
                    case "anytls"_hash:
                        if (tls != "tls" && tls != "reality")
                            continue;
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
                        node.TLSStr = tls;
                        node.TLSSecure = true;
                        node.PublicKey = pbk;
                        node.ShortId = sid;
                        break;
                    case "naive"_hash: {
                        if (tls != "tls" && tls != "reality")
                            continue;
                        user = GetMember(singboxNode, "username");
                        password = GetMember(singboxNode, "password");
                        if (password.empty())
                            continue;
                        bool naive_quic = false;
                        uint32_t insecure_concurrency = 0;
                        if (singboxNode.HasMember("quic")) {
                            if (!singboxNode["quic"].IsBool())
                                continue;
                            naive_quic = singboxNode["quic"].GetBool();
                        }
                        if (singboxNode.HasMember("insecure_concurrency")) {
                            if (!singboxNode["insecure_concurrency"].IsUint())
                                continue;
                            insecure_concurrency =
                                singboxNode["insecure_concurrency"].GetUint();
                        }
                        naiveConstruct(node, NAIVE_DEFAULT_GROUP, ps, port,
                                       user, password, server, alpnList,
                                       fingerprint, sni, scv, naive_quic,
                                       insecure_concurrency);
                        node.TLSStr = tls;
                        node.PublicKey = pbk;
                        node.ShortId = sid;
                        node.CongestionControl =
                            GetMember(singboxNode,
                                      "quic_congestion_control");
                        if (singboxNode.HasMember("udp_over_tcp")) {
                            if (!singboxNode["udp_over_tcp"].IsBool())
                                continue;
                            node.NaiveUot =
                                singboxNode["udp_over_tcp"].GetBool();
                        }
                        break;
                    }
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
                        node.TLSStr = tls.empty() ? "tls" : tls;
                        node.PublicKey = pbk;
                        node.ShortId = sid;
                        node.Fingerprint = fingerprint;
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

void explodeSingboxEndpoints(rapidjson::Value &endpoints,
                             std::vector<Proxy> &nodes) {
    uint32_t index = nodes.size();
    if (!endpoints.IsArray())
        return;
    for (auto &endpoint : endpoints.GetArray()) {
        if (!endpoint.IsObject() || GetMember(endpoint, "type") != "wireguard")
            continue;
        Proxy node;
        if (!explodeSingboxWireGuardNode(endpoint, true, node))
            continue;
        node.Id = index++;
        nodes.emplace_back(std::move(node));
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
    node.TLSStr = decodedUrlArg(parsed.query, "security");
    if (node.TLSStr.empty())
        node.TLSStr = "tls";
    node.PublicKey = decodedUrlArg(parsed.query, "pbk");
    node.ShortId = decodedUrlArg(parsed.query, "sid");
    node.Fingerprint = decodedUrlArg(parsed.query, "fp");
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
    node.TLSStr = decodedUrlArg(parsed.query, "security");
    if (node.TLSStr.empty())
        node.TLSStr = "tls";
    node.PublicKey = decodedUrlArg(parsed.query, "pbk");
    node.ShortId = decodedUrlArg(parsed.query, "sid");
}

void explodeNaive(std::string naive, Proxy &node) {
    const bool quic = startsWith(naive, "naive+quic://");
    ParsedShareUri parsed;
    std::string ignored_ports;
    if (!parseModernShareUri(std::move(naive),
                             quic ? "naive+quic" : "naive+https", true,
                             "443", false, parsed, ignored_ports))
        return;

    std::string username;
    std::string password = parsed.user;
    const size_t separator = parsed.user.find(':');
    if (separator != std::string::npos) {
        username = parsed.user.substr(0, separator);
        password = parsed.user.substr(separator + 1);
    }
    if (password.empty())
        return;

    uint32_t insecure_concurrency = 0;
    const std::string concurrency =
        decodedUrlArg(parsed.query, "insecure-concurrency");
    if (!concurrency.empty()) {
        if (!std::all_of(concurrency.begin(), concurrency.end(),
                         [](unsigned char ch) { return std::isdigit(ch) != 0; }))
            return;
        try {
            const unsigned long long parsed_value = std::stoull(concurrency);
            if (parsed_value == 0 ||
                parsed_value > std::numeric_limits<uint32_t>::max())
                return;
            insecure_concurrency = static_cast<uint32_t>(parsed_value);
        } catch (const std::exception &) {
            return;
        }
    }

    if (parsed.remark.empty())
        parsed.remark = parsed.host + ":" + parsed.port;
    const std::string insecure = decodedFirstUrlArg(
        parsed.query, {"insecure", "allow_insecure", "allow-insecure"});
    naiveConstruct(node, NAIVE_DEFAULT_GROUP, parsed.remark, parsed.port,
                   username, password, parsed.host,
                   getUrlAlpnList(parsed.query),
                   decodedFirstUrlArg(parsed.query, {"fp", "fingerprint"}),
                   decodedUrlArg(parsed.query, "sni"), tribool(insecure), quic,
                   insecure_concurrency);
    node.TLSStr = decodedUrlArg(parsed.query, "security");
    if (node.TLSStr.empty())
        node.TLSStr = "tls";
    node.PublicKey = decodedUrlArg(parsed.query, "pbk");
    node.ShortId = decodedUrlArg(parsed.query, "sid");
}

void explodeWireGuard(std::string wireguard, Proxy &node) {
    ParsedShareUri parsed;
    if (!parseShareUri(std::move(wireguard), "wireguard", parsed))
        return;

    const std::string public_key = decodedUrlArg(parsed.query, "publickey");
    const std::string address = decodedUrlArg(parsed.query, "address");
    if (parsed.user.empty() || public_key.empty() || address.empty())
        return;

    string_array local_addresses;
    std::string self_ip;
    std::string self_ipv6;
    for (std::string item : split(address, ",")) {
        item = trim(item);
        if (item.empty())
            return;
        const size_t slash = item.find('/');
        const std::string host = slash == std::string::npos
                                     ? item
                                     : item.substr(0, slash);
        const std::string prefix = slash == std::string::npos
                                       ? std::string()
                                       : item.substr(slash + 1);
        if (slash != std::string::npos &&
            (prefix.empty() || prefix.size() > 3 ||
             !std::all_of(prefix.begin(), prefix.end(), [](unsigned char ch) {
                 return std::isdigit(ch) != 0;
             })))
            return;
        if (isIPv4(host)) {
            if (!self_ip.empty())
                return;
            if (!prefix.empty() && to_int(prefix, -1) > 32)
                return;
            self_ip = host;
            if (slash == std::string::npos)
                item += "/32";
        } else if (isIPv6(host)) {
            if (!self_ipv6.empty())
                return;
            if (!prefix.empty() && to_int(prefix, -1) > 128)
                return;
            self_ipv6 = host;
            if (slash == std::string::npos)
                item += "/128";
        } else {
            return;
        }
        local_addresses.emplace_back(std::move(item));
    }

    const std::string mtu = decodedUrlArg(parsed.query, "mtu");
    if (!mtu.empty() && parseUint16Option(mtu, 0) == 0)
        return;
    const std::string reserved = normalizeWireGuardReserved(
        decodedUrlArg(parsed.query, "reserved"));
    if (!decodedUrlArg(parsed.query, "reserved").empty() && reserved.empty())
        return;

    if (parsed.remark.empty())
        parsed.remark = parsed.host + ":" + parsed.port;
    wireguardConstruct(node, WG_DEFAULT_GROUP, parsed.remark, parsed.host,
                       parsed.port, self_ip, self_ipv6, parsed.user, public_key,
                       decodedUrlArg(parsed.query, "presharedkey"), {}, mtu,
                       "0", "", reserved, tribool(), "");
    node.WireGuardLocalAddresses = std::move(local_addresses);
    syncLegacyWireGuardProjection(node);
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
    else if (startsWith(link, "naive+https://") ||
             startsWith(link, "naive+quic://"))
        explodeNaive(link, node);
    else if (startsWith(link, "wireguard://"))
        explodeWireGuard(link, node);
    else if (startsWith(link, "hysteria2+realm://") ||
             startsWith(link, "hysteria2+realm+http://"))
        explodeHysteria2Realm(link, node);
    else if (strFind(link, "hysteria2://") || strFind(link, "hy2://"))
        explodeHysteria2(link, node);
    else if (startsWith(link, "mierus://") || startsWith(link, "mieru://"))
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
        if (!processed && !sub.empty() && sub.front() == '{') {
            rapidjson::Document document;
            document.Parse(sub.c_str());
            if (!document.HasParseError() && document.IsObject()) {
                const size_t before = nodes.size();
                if (document.HasMember("outbounds") &&
                    document["outbounds"].IsArray())
                    explodeSingbox(document["outbounds"], nodes);
                if (document.HasMember("endpoints") &&
                    document["endpoints"].IsArray())
                    explodeSingboxEndpoints(document["endpoints"], nodes);
                processed = nodes.size() > before;
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
        if (sub.find("[Proxy]") != std::string::npos ||
            regFind(sub, "(?i)(vmess|vless|shadowsocks|hysteria2|anytls|http|trojan)\\s*?=")) {
            if (explodeSurge(sub, nodes))
                return;
        }
        strstream << sub;
        char delimiter =
                count(sub.begin(), sub.end(), '\n') < 1 ? count(sub.begin(), sub.end(), '\r') < 1 ? ' ' : '\r' : '\n';
        while (getline(strstream, strLink, delimiter)) {
            if (strLink.rfind('\r') != std::string::npos)
                strLink.erase(strLink.size() - 1);
            if (startsWith(strLink, "mierus://")) {
                explodeMierusNodes(strLink, nodes);
                continue;
            }
            Proxy node;
            explode(strLink, node);
            if (strLink.empty() || node.Type == ProxyType::Unknown) {
                continue;
            }
            nodes.emplace_back(std::move(node));
        }
    }
}
