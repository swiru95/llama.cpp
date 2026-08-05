#include "server-ssrf.h"
#include "common.h"
#include "server-common.h"
#include "log.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <sstream>
#include <vector>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <cmath>

namespace {

// IPv4/IPv6 CIDR entry
struct cidr {
    int family;                // AF_INET or AF_INET6
    uint8_t net[16];           // aligned to 16 bytes for IPv6
    int bits;
    // B1-a: port restriction for allowlist CIDR/IP-literal entries. 0 = no portspec (80/443
    // only), -1 = ":*" (any port), N = specific port. Unused (left at default 0) for the
    // compiled-in BLOCKED_RANGES_V4/V6 tables, which are matched without a port dimension.
    int port = 0;
};

// Hostname allowlist entry
struct hostname_entry {
    std::string hostname;      // case-normalized for comparison
    int port;                  // specific port (1-65535), 0 for 80/443, -1 for any
};

// Allowlist entry (either CIDR or hostname)
struct allowlist_entry {
    bool is_cidr;
    cidr cidr_data;
    hostname_entry host_data;
};

// Configuration state
static std::vector<allowlist_entry> g_allowlist;
static std::vector<cidr> g_blocked_ranges;
static bool g_enabled = false;
static int g_self_port = 0;
static std::string g_self_hostname;

// Blocked ranges (IPv4 and IPv6 as per design section 3.7)
static const std::vector<cidr> BLOCKED_RANGES_V4 = {
    {AF_INET,  {0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},  8},  // 0.0.0.0/8
    {AF_INET,  {0x0a, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},  8},  // 10.0.0.0/8
    {AF_INET,  {0x64, 0x40, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 10},  // 100.64.0.0/10
    {AF_INET,  {0x7f, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},  8},  // 127.0.0.0/8
    {AF_INET,  {0xa9, 0xfe, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 16},  // 169.254.0.0/16
    {AF_INET,  {0xac, 0x10, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 12},  // 172.16.0.0/12
    {AF_INET,  {0xc0, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 24},  // 192.0.0.0/24
    {AF_INET,  {0xc0, 0x00, 0x02, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 24},  // 192.0.2.0/24
    {AF_INET,  {0xc0, 0xa8, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 16},  // 192.168.0.0/16
    {AF_INET,  {0xc6, 0x12, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 15},  // 198.18.0.0/15
    {AF_INET,  {0xc6, 0x33, 0x64, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 24},  // 198.51.100.0/24
    {AF_INET,  {0xcb, 0x00, 0x71, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 24},  // 203.0.113.0/24
    {AF_INET,  {0xe0, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},  4},  // 224.0.0.0/4
    {AF_INET,  {0xf0, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},  4},  // 240.0.0.0/4
};

static const std::vector<cidr> BLOCKED_RANGES_V6 = {
    {AF_INET6, {0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 128}, // ::/128
    {AF_INET6, {0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}, 128}, // ::1/128
    {AF_INET6, {0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 96},  // 64:ff9b::/96
    {AF_INET6, {0x01, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 64},  // 100::/64
    {AF_INET6, {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 32},  // 2001:db8::/32
    {AF_INET6, {0xfc, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},  7},  // fc00::/7
    {AF_INET6, {0xfe, 0x80, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 10},  // fe80::/10
    {AF_INET6, {0xff, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},  8},  // ff00::/8
};

// Check if an address matches a CIDR
static bool prefix_match(const uint8_t * addr, int addr_family, const cidr & c) {
    if (addr_family != c.family) {
        return false;
    }
    int bytes = c.bits / 8;
    int bits = c.bits % 8;
    if (std::memcmp(addr, c.net, bytes) != 0) {
        return false;
    }
    if (bits > 0) {
        uint8_t mask = 0xff << (8 - bits);
        if ((addr[bytes] & mask) != (c.net[bytes] & mask)) {
            return false;
        }
    }
    return true;
}

// Strip IPv4-mapped IPv6 prefix (::ffff:a.b.c.d -> a.b.c.d)
static bool unwrap_v4mapped(struct sockaddr_storage & ss, socklen_t & len) {
    if (ss.ss_family != AF_INET6) {
        return false;
    }
    struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *)&ss;
    // Check for ::ffff:0:0/96 prefix
    if (sin6->sin6_addr.s6_addr[0] == 0 && sin6->sin6_addr.s6_addr[1] == 0 &&
        sin6->sin6_addr.s6_addr[2] == 0 && sin6->sin6_addr.s6_addr[3] == 0 &&
        sin6->sin6_addr.s6_addr[4] == 0 && sin6->sin6_addr.s6_addr[5] == 0 &&
        sin6->sin6_addr.s6_addr[6] == 0 && sin6->sin6_addr.s6_addr[7] == 0 &&
        sin6->sin6_addr.s6_addr[8] == 0 && sin6->sin6_addr.s6_addr[9] == 0 &&
        sin6->sin6_addr.s6_addr[10] == 0xff && sin6->sin6_addr.s6_addr[11] == 0xff) {
        // Unwrap to IPv4
        struct sockaddr_in sin4;
        std::memset(&sin4, 0, sizeof(sin4));
        sin4.sin_family = AF_INET;
        sin4.sin_addr.s_addr = *(uint32_t *)&sin6->sin6_addr.s6_addr[12];
        std::memcpy(&ss, &sin4, sizeof(sin4));
        len = sizeof(sin4);
        return true;
    }
    return false;
}

// Format an address as a string (numeric only, no DNS reverse lookup)
static std::string format_address(const struct sockaddr_storage & ss, socklen_t) {
    char addr_str[INET6_ADDRSTRLEN] = {0};
    if (ss.ss_family == AF_INET) {
        const struct sockaddr_in * sin = (const struct sockaddr_in *)&ss;
        inet_ntop(AF_INET, &sin->sin_addr, addr_str, sizeof(addr_str));
    } else if (ss.ss_family == AF_INET6) {
        const struct sockaddr_in6 * sin6 = (const struct sockaddr_in6 *)&ss;
        inet_ntop(AF_INET6, &sin6->sin6_addr, addr_str, sizeof(addr_str));
    }
    return std::string(addr_str);
}

// Normalize hostname for case-insensitive comparison
static std::string normalize_hostname(std::string host) {
    if (!host.empty() && host.back() == '.') {
        host.pop_back();
    }
    std::transform(host.begin(), host.end(), host.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return host;
}

// Check if hostname matches allowed character set
static bool is_valid_hostname_charset(const std::string & host) {
    for (unsigned char c : host) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'F') || c == '.' || c == ':' || c == '%' || c == '_' || c == '-')) {
            return false;
        }
        // Also reject control bytes, whitespace, special chars per design
        if (c < 32 || c == 127) return false;  // control bytes
        if (c == '/' || c == '@' || c == '\\' || c == '?' || c == '#' || c == '[' || c == ']') {
            return false;
        }
        if (c >= 128) return false;  // non-ASCII
    }
    return true;
}

// Parse a single allowlist entry (target or target:portspec)
static bool parse_allowlist_entry(const std::string & entry_str, allowlist_entry & out) {
    if (entry_str.empty()) {
        return false;
    }

    // Find the last ':' for port separator (but be careful with IPv6 literals)
    int colon_pos = -1;
    bool in_brackets = false;
    for (int i = (int)entry_str.size() - 1; i >= 0; i--) {
        if (entry_str[i] == ']') {
            in_brackets = true;
        } else if (entry_str[i] == '[') {
            in_brackets = false;
        } else if (entry_str[i] == ':' && !in_brackets) {
            colon_pos = i;
            break;
        }
    }

    std::string target = entry_str;
    int port = 0;  // 0 means default (80/443)

    if (colon_pos > 0) {
        target = entry_str.substr(0, colon_pos);
        std::string portspec = entry_str.substr(colon_pos + 1);

        if (portspec == "*") {
            port = -1;  // -1 means any port
            SRV_WRN("cors-proxy: allowlist entry with :* grants all ports: %s\n", entry_str.c_str());
        } else {
            try {
                port = std::stoi(portspec);
                if (port < 1 || port > 65535) {
                    SRV_ERR("cors-proxy: invalid port in allowlist entry: %s\n", entry_str.c_str());
                    return false;
                }
            } catch (...) {
                SRV_ERR("cors-proxy: invalid port in allowlist entry: %s\n", entry_str.c_str());
                return false;
            }
        }
    }

    // Try to parse as CIDR (IPv4 or IPv6)
    std::string cidr_target = target;
    int cidr_bits = -1;

    // Handle [IPv6]/bits format
    if (target.size() > 2 && target[0] == '[' && target[target.size()-1] != ']') {
        // Format is [IPv6]/bits
        size_t bracket_end = target.find(']');
        if (bracket_end != std::string::npos && bracket_end < target.size() - 1 && target[bracket_end + 1] == '/') {
            cidr_target = target.substr(1, bracket_end - 1);
            try {
                cidr_bits = std::stoi(target.substr(bracket_end + 2));
            } catch (...) {
                SRV_ERR("cors-proxy: invalid CIDR bits in allowlist entry: %s\n", entry_str.c_str());
                return false;
            }
        }
    } else if (target.size() > 2 && target[0] == '[' && target[target.size()-1] == ']') {
        // Format is [IPv6] without port or bits
        cidr_target = target.substr(1, target.size() - 2);
    } else {
        // Check for /bits suffix for IPv4
        size_t slash_pos = target.rfind('/');
        if (slash_pos != std::string::npos && slash_pos > 0) {
            try {
                cidr_bits = std::stoi(target.substr(slash_pos + 1));
                cidr_target = target.substr(0, slash_pos);
            } catch (...) {
                // Not a CIDR, treat as hostname
            }
        }
    }

    // Try CIDR parse
    out.is_cidr = false;
    struct in_addr v4addr;
    struct in6_addr v6addr;

    if (cidr_bits >= 0 || inet_pton(AF_INET, cidr_target.c_str(), &v4addr) > 0) {
        // IPv4 CIDR or literal
        out.is_cidr = true;
        out.cidr_data.family = AF_INET;
        std::memset(out.cidr_data.net, 0, 16);
        if (inet_pton(AF_INET, cidr_target.c_str(), out.cidr_data.net) <= 0) {
            SRV_ERR("cors-proxy: invalid IPv4 CIDR in allowlist entry: %s\n", entry_str.c_str());
            return false;
        }
        out.cidr_data.bits = (cidr_bits >= 0) ? cidr_bits : 32;
        if (out.cidr_data.bits > 32) {
            SRV_ERR("cors-proxy: CIDR prefix too large for IPv4 in allowlist entry: %s\n", entry_str.c_str());
            return false;
        }
        if (out.cidr_data.bits == 0) {
            SRV_ERR("cors-proxy: /0 prefix not allowed in allowlist entry: %s\n", entry_str.c_str());
            return false;
        }
        out.cidr_data.port = port;  // B1-a: no portspec means 80/443 only, not "any port"
    } else if (inet_pton(AF_INET6, cidr_target.c_str(), &v6addr) > 0) {
        // IPv6 CIDR or literal
        out.is_cidr = true;
        out.cidr_data.family = AF_INET6;
        std::memset(out.cidr_data.net, 0, 16);
        if (inet_pton(AF_INET6, cidr_target.c_str(), out.cidr_data.net) <= 0) {
            SRV_ERR("cors-proxy: invalid IPv6 CIDR in allowlist entry: %s\n", entry_str.c_str());
            return false;
        }
        out.cidr_data.bits = (cidr_bits >= 0) ? cidr_bits : 128;
        if (out.cidr_data.bits > 128) {
            SRV_ERR("cors-proxy: CIDR prefix too large for IPv6 in allowlist entry: %s\n", entry_str.c_str());
            return false;
        }
        if (out.cidr_data.bits == 0) {
            SRV_ERR("cors-proxy: /0 prefix not allowed in allowlist entry: %s\n", entry_str.c_str());
            return false;
        }
        out.cidr_data.port = port;  // B1-a: no portspec means 80/443 only, not "any port"
    } else {
        // Hostname entry
        if (target.empty() || target.size() > 253) {
            SRV_ERR("cors-proxy: invalid hostname in allowlist entry: %s\n", entry_str.c_str());
            return false;
        }
        if (!is_valid_hostname_charset(target)) {
            SRV_ERR("cors-proxy: invalid characters in hostname allowlist entry: %s\n", entry_str.c_str());
            return false;
        }
        out.is_cidr = false;
        out.host_data.hostname = normalize_hostname(target);
        out.host_data.port = port;
    }

    return true;
}

}  // namespace

bool server_ssrf::configure(const common_params & params) {
    g_allowlist.clear();
    g_enabled = false;
    g_self_port = params.port;
    g_self_hostname = params.hostname;

    if (params.proxy_allowed_hosts.empty()) {
        return true;  // No allowlist configured (deny-by-default)
    }

    // Parse comma-separated allowlist entries
    std::istringstream iss(params.proxy_allowed_hosts);
    std::string entry;
    while (std::getline(iss, entry, ',')) {
        // Trim whitespace
        entry.erase(0, entry.find_first_not_of(" \t\r\n"));
        entry.erase(entry.find_last_not_of(" \t\r\n") + 1);

        if (entry.empty()) {
            continue;
        }

        allowlist_entry ae;
        if (!parse_allowlist_entry(entry, ae)) {
            return false;
        }
        g_allowlist.push_back(ae);
    }

    g_enabled = !g_allowlist.empty();

    // Build blocked ranges table
    g_blocked_ranges.clear();
    g_blocked_ranges.insert(g_blocked_ranges.end(), BLOCKED_RANGES_V4.begin(), BLOCKED_RANGES_V4.end());
    g_blocked_ranges.insert(g_blocked_ranges.end(), BLOCKED_RANGES_V6.begin(), BLOCKED_RANGES_V6.end());

    return true;
}

bool server_ssrf::enabled() {
    return g_enabled;
}

bool server_ssrf::check_target(const std::string & host, int port,
                               server_ssrf_target & out, std::string & out_log_reason) {
    // S1: allowlist non-empty
    if (!g_enabled) {
        out_log_reason = "no allowlist configured";
        return false;
    }

    // S2: port sanity
    if (port < 1 || port > 65535) {
        out_log_reason = "bad port";
        return false;
    }

    // S3: hostname sanity
    std::string normalized_host = host;
    std::transform(normalized_host.begin(), normalized_host.end(), normalized_host.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (!normalized_host.empty() && normalized_host.back() == '.') {
        normalized_host.pop_back();
    }

    if (normalized_host.empty() || normalized_host.size() > 253) {
        out_log_reason = "bad hostname";
        return false;
    }

    for (unsigned char c : normalized_host) {
        if (c < 32 || c == 127 || c >= 128) {
            out_log_reason = "bad hostname";
            return false;
        }
        if (c == '/' || c == '@' || c == '\\' || c == '?' || c == '#' || c == '[' || c == ']') {
            out_log_reason = "bad hostname";
            return false;
        }
        // Also check for embedded NUL (R-A2)
        if (c == '\0') {
            out_log_reason = "bad hostname";
            return false;
        }
    }

    // S4: resolve
    struct addrinfo hints;
    struct addrinfo * res = nullptr;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    // Check if it's an IP literal first
    struct in_addr v4addr;
    struct in6_addr v6addr;
    bool is_ipv4_literal = (inet_pton(AF_INET, normalized_host.c_str(), &v4addr) > 0);
    bool is_ipv6_literal = (inet_pton(AF_INET6, normalized_host.c_str(), &v6addr) > 0);

    // Only resolve if it's not an IP literal OR if it's a literal that should be resolved
    if (!is_ipv4_literal && !is_ipv6_literal) {
        // Check if this hostname is in the allowlist before resolving (R-A6: never resolve unless matchable)
        bool hostname_in_allowlist = false;
        for (const auto & entry : g_allowlist) {
            if (!entry.is_cidr && entry.host_data.hostname == normalized_host) {
                hostname_in_allowlist = true;
                break;
            }
        }
        if (!hostname_in_allowlist) {
            out_log_reason = "hostname not in allowlist";
            return false;
        }

        int ret = getaddrinfo(normalized_host.c_str(), nullptr, &hints, &res);
        if (ret != 0 || res == nullptr) {
            out_log_reason = "resolve failed";
            return false;
        }
    }

    // Collect resolved addresses (max 32)
    std::vector<struct sockaddr_storage> addresses;
    if (is_ipv4_literal || is_ipv6_literal) {
        // Use the literal directly
        struct sockaddr_storage ss;
        std::memset(&ss, 0, sizeof(ss));
        if (is_ipv4_literal) {
            struct sockaddr_in * sin = (struct sockaddr_in *)&ss;
            sin->sin_family = AF_INET;
            sin->sin_addr = v4addr;
            addresses.push_back(ss);
        } else {
            struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *)&ss;
            sin6->sin6_family = AF_INET6;
            sin6->sin6_addr = v6addr;
            addresses.push_back(ss);
        }
    } else {
        // Use resolved addresses
        for (struct addrinfo * p = res; p != nullptr && addresses.size() < 32; p = p->ai_next) {
            if (p->ai_family == AF_INET || p->ai_family == AF_INET6) {
                struct sockaddr_storage ss;
                std::memset(&ss, 0, sizeof(ss));
                std::memcpy(&ss, p->ai_addr, p->ai_addrlen);
                addresses.push_back(ss);
            }
        }
        if (res) {
            freeaddrinfo(res);
        }
    }

    if (addresses.empty()) {
        out_log_reason = "resolve failed";
        return false;
    }

    // S5: every resolved address must be permitted
    std::string first_pinned_ip;
    bool has_ipv6_results = false;
    bool has_ipv4_results = false;

    for (size_t i = 0; i < addresses.size(); i++) {
        struct sockaddr_storage ss = addresses[i];
        socklen_t ss_len = (ss.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

        // Unwrap v4-mapped IPv6
        if (unwrap_v4mapped(ss, ss_len)) {
            addresses[i] = ss;
        }

        bool allowed = false;
        bool check_blocked = false;

        if (ss.ss_family == AF_INET) {
            has_ipv4_results = true;
            struct sockaddr_in * sin = (struct sockaddr_in *)&ss;
            uint8_t * addr_bytes = (uint8_t *)&sin->sin_addr;

            // Check CIDR allowlist entries. B1-a: a CIDR entry's own port restriction applies
            // here too, exactly like a hostname entry's - "no portspec" must mean 80/443 only,
            // not "every port on this address", or 127.0.0.1/32 would still reach 127.0.0.1:6379.
            for (const auto & entry : g_allowlist) {
                if (entry.is_cidr && entry.cidr_data.family == AF_INET) {
                    if (prefix_match(addr_bytes, AF_INET, entry.cidr_data)) {
                        if (entry.cidr_data.port == 0) {
                            if (port != 80 && port != 443) {
                                continue;
                            }
                        } else if (entry.cidr_data.port > 0 && entry.cidr_data.port != port) {
                            continue;
                        }
                        allowed = true;
                        break;
                    }
                }
            }

            // Check hostname allowlist entries and then blocked ranges
            if (!allowed) {
                for (const auto & entry : g_allowlist) {
                    if (!entry.is_cidr && entry.host_data.hostname == normalized_host) {
                        // Check port match for hostname entries
                        if (entry.host_data.port == 0) {
                            // Default: only 80/443
                            if (port != 80 && port != 443) {
                                continue;
                            }
                        } else if (entry.host_data.port > 0 && entry.host_data.port != port) {
                            // Specific port doesn't match
                            continue;
                        }
                        // Port matches, check blocked ranges
                        check_blocked = true;
                        break;
                    }
                }
            }

            if (!allowed && check_blocked) {
                // Check if address is blocked
                bool is_blocked = false;
                for (const auto & br : g_blocked_ranges) {
                    if (br.family == AF_INET && prefix_match(addr_bytes, AF_INET, br)) {
                        is_blocked = true;
                        break;
                    }
                }
                allowed = !is_blocked;
            }
        } else if (ss.ss_family == AF_INET6) {
            has_ipv6_results = true;
            struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *)&ss;
            uint8_t * addr_bytes = sin6->sin6_addr.s6_addr;

            // Check CIDR allowlist entries. B1-a: same port restriction as the IPv4 branch above.
            for (const auto & entry : g_allowlist) {
                if (entry.is_cidr && entry.cidr_data.family == AF_INET6) {
                    if (prefix_match(addr_bytes, AF_INET6, entry.cidr_data)) {
                        if (entry.cidr_data.port == 0) {
                            if (port != 80 && port != 443) {
                                continue;
                            }
                        } else if (entry.cidr_data.port > 0 && entry.cidr_data.port != port) {
                            continue;
                        }
                        allowed = true;
                        break;
                    }
                }
            }

            // Check hostname allowlist entries and then blocked ranges
            if (!allowed) {
                for (const auto & entry : g_allowlist) {
                    if (!entry.is_cidr && entry.host_data.hostname == normalize_hostname(host)) {
                        // Check port match for hostname entries
                        if (entry.host_data.port == 0) {
                            // Default: only 80/443
                            if (port != 80 && port != 443) {
                                continue;
                            }
                        } else if (entry.host_data.port > 0 && entry.host_data.port != port) {
                            // Specific port doesn't match
                            continue;
                        }
                        // Port matches, check blocked ranges
                        check_blocked = true;
                        break;
                    }
                }
            }

            if (!allowed && check_blocked) {
                // Check if address is blocked
                bool is_blocked = false;
                for (const auto & br : g_blocked_ranges) {
                    if (br.family == AF_INET6 && prefix_match(addr_bytes, AF_INET6, br)) {
                        is_blocked = true;
                        break;
                    }
                }
                allowed = !is_blocked;
            }
        }

        if (!allowed) {
            out_log_reason = "address not permitted";
            return false;
        }

        if (first_pinned_ip.empty()) {
            first_pinned_ip = format_address(ss, ss_len);
        }
    }

    // S6: pin - R-A1 prefer IPv4 unless only IPv6 available
    std::string final_pinned_ip = first_pinned_ip;
    if (has_ipv6_results && !has_ipv4_results) {
        // Only IPv6 results, use first IPv6
        for (const auto & ss : addresses) {
            if (ss.ss_family == AF_INET6) {
                socklen_t ss_len = sizeof(struct sockaddr_in6);
                final_pinned_ip = format_address(ss, ss_len);
                break;
            }
        }
    } else if (has_ipv4_results) {
        // Prefer first IPv4 result
        for (const auto & ss : addresses) {
            if (ss.ss_family == AF_INET) {
                socklen_t ss_len = sizeof(struct sockaddr_in);
                final_pinned_ip = format_address(ss, ss_len);
                break;
            }
        }
    }

    // B1-b: Self-target block
    if (port == g_self_port) {
        // Check if pinned IP is loopback, unspecified, or matches self hostname
        bool is_self_target = false;
        if (final_pinned_ip == "127.0.0.1" || final_pinned_ip == "::1" ||
            final_pinned_ip == "0.0.0.0" || final_pinned_ip == "::") {
            is_self_target = true;
        } else if (!g_self_hostname.empty()) {
            // Try to resolve self hostname and compare
            struct addrinfo hints_self;
            struct addrinfo * res_self = nullptr;
            std::memset(&hints_self, 0, sizeof(hints_self));
            hints_self.ai_family = AF_UNSPEC;
            hints_self.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(g_self_hostname.c_str(), nullptr, &hints_self, &res_self) == 0 && res_self) {
                for (struct addrinfo * p = res_self; p != nullptr; p = p->ai_next) {
                    struct sockaddr_storage ss;
                    std::memset(&ss, 0, sizeof(ss));
                    std::memcpy(&ss, p->ai_addr, p->ai_addrlen);
                    socklen_t ss_len = (ss.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
                    if (format_address(ss, ss_len) == final_pinned_ip) {
                        is_self_target = true;
                        break;
                    }
                }
                freeaddrinfo(res_self);
            }
        }
        if (is_self_target) {
            out_log_reason = "self-target";
            return false;
        }
    }

    out.host = host;  // Original host string for SNI/Host/cert verification
    out.port = port;
    out.pinned_ip = final_pinned_ip;
    return true;
}
