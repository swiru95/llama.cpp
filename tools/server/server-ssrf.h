#pragma once

#include <string>
#include <vector>
#include <cstdint>

struct common_params;

// A proxy target that passed every check. pinned_ip is the numeric address the connection
// MUST use; re-resolving host at connect time would reopen the DNS-rebinding window.
struct server_ssrf_target {
    std::string host;       // hostname or IP literal exactly as parsed from the URL
    int         port = 0;
    std::string pinned_ip;  // numeric IPv4 or IPv6 literal (no brackets for IPv6)
};

struct server_ssrf {
    // Parse --proxy-allowed-hosts into the allowlist. Returns false (and logs SRV_ERR) on any
    // malformed entry; the caller MUST abort startup. Safe to call once, before any request.
    // Never throws.
    static bool configure(const common_params & params);

    // True iff at least one allowlist entry was configured.
    static bool enabled();

    // Decide whether host:port may be proxied to, and if so which IP to pin.
    // Returns true and fills out on allow. Returns false on deny and writes a SHORT,
    // non-sensitive diagnostic into out_log_reason for the SERVER LOG ONLY.
    // Never throws.
    static bool check_target(const std::string & host,
                             int port,
                             server_ssrf_target & out,
                             std::string & out_log_reason);
};
