#pragma once
/**
 * @file scan_result.h
 * @brief Result structures returned by the scan engine.
 */

#include "types.h"
#include <string>
#include <vector>
#include <chrono>
#include <map>

namespace nemesis {

// ─── Script Result ──────────────────────────────────────────────────────────

struct ScriptResult {
    std::string id;           // Script name (e.g., "http-title")
    std::string output;       // Script text output
    std::map<std::string, std::string> elements;  // Structured key-value data
};

// ─── Per-Port Result ────────────────────────────────────────────────────────

struct PortResult {
    uint16_t    port        = 0;
    std::string protocol    = "tcp";    // "tcp", "udp", "sctp"
    PortState   state       = PortState::Unknown;
    std::string reason;                 // Why port is in this state ("syn-ack", "rst", "no-response", ...)
    int         reason_ttl  = 0;        // TTL of the response packet

    // Service/version detection
    std::string service;                // Service name ("http", "ssh", ...)
    std::string product;                // Software product ("Apache httpd", "OpenSSH", ...)
    std::string version;                // Version string ("2.4.41", "8.2p1", ...)
    std::string extra_info;             // Additional info ("protocol 2.0", ...)
    std::string os_type;                // OS type from service detection
    std::string device_type;            // Device type from service detection
    std::string cpe;                    // CPE identifier ("cpe:/a:apache:http_server:2.4.41")
    std::string banner;                 // Raw banner data (truncated)

    // SSL/TLS
    bool        is_ssl      = false;
    std::string ssl_version;            // "TLSv1.2", "TLSv1.3"
    std::string ssl_cipher;
    std::string ssl_cert_subject;
    std::string ssl_cert_issuer;
    std::string ssl_cert_expiry;

    // NSE script results
    std::vector<ScriptResult> scripts;

    // Convenience
    bool is_open() const {
        return state == PortState::Open;
    }
    bool is_open_or_filtered() const {
        return state == PortState::Open || state == PortState::OpenFiltered;
    }
};

// ─── OS Detection Result ────────────────────────────────────────────────────

struct OsMatch {
    std::string name;                   // "Linux 5.4 - 5.15"
    int         accuracy    = 0;        // 0-100
    std::string device_type;            // "general purpose", "router", "firewall", ...
    std::string os_family;              // "Linux", "Windows", "FreeBSD", ...
    std::string os_generation;          // "5.X", "10", ...
    std::string vendor;                 // "Microsoft", "Canonical", ...
    std::vector<std::string> cpe;       // CPE identifiers
};

struct OsResult {
    std::vector<OsMatch> matches;
    uint32_t    uptime_seconds  = 0;
    std::string last_boot;              // Estimated last boot time
    std::string tcp_seq_class;          // "random positive increments", ...
    std::string tcp_seq_difficulty;     // "Good luck!", ...
    int64_t     tcp_seq_index   = 0;
    std::string ipid_class;             // "Incremental", "Randomized", ...
    std::string tcp_ts_class;           // "2HZ", "100HZ", "1000HZ"
};

// ─── Traceroute Hop ─────────────────────────────────────────────────────────

struct HopResult {
    int         ttl         = 0;
    std::string ip;
    std::string hostname;
    double      rtt_ms      = 0.0;      // Round-trip time in milliseconds
    bool        timed_out   = false;
};

// ─── Per-Host Result ────────────────────────────────────────────────────────

struct HostResult {
    std::string ip;
    std::string hostname;
    bool        is_up               = false;
    std::string status_reason;                  // "syn-ack", "arp-response", "user-set", ...
    double      latency_ms          = 0.0;      // Discovery round-trip time

    // Port scan results
    std::vector<PortResult> ports;

    // OS detection
    OsResult    os;

    // Traceroute
    std::vector<HopResult> traceroute;

    // Host-level NSE scripts
    std::vector<ScriptResult> host_scripts;

    // Timing
    double      scan_duration_ms    = 0.0;

    // Helpers
    int count_by_state(PortState s) const {
        int n = 0;
        for (const auto& p : ports)
            if (p.state == s) ++n;
        return n;
    }

    std::vector<PortResult> open_ports() const {
        std::vector<PortResult> result;
        for (const auto& p : ports)
            if (p.is_open()) result.push_back(p);
        return result;
    }
};

// ─── Full Scan Result ───────────────────────────────────────────────────────

struct ScanResult {
    std::string scanner         = "nemesis-scan";
    std::string scanner_version = "1.0.0";
    std::string command_line;
    std::string start_time;             // ISO 8601
    std::string end_time;               // ISO 8601
    double      elapsed_seconds = 0.0;

    std::vector<HostResult> hosts;

    int hosts_up    = 0;
    int hosts_down  = 0;
    int hosts_total = 0;

    // Summary stats
    int total_open_ports() const {
        int n = 0;
        for (const auto& h : hosts)
            n += h.count_by_state(PortState::Open);
        return n;
    }
};

} // namespace nemesis
