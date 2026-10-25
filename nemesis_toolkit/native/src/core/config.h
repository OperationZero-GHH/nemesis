#pragma once
/**
 * @file config.h
 * @brief Master scan configuration — aggregates all user-facing options.
 */

#include "types.h"
#include "timing.h"
#include <string>
#include <vector>
#include <cstdint>

namespace nemesis {

// ─── Evasion Configuration ──────────────────────────────────────────────────

struct EvasionConfig {
    bool        fragment        = false;
    int         mtu             = 0;        // Custom MTU (0 = default)
    std::vector<std::string> decoys;        // Decoy source IPs
    std::string source_ip;                  // Spoofed source IP
    uint16_t    source_port     = 0;        // Spoofed source port (0 = random)
    std::string spoof_mac;                  // Spoofed MAC address
    int         data_length     = 0;        // Random padding bytes
    std::string ip_options;                 // Custom IP options (hex string)
    bool        randomize_hosts = false;    // Randomize target order
    bool        bad_checksum    = false;    // Send invalid checksums
};

// ─── Master Scan Configuration ──────────────────────────────────────────────

struct ScanConfig {
    // ── Targets ──
    std::vector<std::string> targets;       // IPs, hostnames, CIDR ranges, octet ranges
    std::string         target_file;        // Read targets from file (-iL)
    std::vector<std::string> exclude_hosts; // Hosts to skip
    std::string         exclude_file;       // File of hosts to skip
    bool                random_targets  = false;
    int                 random_count    = 0;
    bool                ipv6            = false;

    // ── Scan type ──
    ScanType            scan_type       = ScanType::TcpSyn;
    uint8_t             custom_tcp_flags= 0;     // For TcpCustom
    std::string         zombie_host;              // For Idle scan
    uint16_t            zombie_port     = 80;
    std::string         ftp_relay;                // For FTP bounce

    // ── Discovery ──
    std::vector<DiscoveryMethod> discovery_methods;
    bool                skip_discovery  = false;  // -Pn

    // ── Port specification ──
    std::string         port_spec;                // "22,80,443,1-1024"
    bool                fast_scan       = false;  // -F (top 100)
    int                 top_ports       = 0;      // --top-ports N
    bool                all_ports       = false;  // -p- (1-65535)
    bool                randomize_ports = false;  // Randomize port order

    // ── Service/version detection ──
    bool                service_detect  = false;  // -sV
    int                 version_intensity = 7;    // 0-9
    bool                version_light   = false;  // --version-light (intensity 2)
    bool                version_all     = false;  // --version-all   (intensity 9)

    // ── OS detection ──
    bool                os_detect       = false;  // -O
    int                 os_scan_limit   = 0;      // --osscan-limit
    bool                os_scan_guess   = false;  // --osscan-guess

    // ── NSE scripting ──
    std::vector<std::string> scripts;             // Script names or categories
    std::string         script_args;              // key=value pairs
    bool                script_trace    = false;  // --script-trace
    std::string         script_dir;               // Custom scripts directory

    // ── Timing ──
    TimingConfig        timing;

    // ── Evasion ──
    EvasionConfig       evasion;

    // ── Output ──
    std::string         normal_output;            // -oN file
    std::string         xml_output;               // -oX file
    std::string         grepable_output;          // -oG file
    std::string         json_output;              // Custom Nemesis JSON
    bool                all_output      = false;  // -oA prefix
    std::string         output_prefix;            // Prefix for -oA
    int                 verbosity       = 0;      // -v / -vv
    int                 debug_level     = 0;      // -d / -dd
    bool                show_reason     = false;  // --reason
    bool                packet_trace    = false;  // --packet-trace
    bool                append_output   = false;  // --append-output

    // ── Traceroute ──
    bool                traceroute      = false;  // --traceroute

    // ── Misc ──
    std::string         dns_servers;              // --dns-servers
    bool                send_eth        = false;  // --send-eth
    bool                send_ip         = false;  // --send-ip
    std::string         interface_name;           // -e iface
    bool                resume          = false;  // --resume
    std::string         resume_file;              // File to resume from

    // ── Internal / computed ──
    int                 concurrency     = 500;    // Nemesis-specific parallelism
    double              connect_timeout = 1.5;    // Seconds for TCP connect fallback

    /**
     * Apply defaults based on scan type and environment.
     * Call after all user options are set.
     */
    void finalize();
};

} // namespace nemesis
