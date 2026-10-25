#pragma once
/**
 * @file port_spec.h
 * @brief Port specification parser and top-ports database.
 */

#include <string>
#include <vector>
#include <cstdint>
#include <set>
#include <stdexcept>

namespace nemesis {

/**
 * Parses port specifications and provides top-N port lists.
 *
 * Supported spec formats:
 *   "80"              → single port
 *   "80,443"          → comma-separated
 *   "1-1024"          → range
 *   "22,80,100-200"   → mixed
 *   "T:80,U:53"       → protocol-prefixed
 *   "-"               → all ports (1-65535)
 */
class PortSpec {
public:
    PortSpec() = default;

    /**
     * Parse an Nmap-style port specification string.
     * @throws std::invalid_argument if malformed.
     */
    void parse(const std::string& spec);

    /**
     * Load from a built-in list: top 100, top 1000, or all 65535.
     */
    void set_top_ports(int n);
    void set_fast_scan();           // Top 100
    void set_all_ports();           // 1-65535

    /**
     * Get the final sorted, de-duplicated port list for TCP scanning.
     */
    std::vector<uint16_t> tcp_ports() const;

    /**
     * Get the final sorted, de-duplicated port list for UDP scanning.
     */
    std::vector<uint16_t> udp_ports() const;

    /**
     * Get a combined list (used when protocol isn't specified in spec).
     */
    std::vector<uint16_t> all_ports() const;

    /**
     * Randomize the port order (for evasion).
     */
    void shuffle();

    /**
     * Number of ports selected.
     */
    size_t count() const { return tcp_.size() + udp_.size(); }

    /**
     * Compress a sorted port list into an Nmap-style string ("22,80-82,443").
     */
    static std::string compress(const std::vector<uint16_t>& ports);

    /**
     * Get the top N most commonly open TCP ports.
     */
    static std::vector<uint16_t> top_tcp_ports(int n);

    /**
     * Get the top N most commonly open UDP ports.
     */
    static std::vector<uint16_t> top_udp_ports(int n);

private:
    std::set<uint16_t> tcp_;
    std::set<uint16_t> udp_;
    bool               randomized_ = false;

    void parse_single_spec(const std::string& spec, std::set<uint16_t>& target);
    static void validate_port(int port);

    // Built-in top port databases
    static const uint16_t TOP_1000_TCP[];
    static const int      TOP_1000_TCP_COUNT;
    static const uint16_t TOP_100_UDP[];
    static const int      TOP_100_UDP_COUNT;
};

} // namespace nemesis
