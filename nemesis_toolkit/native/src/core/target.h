#pragma once
/**
 * @file target.h
 * @brief Target specification parser — handles IPs, CIDRs, octet ranges,
 *        hostnames, target files, random targets, exclusions, and IPv6.
 */

#include <string>
#include <vector>
#include <cstdint>
#include <set>

namespace nemesis {

/**
 * Represents a single resolved target IP address with an optional hostname.
 */
struct TargetHost {
    std::string ip;
    std::string hostname;     // Original or reverse-DNS hostname
    bool        is_ipv6 = false;
};

/**
 * Parses and expands target specifications into individual host IPs.
 *
 * Supported formats:
 *   - Single IPv4:     "192.168.1.1"
 *   - CIDR:            "192.168.1.0/24"
 *   - Octet range:     "192.168.1-5.1-254"
 *   - Hostname:        "scanme.nmap.org"
 *   - IPv6:            "::1", "fe80::1", "2001:db8::/32"
 *   - Target file:     each line is one of the above formats
 */
class TargetParser {
public:
    TargetParser() = default;

    /**
     * Parse a single target specification string and add all expanded hosts.
     * @throws std::invalid_argument if the spec is malformed.
     */
    void add_spec(const std::string& spec);

    /**
     * Read targets from a file (one spec per line). Lines starting with '#'
     * are ignored. Empty lines are skipped.
     * @throws std::runtime_error on file I/O errors.
     */
    void add_file(const std::string& path);

    /**
     * Add randomly generated routable IPv4 addresses.
     */
    void add_random(int count);

    /**
     * Exclude specific hosts or CIDR ranges from the target list.
     */
    void exclude(const std::string& spec);

    /**
     * Exclude hosts listed in a file.
     */
    void exclude_file(const std::string& path);

    /**
     * Return the final expanded and de-duplicated list of targets,
     * with exclusions applied.
     */
    std::vector<TargetHost> resolve() const;

    /**
     * Return the count of targets (before resolve, an estimate).
     */
    size_t estimated_count() const { return hosts_.size(); }

    /**
     * Randomize the target order.
     */
    void shuffle();

private:
    std::vector<TargetHost> hosts_;
    std::set<std::string>   seen_;          // De-duplication set
    std::set<std::string>   excluded_;      // Excluded IPs

    void expand_cidr_v4(const std::string& ip_str, int prefix_len);
    void expand_cidr_v6(const std::string& ip_str, int prefix_len);
    void expand_octet_range(const std::string& spec);
    void resolve_hostname(const std::string& hostname);
    bool is_excluded(const std::string& ip) const;
    void add_host(const std::string& ip, const std::string& hostname = "", bool is_v6 = false);

    static bool is_ipv4(const std::string& s);
    static bool is_ipv6(const std::string& s);
    static bool is_cidr(const std::string& s);
    static bool has_octet_range(const std::string& s);
    static bool is_routable_v4(uint32_t ip);
};

} // namespace nemesis
