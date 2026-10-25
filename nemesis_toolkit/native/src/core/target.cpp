/**
 * @file target.cpp
 * @brief Target specification parser implementation.
 */

#include "target.h"
#include "../platform/platform.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <random>
#include <stdexcept>
#include <cstring>
#include <regex>

namespace nemesis {

// ─── Classification helpers ─────────────────────────────────────────────────

bool TargetParser::is_ipv4(const std::string& s) {
    struct in_addr addr;
#ifdef NEMESIS_WINDOWS
    // inet_pton requires WinSock initialized
    return inet_pton(AF_INET, s.c_str(), &addr) == 1;
#else
    return inet_pton(AF_INET, s.c_str(), &addr) == 1;
#endif
}

bool TargetParser::is_ipv6(const std::string& s) {
    struct in6_addr addr;
    return inet_pton(AF_INET6, s.c_str(), &addr) == 1;
}

bool TargetParser::is_cidr(const std::string& s) {
    auto pos = s.find('/');
    if (pos == std::string::npos) return false;
    std::string prefix = s.substr(pos + 1);
    try {
        int len = std::stoi(prefix);
        return len >= 0 && len <= 128;
    } catch (...) {
        return false;
    }
}

bool TargetParser::has_octet_range(const std::string& s) {
    // Matches patterns like "192.168.1-5.1" or "10.0.0.1-254"
    return s.find('-') != std::string::npos && s.find('.') != std::string::npos
           && !is_ipv6(s) && !is_cidr(s);
}

bool TargetParser::is_routable_v4(uint32_t ip) {
    uint8_t a = (ip >> 24) & 0xFF;
    uint8_t b = (ip >> 16) & 0xFF;
    // Skip: 0.x.x.x, 10.x.x.x, 127.x.x.x, 169.254.x.x, 172.16-31.x.x,
    //        192.168.x.x, 224-255.x.x.x (multicast/reserved)
    if (a == 0 || a == 10 || a == 127 || a >= 224) return false;
    if (a == 169 && b == 254) return false;
    if (a == 172 && b >= 16 && b <= 31) return false;
    if (a == 192 && b == 168) return false;
    return true;
}

// ─── Core operations ────────────────────────────────────────────────────────

void TargetParser::add_host(const std::string& ip, const std::string& hostname, bool is_v6) {
    if (ip.empty()) return;
    if (seen_.count(ip)) return;
    seen_.insert(ip);
    hosts_.push_back({ip, hostname, is_v6});
}

void TargetParser::add_spec(const std::string& spec) {
    std::string trimmed = spec;
    // Trim whitespace
    while (!trimmed.empty() && (trimmed.front() == ' ' || trimmed.front() == '\t'))
        trimmed.erase(trimmed.begin());
    while (!trimmed.empty() && (trimmed.back() == ' ' || trimmed.back() == '\t'))
        trimmed.pop_back();

    if (trimmed.empty())
        throw std::invalid_argument("Empty target specification");

    // CIDR notation
    if (is_cidr(trimmed)) {
        auto slash_pos = trimmed.find('/');
        std::string ip_part = trimmed.substr(0, slash_pos);
        int prefix_len = std::stoi(trimmed.substr(slash_pos + 1));

        if (is_ipv6(ip_part) || trimmed.find(':') != std::string::npos) {
            expand_cidr_v6(ip_part, prefix_len);
        } else {
            expand_cidr_v4(ip_part, prefix_len);
        }
        return;
    }

    // Octet ranges (e.g., "192.168.1-5.1-254")
    if (has_octet_range(trimmed)) {
        expand_octet_range(trimmed);
        return;
    }

    // Plain IPv4
    if (is_ipv4(trimmed)) {
        add_host(trimmed);
        return;
    }

    // Plain IPv6
    if (is_ipv6(trimmed)) {
        add_host(trimmed, "", true);
        return;
    }

    // Assume hostname — resolve via DNS
    resolve_hostname(trimmed);
}

void TargetParser::add_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open())
        throw std::runtime_error("Cannot open target file: " + path);

    std::string line;
    int line_num = 0;
    while (std::getline(file, line)) {
        ++line_num;
        // Trim
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t'))
            line.erase(line.begin());
        while (!line.empty() && (line.back() == ' ' || line.back() == '\t' || line.back() == '\r'))
            line.pop_back();

        // Skip empty and comments
        if (line.empty() || line[0] == '#') continue;

        try {
            add_spec(line);
        } catch (const std::exception& e) {
            // Log warning but continue processing
        }
    }
}

void TargetParser::add_random(int count) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist(0x01000001, 0xDFFFFFFF);

    int added = 0;
    while (added < count) {
        uint32_t ip = dist(gen);
        if (!is_routable_v4(ip)) continue;

        char buf[INET_ADDRSTRLEN];
        uint32_t net_ip = htonl(ip);
        inet_ntop(AF_INET, &net_ip, buf, sizeof(buf));
        std::string ip_str(buf);

        if (!seen_.count(ip_str)) {
            add_host(ip_str);
            ++added;
        }
    }
}

void TargetParser::exclude(const std::string& spec) {
    // For simplicity, expand the exclusion spec the same way
    TargetParser excl_parser;
    excl_parser.add_spec(spec);
    for (const auto& h : excl_parser.hosts_) {
        excluded_.insert(h.ip);
    }
}

void TargetParser::exclude_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open())
        throw std::runtime_error("Cannot open exclude file: " + path);

    std::string line;
    while (std::getline(file, line)) {
        while (!line.empty() && (line.back() == ' ' || line.back() == '\t' || line.back() == '\r'))
            line.pop_back();
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t'))
            line.erase(line.begin());
        if (line.empty() || line[0] == '#') continue;

        try {
            exclude(line);
        } catch (...) {}
    }
}

bool TargetParser::is_excluded(const std::string& ip) const {
    return excluded_.count(ip) > 0;
}

std::vector<TargetHost> TargetParser::resolve() const {
    std::vector<TargetHost> result;
    result.reserve(hosts_.size());
    for (const auto& h : hosts_) {
        if (!is_excluded(h.ip)) {
            result.push_back(h);
        }
    }
    return result;
}

void TargetParser::shuffle() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::shuffle(hosts_.begin(), hosts_.end(), gen);
}

// ─── CIDR expansion ─────────────────────────────────────────────────────────

void TargetParser::expand_cidr_v4(const std::string& ip_str, int prefix_len) {
    if (prefix_len < 0 || prefix_len > 32)
        throw std::invalid_argument("Invalid IPv4 CIDR prefix: /" + std::to_string(prefix_len));

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1)
        throw std::invalid_argument("Invalid IPv4 address in CIDR: " + ip_str);

    uint32_t ip = ntohl(addr.s_addr);
    uint32_t mask = prefix_len == 0 ? 0 : (~0u << (32 - prefix_len));
    uint32_t network = ip & mask;
    uint32_t broadcast = network | ~mask;

    // Limit expansion to avoid OOM (max /16 = 65534 hosts)
    uint32_t count = broadcast - network + 1;
    if (count > 65536)
        throw std::invalid_argument("CIDR range too large (>" + std::to_string(count) + " hosts). Use /16 or smaller.");

    // For /31 and /32, include all addresses
    // For larger ranges, skip network and broadcast
    uint32_t start = (prefix_len >= 31) ? network : network + 1;
    uint32_t end   = (prefix_len >= 31) ? broadcast : broadcast - 1;

    for (uint32_t i = start; i <= end; ++i) {
        uint32_t net_ip = htonl(i);
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &net_ip, buf, sizeof(buf));
        add_host(std::string(buf));
    }
}

void TargetParser::expand_cidr_v6(const std::string& ip_str, int prefix_len) {
    if (prefix_len < 0 || prefix_len > 128)
        throw std::invalid_argument("Invalid IPv6 CIDR prefix: /" + std::to_string(prefix_len));

    // For IPv6, only support /128 (single host) and /126, /127 (small subnets)
    // Full IPv6 range expansion is impractical
    if (prefix_len < 120)
        throw std::invalid_argument("IPv6 CIDR prefix must be /120 or larger (max 256 hosts)");

    struct in6_addr addr;
    if (inet_pton(AF_INET6, ip_str.c_str(), &addr) != 1)
        throw std::invalid_argument("Invalid IPv6 address in CIDR: " + ip_str);

    int host_bits = 128 - prefix_len;
    uint32_t count = 1u << host_bits;

    for (uint32_t i = 0; i < count; ++i) {
        struct in6_addr current = addr;
        // Set the host bits
        int byte_idx = 15;
        uint32_t val = i;
        while (val > 0 && byte_idx >= 0) {
            current.s6_addr[byte_idx] = (addr.s6_addr[byte_idx] & 0xFF) | (val & 0xFF);
            val >>= 8;
            --byte_idx;
        }
        char buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &current, buf, sizeof(buf));
        add_host(std::string(buf), "", true);
    }
}

// ─── Octet range expansion ─────────────────────────────────────────────────

void TargetParser::expand_octet_range(const std::string& spec) {
    // Split into octets by '.'
    std::vector<std::string> octets;
    std::stringstream ss(spec);
    std::string part;
    while (std::getline(ss, part, '.')) {
        octets.push_back(part);
    }

    if (octets.size() != 4)
        throw std::invalid_argument("Invalid octet range (need 4 octets): " + spec);

    // Parse each octet into a list of values
    std::vector<std::vector<int>> octet_values(4);

    for (int i = 0; i < 4; ++i) {
        // Each octet can be "N", "N-M", or "N,M,O-P"
        std::stringstream oss(octets[i]);
        std::string range;
        while (std::getline(oss, range, ',')) {
            auto dash = range.find('-');
            if (dash != std::string::npos) {
                int start = std::stoi(range.substr(0, dash));
                int end   = std::stoi(range.substr(dash + 1));
                if (start > end) std::swap(start, end);
                if (start < 0 || end > 255)
                    throw std::invalid_argument("Octet value out of range: " + range);
                for (int v = start; v <= end; ++v)
                    octet_values[i].push_back(v);
            } else {
                int v = std::stoi(range);
                if (v < 0 || v > 255)
                    throw std::invalid_argument("Octet value out of range: " + range);
                octet_values[i].push_back(v);
            }
        }
        if (octet_values[i].empty())
            throw std::invalid_argument("Empty octet in range: " + spec);
    }

    // Safety: limit total expansion
    size_t total = octet_values[0].size() * octet_values[1].size()
                 * octet_values[2].size() * octet_values[3].size();
    if (total > 65536)
        throw std::invalid_argument("Octet range expands to " + std::to_string(total) + " hosts (max 65536)");

    // Expand all combinations
    for (int a : octet_values[0])
        for (int b : octet_values[1])
            for (int c : octet_values[2])
                for (int d : octet_values[3]) {
                    std::string ip = std::to_string(a) + "." + std::to_string(b) + "."
                                   + std::to_string(c) + "." + std::to_string(d);
                    add_host(ip);
                }
}

// ─── DNS resolution ─────────────────────────────────────────────────────────

void TargetParser::resolve_hostname(const std::string& hostname) {
    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int err = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
    if (err != 0) {
        throw std::invalid_argument("Cannot resolve hostname: " + hostname
                                    + " (" + gai_strerror(err) + ")");
    }

    // Add all resolved addresses
    for (auto* rp = result; rp != nullptr; rp = rp->ai_next) {
        char buf[INET6_ADDRSTRLEN];
        if (rp->ai_family == AF_INET) {
            auto* sa = reinterpret_cast<struct sockaddr_in*>(rp->ai_addr);
            inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
            add_host(std::string(buf), hostname, false);
        } else if (rp->ai_family == AF_INET6) {
            auto* sa = reinterpret_cast<struct sockaddr_in6*>(rp->ai_addr);
            inet_ntop(AF_INET6, &sa->sin6_addr, buf, sizeof(buf));
            add_host(std::string(buf), hostname, true);
        }
    }

    freeaddrinfo(result);
}

} // namespace nemesis
