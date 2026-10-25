/**
 * @file service_detector.cpp
 * @brief Service/version detection implementation.
 */

#include "service_detector.h"
#include "../platform/platform.h"
#include <thread>
#include <future>
#include <chrono>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>

namespace nemesis {

// ─── Built-in service signatures ────────────────────────────────────────────

static const std::map<uint16_t, std::string> PORT_HINTS = {
    {21, "ftp"}, {22, "ssh"}, {23, "telnet"}, {25, "smtp"}, {53, "dns"},
    {80, "http"}, {110, "pop3"}, {111, "rpcbind"}, {135, "msrpc"},
    {139, "netbios-ssn"}, {143, "imap"}, {443, "https"}, {445, "microsoft-ds"},
    {465, "smtps"}, {587, "submission"}, {993, "imaps"}, {995, "pop3s"},
    {1433, "ms-sql-s"}, {1521, "oracle"}, {2049, "nfs"}, {3306, "mysql"},
    {3389, "ms-wbt-server"}, {5432, "postgresql"}, {5900, "vnc"},
    {5901, "vnc-1"}, {6379, "redis"}, {6667, "irc"}, {8080, "http-proxy"},
    {8443, "https-alt"}, {9200, "elasticsearch"}, {9300, "elasticsearch"},
    {11211, "memcached"}, {27017, "mongodb"}, {27018, "mongodb"},
    {28017, "mongodb-web"},
};

// Banner patterns: {pattern_substring, service, product}
struct BannerPattern {
    const char* pattern;
    const char* service;
    const char* product;
    const char* version_prefix;  // If non-null, text before the version number
};

static const BannerPattern BANNER_PATTERNS[] = {
    {"SSH-2.0-OpenSSH",     "ssh",    "OpenSSH",             "SSH-2.0-OpenSSH_"},
    {"SSH-2.0-",            "ssh",    "",                    "SSH-2.0-"},
    {"SSH-1.",              "ssh",    "",                    "SSH-"},
    {"220 ",                "ftp",    "",                    nullptr},
    {"220-",                "ftp",    "",                    nullptr},
    {"* OK ",               "imap",   "",                    nullptr},
    {"+OK ",                "pop3",   "",                    nullptr},
    {"HTTP/1.",             "http",   "",                    "HTTP/"},
    {"HTTP/2",              "http",   "",                    "HTTP/"},
    {"220 ",                "smtp",   "",                    nullptr},
    {"MySQL",               "mysql",  "MySQL",               nullptr},
    {"MariaDB",             "mysql",  "MariaDB",             nullptr},
    {"PostgreSQL",          "postgresql", "PostgreSQL",      nullptr},
    {"-ERR ",               "redis",  "Redis",               nullptr},
    {"+PONG",               "redis",  "Redis",               nullptr},
    {"-DENIED",             "redis",  "Redis",               nullptr},
    {"MongoDB",             "mongodb", "MongoDB",            nullptr},
    {"elasticsearch",       "elasticsearch", "Elasticsearch", nullptr},
    {"Apache",              "http",   "Apache httpd",        "Apache/"},
    {"nginx",               "http",   "nginx",               "nginx/"},
    {"Microsoft-IIS",       "http",   "Microsoft IIS httpd", "Microsoft-IIS/"},
    {"lighttpd",            "http",   "lighttpd",            "lighttpd/"},
    {"Server: Apache",      "http",   "Apache httpd",        "Apache/"},
    {"Server: nginx",       "http",   "nginx",               "nginx/"},
};
static const int BANNER_PATTERN_COUNT = sizeof(BANNER_PATTERNS) / sizeof(BANNER_PATTERNS[0]);

// ─── Constructor ────────────────────────────────────────────────────────────

ServiceDetector::ServiceDetector() {
    load_builtin_signatures();
}

void ServiceDetector::load_builtin_signatures() {
    // Convert static patterns to ServiceSignature objects
    for (int i = 0; i < BANNER_PATTERN_COUNT; ++i) {
        ServiceSignature sig;
        sig.pattern = BANNER_PATTERNS[i].pattern;
        sig.service = BANNER_PATTERNS[i].service;
        sig.product = BANNER_PATTERNS[i].product;
        if (BANNER_PATTERNS[i].version_prefix)
            sig.version_regex = BANNER_PATTERNS[i].version_prefix;
        signatures_.push_back(std::move(sig));
    }
}

// ─── Port service hint ──────────────────────────────────────────────────────

std::string ServiceDetector::port_service_hint(uint16_t port) {
    auto it = PORT_HINTS.find(port);
    if (it != PORT_HINTS.end())
        return it->second;
    return "unknown";
}

// ─── NULL probe (banner grab) ───────────────────────────────────────────────

std::string ServiceDetector::null_probe(
    const std::string& target_ip,
    uint16_t port,
    int timeout_ms
) {
    bool is_ipv6 = target_ip.find(':') != std::string::npos;
    int family = is_ipv6 ? AF_INET6 : AF_INET;

    socket_t sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCK) return "";

    // Set timeout
#ifdef NEMESIS_WINDOWS
    DWORD tv = static_cast<DWORD>(timeout_ms);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    // Connect
    struct sockaddr_storage addr{};
    socklen_t addr_len = 0;

    if (is_ipv6) {
        auto* sa6 = reinterpret_cast<struct sockaddr_in6*>(&addr);
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = htons(port);
        inet_pton(AF_INET6, target_ip.c_str(), &sa6->sin6_addr);
        addr_len = sizeof(struct sockaddr_in6);
    } else {
        auto* sa4 = reinterpret_cast<struct sockaddr_in*>(&addr);
        sa4->sin_family = AF_INET;
        sa4->sin_port = htons(port);
        inet_pton(AF_INET, target_ip.c_str(), &sa4->sin_addr);
        addr_len = sizeof(struct sockaddr_in);
    }

    if (connect(sock, reinterpret_cast<struct sockaddr*>(&addr), addr_len) != 0) {
        close_socket(sock);
        return "";
    }

    // Read banner (wait up to timeout)
    char buf[4096];
    std::memset(buf, 0, sizeof(buf));

#ifdef NEMESIS_WINDOWS
    int n = recv(sock, buf, sizeof(buf) - 1, 0);
#else
    ssize_t n = recv(sock, buf, sizeof(buf) - 1, 0);
#endif

    close_socket(sock);

    if (n <= 0) return "";
    return std::string(buf, static_cast<size_t>(n));
}

// ─── Active probe ───────────────────────────────────────────────────────────

std::string ServiceDetector::active_probe(
    const std::string& target_ip,
    uint16_t port,
    const std::string& data,
    int timeout_ms
) {
    bool is_ipv6 = target_ip.find(':') != std::string::npos;
    int family = is_ipv6 ? AF_INET6 : AF_INET;

    socket_t sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCK) return "";

#ifdef NEMESIS_WINDOWS
    DWORD tv = static_cast<DWORD>(timeout_ms);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    struct sockaddr_storage addr{};
    socklen_t addr_len = 0;

    if (is_ipv6) {
        auto* sa6 = reinterpret_cast<struct sockaddr_in6*>(&addr);
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = htons(port);
        inet_pton(AF_INET6, target_ip.c_str(), &sa6->sin6_addr);
        addr_len = sizeof(struct sockaddr_in6);
    } else {
        auto* sa4 = reinterpret_cast<struct sockaddr_in*>(&addr);
        sa4->sin_family = AF_INET;
        sa4->sin_port = htons(port);
        inet_pton(AF_INET, target_ip.c_str(), &sa4->sin_addr);
        addr_len = sizeof(struct sockaddr_in);
    }

    if (connect(sock, reinterpret_cast<struct sockaddr*>(&addr), addr_len) != 0) {
        close_socket(sock);
        return "";
    }

    // Send probe data
    send(sock, data.c_str(), static_cast<int>(data.size()), 0);

    // Read response
    char buf[4096];
    std::memset(buf, 0, sizeof(buf));
#ifdef NEMESIS_WINDOWS
    int n = recv(sock, buf, sizeof(buf) - 1, 0);
#else
    ssize_t n = recv(sock, buf, sizeof(buf) - 1, 0);
#endif

    close_socket(sock);

    if (n <= 0) return "";
    return std::string(buf, static_cast<size_t>(n));
}

// ─── Banner matching ────────────────────────────────────────────────────────

void ServiceDetector::match_banner(const std::string& banner, uint16_t port, PortResult& result) {
    if (banner.empty()) {
        result.service = port_service_hint(port);
        return;
    }

    // Try each signature
    for (const auto& sig : signatures_) {
        if (banner.find(sig.pattern) != std::string::npos) {
            result.service = sig.service;
            if (!sig.product.empty())
                result.product = sig.product;

            // Try to extract version
            if (!sig.version_regex.empty()) {
                auto pos = banner.find(sig.version_regex);
                if (pos != std::string::npos) {
                    size_t ver_start = pos + sig.version_regex.size();
                    size_t ver_end = ver_start;
                    while (ver_end < banner.size() &&
                           banner[ver_end] != ' ' &&
                           banner[ver_end] != '\r' &&
                           banner[ver_end] != '\n' &&
                           banner[ver_end] != '\t' &&
                           banner[ver_end] != '(' &&
                           banner[ver_end] != ')') {
                        ++ver_end;
                    }
                    if (ver_end > ver_start) {
                        result.version = banner.substr(ver_start, ver_end - ver_start);
                    }
                }
            }

            // Store banner
            result.banner = banner.substr(0, std::min(banner.size(), size_t(1024)));
            return;
        }
    }

    // No signature match — use port hint
    result.service = port_service_hint(port);
    result.banner = banner.substr(0, std::min(banner.size(), size_t(1024)));
}

// ─── SSL/TLS detection (basic) ──────────────────────────────────────────────

void ServiceDetector::detect_ssl(
    const std::string& target_ip,
    uint16_t port,
    int timeout_ms,
    PortResult& result
) {
    // Send a TLS ClientHello and check for ServerHello
    // This is a minimal TLS 1.0 ClientHello
    static const unsigned char CLIENT_HELLO[] = {
        0x16,       // Content type: Handshake
        0x03, 0x01, // Version: TLS 1.0
        0x00, 0x65, // Length
        0x01,       // Handshake type: ClientHello
        0x00, 0x00, 0x61, // Length
        0x03, 0x03, // Client version: TLS 1.2
        // 32 bytes random
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,       // Session ID length: 0
        0x00, 0x1c, // Cipher suites length
        // Cipher suites
        0xc0, 0x2c, 0xc0, 0x2b, 0xc0, 0x30, 0xc0, 0x2f,
        0x00, 0x9f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x23,
        0xc0, 0x28, 0xc0, 0x27, 0xc0, 0x0a, 0xc0, 0x09,
        0xc0, 0x14, 0xc0, 0x13,
        0x01, 0x00, // Compression methods
        0x00, 0x16, // Extensions length
        // Extensions (SNI, etc.)
        0x00, 0x00, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x00,
        0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
        0x73, 0x74,
        0x00, 0x17, 0x00, 0x00, // Extended master secret
    };

    std::string probe_data(reinterpret_cast<const char*>(CLIENT_HELLO), sizeof(CLIENT_HELLO));
    std::string response = active_probe(target_ip, port, probe_data, timeout_ms);

    if (response.size() >= 5 && static_cast<unsigned char>(response[0]) == 0x16) {
        // Got a TLS ServerHello
        result.is_ssl = true;

        // Extract TLS version
        unsigned char major = static_cast<unsigned char>(response[1]);
        unsigned char minor = static_cast<unsigned char>(response[2]);
        if (major == 3) {
            switch (minor) {
                case 0: result.ssl_version = "SSLv3"; break;
                case 1: result.ssl_version = "TLSv1.0"; break;
                case 2: result.ssl_version = "TLSv1.1"; break;
                case 3: result.ssl_version = "TLSv1.2"; break;
                case 4: result.ssl_version = "TLSv1.3"; break;
                default: result.ssl_version = "TLS-unknown"; break;
            }
        }

        // Mark service as SSL-wrapped
        if (result.service == "http")
            result.service = "https";
        else if (result.service.find("ssl") == std::string::npos &&
                 result.service.find("tls") == std::string::npos)
            result.extra_info += (result.extra_info.empty() ? "" : "; ") + std::string("SSL/TLS detected");
    }
}

// ─── Single port detection ──────────────────────────────────────────────────

PortResult ServiceDetector::detect(
    const std::string& target_ip,
    uint16_t port,
    const std::string& protocol,
    int intensity,
    int timeout_ms,
    const std::atomic<bool>& cancel
) {
    PortResult result;
    result.port = port;
    result.protocol = protocol;
    result.state = PortState::Open;

    if (cancel.load(std::memory_order_relaxed))
        return result;

    // Step 1: NULL probe — connect and wait for banner
    std::string banner = null_probe(target_ip, port, timeout_ms);
    match_banner(banner, port, result);

    if (cancel.load(std::memory_order_relaxed))
        return result;

    // Step 2: If no banner and intensity >= 2, try HTTP GET probe
    if (banner.empty() && intensity >= 2) {
        std::string http_probe = "GET / HTTP/1.0\r\nHost: " + target_ip + "\r\n\r\n";
        std::string response = active_probe(target_ip, port, http_probe, timeout_ms);
        if (!response.empty()) {
            match_banner(response, port, result);
        }
    }

    if (cancel.load(std::memory_order_relaxed))
        return result;

    // Step 3: SSL/TLS detection on likely ports or if intensity >= 5
    bool likely_ssl = (port == 443 || port == 465 || port == 636 || port == 853 ||
                       port == 993 || port == 995 || port == 8443 || port == 9443);
    if ((likely_ssl || intensity >= 5) && !result.is_ssl) {
        detect_ssl(target_ip, port, timeout_ms, result);
    }

    // Step 4: Generate CPE identifier if we have enough info
    if (!result.product.empty()) {
        std::string cpe = "cpe:/a:";
        // Normalize vendor from product
        std::string vendor = result.product;
        std::transform(vendor.begin(), vendor.end(), vendor.begin(), ::tolower);
        // Replace spaces with underscores
        std::replace(vendor.begin(), vendor.end(), ' ', '_');
        cpe += vendor;
        if (!result.version.empty())
            cpe += ":" + result.version;
        result.cpe = cpe;
    }

    return result;
}

// ─── Batch detection ────────────────────────────────────────────────────────

void ServiceDetector::detect_batch(
    const std::string& target_ip,
    std::vector<PortResult>& ports,
    int intensity,
    int timeout_ms,
    int parallelism,
    const std::atomic<bool>& cancel
) {
    // Only detect on open ports
    std::vector<size_t> open_indices;
    for (size_t i = 0; i < ports.size(); ++i) {
        if (ports[i].is_open())
            open_indices.push_back(i);
    }

    if (open_indices.empty()) return;

    // Process in batches
    size_t idx = 0;
    while (idx < open_indices.size() && !cancel.load(std::memory_order_relaxed)) {
        int batch = std::min(parallelism, static_cast<int>(open_indices.size() - idx));

        std::vector<std::future<std::pair<size_t, PortResult>>> futures;
        for (int i = 0; i < batch; ++i) {
            size_t port_idx = open_indices[idx + i];
            uint16_t port = ports[port_idx].port;
            std::string proto = ports[port_idx].protocol;

            futures.push_back(std::async(std::launch::async,
                [this, &target_ip, port, proto, intensity, timeout_ms, &cancel, port_idx]()
                    -> std::pair<size_t, PortResult> {
                    return {port_idx, detect(target_ip, port, proto, intensity, timeout_ms, cancel)};
                }
            ));
        }

        for (auto& fut : futures) {
            auto [port_idx, detected] = fut.get();
            // Merge detected info into existing port result
            auto& pr = ports[port_idx];
            pr.service    = detected.service;
            pr.product    = detected.product;
            pr.version    = detected.version;
            pr.extra_info = detected.extra_info;
            pr.os_type    = detected.os_type;
            pr.cpe        = detected.cpe;
            pr.banner     = detected.banner;
            pr.is_ssl     = detected.is_ssl;
            pr.ssl_version= detected.ssl_version;
        }

        idx += batch;
    }
}

void ServiceDetector::load_probes(const std::string& path) {
    // TODO: Parse nmap-service-probes format file
    // For now, the built-in signatures are sufficient for Phase 1
    (void)path;
}

} // namespace nemesis
