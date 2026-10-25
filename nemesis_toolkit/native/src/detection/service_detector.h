#pragma once
/**
 * @file service_detector.h
 * @brief Service and version detection via banner grabbing and probe matching.
 */

#include "../core/scan_result.h"
#include "../core/timing.h"
#include <string>
#include <vector>
#include <map>
#include <regex>
#include <atomic>

namespace nemesis {

/**
 * A service probe definition — send data and match the response.
 */
struct ServiceProbe {
    std::string name;           // Probe name (e.g., "GetRequest", "NULL")
    std::string protocol;       // "tcp" or "udp"
    std::string send_data;      // Data to send (raw bytes)
    int         rarity = 1;     // 1-9 (controls when probe is used by intensity)
    std::vector<std::pair<std::regex, std::string>> matches;  // regex → service name
};

/**
 * Known service signature for banner matching.
 */
struct ServiceSignature {
    std::string pattern;        // String or regex pattern to match in banner
    std::string service;        // Service name
    std::string product;        // Product name
    std::string version_regex;  // Capture group for version extraction
};

/**
 * Detects the service and version running on an open port.
 *
 * Detection strategy:
 *   1. NULL probe — connect and wait for a banner (SSH, SMTP, FTP, etc.)
 *   2. Active probes — send protocol-specific data based on intensity
 *   3. Banner matching — compare response against signature database
 *   4. SSL/TLS detection — try TLS handshake on non-standard ports
 */
class ServiceDetector {
public:
    ServiceDetector();

    /**
     * Detect the service on a single port.
     *
     * @param target_ip  Host IP address
     * @param port       Port number (must be open)
     * @param protocol   "tcp" or "udp"
     * @param intensity  Version detection intensity (0-9, default 7)
     * @param timeout_ms Timeout in milliseconds for each probe
     * @param cancel     External cancellation flag
     * @return           Updated PortResult with service info filled in
     */
    PortResult detect(
        const std::string& target_ip,
        uint16_t port,
        const std::string& protocol,
        int intensity,
        int timeout_ms,
        const std::atomic<bool>& cancel
    );

    /**
     * Batch detect services on multiple ports.
     */
    void detect_batch(
        const std::string& target_ip,
        std::vector<PortResult>& ports,
        int intensity,
        int timeout_ms,
        int parallelism,
        const std::atomic<bool>& cancel
    );

    /**
     * Load a service probes database file.
     */
    void load_probes(const std::string& path);

    /**
     * Get the number of loaded probes.
     */
    size_t probe_count() const { return probes_.size(); }

private:
    std::vector<ServiceProbe>    probes_;
    std::vector<ServiceSignature> signatures_;

    // Built-in signature database (compiled-in)
    void load_builtin_signatures();

    // Perform the NULL probe (connect and wait for banner)
    std::string null_probe(const std::string& target_ip, uint16_t port, int timeout_ms);

    // Send a specific probe and get response
    std::string active_probe(const std::string& target_ip, uint16_t port,
                             const std::string& data, int timeout_ms);

    // Match a banner/response against signatures
    void match_banner(const std::string& banner, uint16_t port, PortResult& result);

    // Try SSL/TLS detection
    void detect_ssl(const std::string& target_ip, uint16_t port, int timeout_ms,
                    PortResult& result);

    // Well-known port → service name fallback
    static std::string port_service_hint(uint16_t port);
};

} // namespace nemesis
