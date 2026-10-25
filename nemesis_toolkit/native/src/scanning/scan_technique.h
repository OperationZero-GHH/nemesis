#pragma once
/**
 * @file scan_technique.h
 * @brief Abstract interface for all port scanning techniques.
 */

#include "../core/types.h"
#include "../core/scan_result.h"
#include "../core/timing.h"
#include "../core/config.h"
#include <vector>
#include <string>
#include <atomic>

namespace nemesis {

/**
 * Abstract base class for every scan technique (SYN, Connect, ACK, UDP, etc.).
 *
 * Each concrete implementation knows how to probe a set of ports on a single
 * target and classify each port into one of the six PortState values.
 */
class IScanTechnique {
public:
    virtual ~IScanTechnique() = default;

    /** Which scan type this implements. */
    virtual ScanType type() const = 0;

    /** Human-readable name ("TCP SYN Scan", "UDP Scan", etc.). */
    virtual std::string name() const = 0;

    /** Whether this technique requires raw socket (admin/root) privileges. */
    virtual bool requires_raw_socket() const = 0;

    /** Default protocol for ports scanned by this technique. */
    virtual std::string default_protocol() const { return "tcp"; }

    /**
     * Scan the given ports on a single target host.
     *
     * @param target_ip     Resolved IPv4 or IPv6 address string.
     * @param ports         List of ports to scan.
     * @param timing        Timing configuration (controls retries, delays, parallelism).
     * @param evasion       Evasion settings (fragmentation, decoys, spoofing, etc.).
     * @param cancel_flag   Set to true externally to abort the scan early.
     * @return              One PortResult per port scanned.
     */
    virtual std::vector<PortResult> scan_ports(
        const std::string& target_ip,
        const std::vector<uint16_t>& ports,
        const TimingConfig& timing,
        const EvasionConfig& evasion,
        const std::atomic<bool>& cancel_flag
    ) = 0;
};

/**
 * Factory: create a scan technique instance from a ScanType enum.
 */
std::unique_ptr<IScanTechnique> create_scan_technique(ScanType type);

} // namespace nemesis
