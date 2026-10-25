#pragma once
/**
 * @file tcp_connect_scan.h
 * @brief TCP Connect scan — full three-way handshake using connect().
 *
 * This is the only scan type that works without raw socket privileges.
 * It uses the OS kernel's TCP stack to complete the connection.
 */

#include "scan_technique.h"

namespace nemesis {

class TcpConnectScan : public IScanTechnique {
public:
    ScanType type() const override { return ScanType::TcpConnect; }
    std::string name() const override { return "TCP Connect Scan"; }
    bool requires_raw_socket() const override { return false; }
    std::string default_protocol() const override { return "tcp"; }

    std::vector<PortResult> scan_ports(
        const std::string& target_ip,
        const std::vector<uint16_t>& ports,
        const TimingConfig& timing,
        const EvasionConfig& evasion,
        const std::atomic<bool>& cancel_flag
    ) override;
};

} // namespace nemesis
