#pragma once
/**
 * @file types.h
 * @brief Core enumerations and lightweight value types for the Nemesis scan engine.
 *
 * Every subsystem includes this header. Keep it free of heavy dependencies.
 */

#include <cstdint>
#include <string>
#include <vector>
#include <chrono>

namespace nemesis {

// ─── Port States (Nmap-compatible six-state model) ──────────────────────────

enum class PortState : uint8_t {
    Open           = 0,  // Accepting connections
    Closed         = 1,  // Accessible but nothing listening
    Filtered       = 2,  // Packet filtering prevents determination
    Unfiltered     = 3,  // Accessible but open/closed unknown (ACK scan)
    OpenFiltered   = 4,  // Cannot determine open vs filtered
    ClosedFiltered = 5,  // Cannot determine closed vs filtered
    Unknown        = 255
};

inline const char* port_state_str(PortState s) {
    switch (s) {
        case PortState::Open:           return "open";
        case PortState::Closed:         return "closed";
        case PortState::Filtered:       return "filtered";
        case PortState::Unfiltered:     return "unfiltered";
        case PortState::OpenFiltered:   return "open|filtered";
        case PortState::ClosedFiltered: return "closed|filtered";
        default:                        return "unknown";
    }
}

// ─── Scan Techniques ────────────────────────────────────────────────────────

enum class ScanType : uint8_t {
    TcpSyn          = 0,   // -sS
    TcpConnect      = 1,   // -sT
    TcpAck          = 2,   // -sA
    TcpWindow       = 3,   // -sW
    TcpMaimon       = 4,   // -sM
    TcpNull         = 5,   // -sN
    TcpFin          = 6,   // -sF
    TcpXmas         = 7,   // -sX
    TcpCustom       = 8,   //      custom flags
    Udp             = 9,   // -sU
    SctpInit        = 10,  // -sY
    SctpCookieEcho  = 11,  // -sZ
    IpProtocol      = 12,  // -sO
    Idle            = 13,  // -sI
    FtpBounce       = 14,  // -b
    ListScan        = 15,  // -sL
    PingScan        = 16,  // -sn
};

inline const char* scan_type_str(ScanType t) {
    switch (t) {
        case ScanType::TcpSyn:         return "tcp-syn";
        case ScanType::TcpConnect:     return "tcp-connect";
        case ScanType::TcpAck:         return "tcp-ack";
        case ScanType::TcpWindow:      return "tcp-window";
        case ScanType::TcpMaimon:      return "tcp-maimon";
        case ScanType::TcpNull:        return "tcp-null";
        case ScanType::TcpFin:         return "tcp-fin";
        case ScanType::TcpXmas:        return "tcp-xmas";
        case ScanType::TcpCustom:      return "tcp-custom";
        case ScanType::Udp:            return "udp";
        case ScanType::SctpInit:       return "sctp-init";
        case ScanType::SctpCookieEcho: return "sctp-cookie";
        case ScanType::IpProtocol:     return "ip-protocol";
        case ScanType::Idle:           return "idle";
        case ScanType::FtpBounce:      return "ftp-bounce";
        case ScanType::ListScan:       return "list";
        case ScanType::PingScan:       return "ping";
        default:                       return "unknown";
    }
}

inline bool scan_requires_raw_socket(ScanType t) {
    switch (t) {
        case ScanType::TcpConnect:
        case ScanType::ListScan:
        case ScanType::FtpBounce:
            return false;
        default:
            return true;
    }
}

// ─── Discovery Methods ──────────────────────────────────────────────────────

enum class DiscoveryMethod : uint8_t {
    IcmpEcho        = 0,  // -PE
    IcmpTimestamp   = 1,  // -PP
    IcmpNetmask     = 2,  // -PM
    TcpSynPing      = 3,  // -PS
    TcpAckPing      = 4,  // -PA
    UdpPing         = 5,  // -PU
    SctpInitPing    = 6,  // -PY
    ArpPing         = 7,  // -PR
    IpProtocolPing  = 8,  // -PO
    Skip            = 9,  // -Pn  (treat all hosts as up)
};

inline const char* discovery_method_str(DiscoveryMethod m) {
    switch (m) {
        case DiscoveryMethod::IcmpEcho:       return "icmp-echo";
        case DiscoveryMethod::IcmpTimestamp:   return "icmp-timestamp";
        case DiscoveryMethod::IcmpNetmask:    return "icmp-netmask";
        case DiscoveryMethod::TcpSynPing:     return "tcp-syn-ping";
        case DiscoveryMethod::TcpAckPing:     return "tcp-ack-ping";
        case DiscoveryMethod::UdpPing:        return "udp-ping";
        case DiscoveryMethod::SctpInitPing:   return "sctp-init-ping";
        case DiscoveryMethod::ArpPing:        return "arp-ping";
        case DiscoveryMethod::IpProtocolPing: return "ip-proto-ping";
        case DiscoveryMethod::Skip:           return "skip";
        default:                              return "unknown";
    }
}

// ─── Timing Templates ───────────────────────────────────────────────────────

enum class TimingTemplate : uint8_t {
    Paranoid   = 0,  // T0
    Sneaky     = 1,  // T1
    Polite     = 2,  // T2
    Normal     = 3,  // T3
    Aggressive = 4,  // T4
    Insane     = 5,  // T5
};

inline const char* timing_template_str(TimingTemplate t) {
    switch (t) {
        case TimingTemplate::Paranoid:   return "paranoid";
        case TimingTemplate::Sneaky:     return "sneaky";
        case TimingTemplate::Polite:     return "polite";
        case TimingTemplate::Normal:     return "normal";
        case TimingTemplate::Aggressive: return "aggressive";
        case TimingTemplate::Insane:     return "insane";
        default:                         return "unknown";
    }
}

// ─── NSE Script Categories ──────────────────────────────────────────────────

enum class ScriptCategory : uint16_t {
    Auth       = 0x0001,
    Broadcast  = 0x0002,
    Brute      = 0x0004,
    Default    = 0x0008,
    Discovery  = 0x0010,
    Dos        = 0x0020,
    Exploit    = 0x0040,
    External   = 0x0080,
    Fuzzer     = 0x0100,
    Intrusive  = 0x0200,
    Malware    = 0x0400,
    Safe       = 0x0800,
    Version    = 0x1000,
    Vuln       = 0x2000,
};

// ─── Severity (aligned with Nemesis Finding model) ──────────────────────────

enum class Severity : uint8_t {
    Critical = 0,
    High     = 1,
    Medium   = 2,
    Low      = 3,
    Info     = 4,
};

inline const char* severity_str(Severity s) {
    switch (s) {
        case Severity::Critical: return "critical";
        case Severity::High:     return "high";
        case Severity::Medium:   return "medium";
        case Severity::Low:      return "low";
        case Severity::Info:     return "info";
        default:                 return "info";
    }
}

// ─── IP Protocol Type ───────────────────────────────────────────────────────

enum class IpProto : uint8_t {
    ICMP  = 1,
    TCP   = 6,
    UDP   = 17,
    SCTP  = 132,
};

} // namespace nemesis
