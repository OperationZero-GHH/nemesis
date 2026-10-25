/**
 * @file tcp_connect_scan.cpp
 * @brief TCP Connect scan implementation — multithreaded non-blocking connect().
 *
 * Uses non-blocking sockets with poll/select to achieve high concurrency
 * without requiring raw sockets or admin privileges.
 */

#include "tcp_connect_scan.h"
#include "../platform/platform.h"
#include <vector>
#include <thread>
#include <future>
#include <queue>
#include <mutex>
#include <chrono>
#include <cstring>
#include <algorithm>

#ifdef NEMESIS_WINDOWS
    #include <mstcpip.h>
#endif

namespace nemesis {

namespace {

/**
 * Set a socket to non-blocking mode.
 */
bool set_nonblocking(socket_t sock) {
#ifdef NEMESIS_WINDOWS
    u_long mode = 1;
    return ioctlsocket(sock, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) return false;
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK) != -1;
#endif
}

/**
 * Attempt a single non-blocking TCP connect to target:port with a timeout.
 * Returns the PortState and a reason string.
 */
struct ProbeResult {
    PortState   state;
    std::string reason;
    double      rtt_ms = 0.0;
};

ProbeResult tcp_connect_probe(
    const std::string& target_ip,
    uint16_t port,
    int timeout_ms,
    bool is_ipv6
) {
    auto start = std::chrono::steady_clock::now();

    // Create socket
    int family = is_ipv6 ? AF_INET6 : AF_INET;
    socket_t sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCK) {
        return {PortState::Unknown, "socket-error"};
    }

    // Set non-blocking
    if (!set_nonblocking(sock)) {
        close_socket(sock);
        return {PortState::Unknown, "fcntl-error"};
    }

    // Prepare address
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

    // Initiate non-blocking connect
    int ret = connect(sock, reinterpret_cast<struct sockaddr*>(&addr), addr_len);

    if (ret == 0) {
        // Immediate connect (unlikely for non-blocking, but possible on localhost)
        auto elapsed = std::chrono::steady_clock::now() - start;
        double rtt = std::chrono::duration<double, std::milli>(elapsed).count();
        close_socket(sock);
        return {PortState::Open, "syn-ack", rtt};
    }

    // Check if connect is in progress
#ifdef NEMESIS_WINDOWS
    int err = WSAGetLastError();
    if (err != WSAEWOULDBLOCK) {
        close_socket(sock);
        if (err == WSAECONNREFUSED)
            return {PortState::Closed, "conn-refused"};
        if (err == WSAENETUNREACH || err == WSAEHOSTUNREACH)
            return {PortState::Filtered, "net-unreachable"};
        return {PortState::Filtered, "connect-error"};
    }
#else
    if (errno != EINPROGRESS) {
        close_socket(sock);
        if (errno == ECONNREFUSED)
            return {PortState::Closed, "conn-refused"};
        if (errno == ENETUNREACH || errno == EHOSTUNREACH)
            return {PortState::Filtered, "net-unreachable"};
        return {PortState::Filtered, "connect-error"};
    }
#endif

    // Wait for connect to complete using poll/select
#ifdef NEMESIS_WINDOWS
    fd_set write_fds, except_fds;
    FD_ZERO(&write_fds);
    FD_ZERO(&except_fds);
    FD_SET(sock, &write_fds);
    FD_SET(sock, &except_fds);

    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    ret = select(0, nullptr, &write_fds, &except_fds, &tv);
#else
    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLOUT;
    pfd.revents = 0;

    ret = poll(&pfd, 1, timeout_ms);
#endif

    auto elapsed = std::chrono::steady_clock::now() - start;
    double rtt = std::chrono::duration<double, std::milli>(elapsed).count();

    if (ret <= 0) {
        // Timeout — no response
        close_socket(sock);
        return {PortState::Filtered, "no-response", rtt};
    }

    // Check if the connection succeeded or was refused
    int so_error = 0;
    socklen_t so_len = sizeof(so_error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR,
#ifdef NEMESIS_WINDOWS
               reinterpret_cast<char*>(&so_error),
#else
               &so_error,
#endif
               &so_len);

    close_socket(sock);

    if (so_error == 0) {
        return {PortState::Open, "syn-ack", rtt};
    }

#ifdef NEMESIS_WINDOWS
    if (so_error == WSAECONNREFUSED)
#else
    if (so_error == ECONNREFUSED)
#endif
    {
        return {PortState::Closed, "conn-refused", rtt};
    }

#ifdef NEMESIS_WINDOWS
    if (so_error == WSAETIMEDOUT)
#else
    if (so_error == ETIMEDOUT)
#endif
    {
        return {PortState::Filtered, "no-response", rtt};
    }

    return {PortState::Filtered, "connect-error", rtt};
}

} // anonymous namespace

// ─── TcpConnectScan implementation ──────────────────────────────────────────

std::vector<PortResult> TcpConnectScan::scan_ports(
    const std::string& target_ip,
    const std::vector<uint16_t>& ports,
    const TimingConfig& timing,
    const EvasionConfig& evasion,
    const std::atomic<bool>& cancel_flag
) {
    std::vector<PortResult> results;
    results.reserve(ports.size());

    // Determine IPv6
    bool is_ipv6 = target_ip.find(':') != std::string::npos;

    // Calculate timeout in milliseconds
    int timeout_ms = static_cast<int>(timing.initial_rtt_timeout.count());
    if (timeout_ms <= 0) timeout_ms = 1500;

    // Determine parallelism
    int parallelism = timing.effective_parallelism(static_cast<int>(ports.size()));
    parallelism = std::min(parallelism, static_cast<int>(ports.size()));
    parallelism = std::max(parallelism, 1);

    // Scan delay
    auto scan_delay = timing.scan_delay;

    // Use thread pool with futures for concurrent scanning
    std::vector<std::future<std::pair<uint16_t, ProbeResult>>> futures;
    size_t port_idx = 0;

    while (port_idx < ports.size() && !cancel_flag.load(std::memory_order_relaxed)) {
        // Launch batch of async probes
        futures.clear();
        int batch = std::min(parallelism, static_cast<int>(ports.size() - port_idx));

        for (int i = 0; i < batch && !cancel_flag.load(std::memory_order_relaxed); ++i) {
            uint16_t port = ports[port_idx + i];
            futures.push_back(std::async(std::launch::async,
                [&target_ip, port, timeout_ms, is_ipv6]() -> std::pair<uint16_t, ProbeResult> {
                    return {port, tcp_connect_probe(target_ip, port, timeout_ms, is_ipv6)};
                }
            ));
        }

        // Collect results
        for (auto& fut : futures) {
            if (cancel_flag.load(std::memory_order_relaxed)) break;

            auto [port, probe] = fut.get();

            // Retry logic for filtered/unknown ports
            int retries = 0;
            while ((probe.state == PortState::Filtered || probe.state == PortState::Unknown)
                    && retries < timing.max_retries
                    && !cancel_flag.load(std::memory_order_relaxed)) {
                probe = tcp_connect_probe(target_ip, port, timeout_ms, is_ipv6);
                ++retries;
            }

            PortResult pr;
            pr.port     = port;
            pr.protocol = "tcp";
            pr.state    = probe.state;
            pr.reason   = probe.reason;
            results.push_back(std::move(pr));
        }

        port_idx += batch;

        // Apply scan delay between batches
        if (scan_delay.count() > 0 && port_idx < ports.size()) {
            std::this_thread::sleep_for(scan_delay);
        }
    }

    // Sort by port number
    std::sort(results.begin(), results.end(),
        [](const PortResult& a, const PortResult& b) { return a.port < b.port; });

    return results;
}

// ─── Scan technique factory ─────────────────────────────────────────────────

std::unique_ptr<IScanTechnique> create_scan_technique(ScanType type) {
    switch (type) {
        case ScanType::TcpConnect:
            return std::make_unique<TcpConnectScan>();

        // Phase 2 stubs — will be implemented with raw sockets
        case ScanType::TcpSyn:
        case ScanType::TcpAck:
        case ScanType::TcpWindow:
        case ScanType::TcpMaimon:
        case ScanType::TcpNull:
        case ScanType::TcpFin:
        case ScanType::TcpXmas:
        case ScanType::TcpCustom:
        case ScanType::Udp:
        case ScanType::SctpInit:
        case ScanType::SctpCookieEcho:
        case ScanType::IpProtocol:
        case ScanType::Idle:
        case ScanType::FtpBounce:
            // Fall back to TcpConnect for now
            return std::make_unique<TcpConnectScan>();

        default:
            return std::make_unique<TcpConnectScan>();
    }
}

} // namespace nemesis
