/**
 * @file engine.cpp
 * @brief NemesisScanEngine implementation — orchestrates all phases.
 */

#include "engine.h"
#include "target.h"
#include "port_spec.h"
#include "../scanning/scan_technique.h"
#include "../scanning/tcp_connect_scan.h"
#include "../detection/service_detector.h"
#include "../platform/platform.h"
#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <ctime>

namespace nemesis {

// ─── Helpers ────────────────────────────────────────────────────────────────

static std::string iso8601_now() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    struct tm tm_buf{};
#ifdef NEMESIS_WINDOWS
    gmtime_s(&tm_buf, &time_t_now);
#else
    gmtime_r(&time_t_now, &tm_buf);
#endif
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
    return std::string(buf);
}

// ─── Engine implementation (pimpl) ──────────────────────────────────────────

struct NemesisScanEngine::Impl {
    std::atomic<bool>    cancel{false};
    std::atomic<bool>    scanning{false};
    std::atomic<double>  progress_val{0.0};
    ProgressCallback     progress_cb;
    std::mutex           mu;

    WinsockInit          winsock;  // RAII Winsock init (no-op on non-Windows)

    void report_progress(const std::string& phase, int current, int total,
                         const std::string& msg) {
        if (total > 0)
            progress_val.store(static_cast<double>(current) / total, std::memory_order_relaxed);
        if (progress_cb)
            progress_cb(phase, current, total, msg);
    }
};

NemesisScanEngine::NemesisScanEngine()
    : impl_(std::make_unique<Impl>()) {}

NemesisScanEngine::~NemesisScanEngine() = default;

NemesisScanEngine::NemesisScanEngine(NemesisScanEngine&&) noexcept = default;
NemesisScanEngine& NemesisScanEngine::operator=(NemesisScanEngine&&) noexcept = default;

void NemesisScanEngine::cancel() {
    impl_->cancel.store(true, std::memory_order_release);
}

bool NemesisScanEngine::is_scanning() const {
    return impl_->scanning.load(std::memory_order_acquire);
}

double NemesisScanEngine::progress() const {
    return impl_->progress_val.load(std::memory_order_relaxed);
}

void NemesisScanEngine::set_progress_callback(ProgressCallback cb) {
    impl_->progress_cb = std::move(cb);
}

bool NemesisScanEngine::has_raw_socket_privilege() {
    return check_raw_socket_privilege();
}

std::vector<std::string> NemesisScanEngine::list_interfaces() {
    return nemesis::list_interfaces();
}

std::string NemesisScanEngine::version() {
    return "1.0.0";
}

// ─── Main scan orchestration ────────────────────────────────────────────────

ScanResult NemesisScanEngine::scan(const ScanConfig& config_in) {
    std::lock_guard lock(impl_->mu);

    impl_->cancel.store(false);
    impl_->scanning.store(true);
    impl_->progress_val.store(0.0);

    ScanResult result;
    result.scanner = "nemesis-scan";
    result.scanner_version = version();
    result.start_time = iso8601_now();
    auto scan_start = std::chrono::steady_clock::now();

    // Make a mutable copy and finalize defaults
    ScanConfig config = config_in;
    config.finalize();

    // ── Phase 1: Parse targets ──
    impl_->report_progress("targets", 0, 1, "Parsing targets...");

    TargetParser target_parser;
    try {
        for (const auto& spec : config.targets) {
            target_parser.add_spec(spec);
        }
        if (!config.target_file.empty()) {
            target_parser.add_file(config.target_file);
        }
        if (config.random_targets && config.random_count > 0) {
            target_parser.add_random(config.random_count);
        }
        for (const auto& excl : config.exclude_hosts) {
            target_parser.exclude(excl);
        }
        if (!config.exclude_file.empty()) {
            target_parser.exclude_file(config.exclude_file);
        }
        if (config.evasion.randomize_hosts) {
            target_parser.shuffle();
        }
    } catch (const std::exception& e) {
        impl_->scanning.store(false);
        throw std::runtime_error(std::string("Target parsing failed: ") + e.what());
    }

    auto targets = target_parser.resolve();
    result.hosts_total = static_cast<int>(targets.size());

    if (targets.empty()) {
        impl_->scanning.store(false);
        result.end_time = iso8601_now();
        return result;
    }

    // ── Phase 2: Parse ports ──
    PortSpec port_spec;
    try {
        if (config.all_ports) {
            port_spec.set_all_ports();
        } else if (config.fast_scan) {
            port_spec.set_fast_scan();
        } else if (config.top_ports > 0) {
            port_spec.set_top_ports(config.top_ports);
        } else if (!config.port_spec.empty()) {
            port_spec.parse(config.port_spec);
        } else {
            port_spec.set_top_ports(100);  // Default: top 100
        }
        if (config.randomize_ports) {
            port_spec.shuffle();
        }
    } catch (const std::exception& e) {
        impl_->scanning.store(false);
        throw std::runtime_error(std::string("Port parsing failed: ") + e.what());
    }

    auto tcp_ports = port_spec.tcp_ports();
    auto udp_ports = port_spec.udp_ports();

    // ── Phase 3: Host discovery ──
    // For Phase 1, skip discovery (treat all hosts as up) unless it's a list/ping scan
    impl_->report_progress("discovery", 0, static_cast<int>(targets.size()),
                          "Discovering hosts...");

    bool skip_discovery = config.skip_discovery;
    // For TCP Connect scans, we don't need discovery — connect will fail on down hosts
    if (config.scan_type == ScanType::TcpConnect) {
        skip_discovery = true;
    }

    for (size_t i = 0; i < targets.size(); ++i) {
        if (impl_->cancel.load(std::memory_order_relaxed)) break;

        HostResult host;
        host.ip       = targets[i].ip;
        host.hostname = targets[i].hostname;

        if (config.scan_type == ScanType::ListScan) {
            // List scan: just list the target, don't scan
            host.is_up = true;
            host.status_reason = "user-set";
            result.hosts.push_back(std::move(host));
            ++result.hosts_up;
            impl_->report_progress("discovery", static_cast<int>(i + 1),
                                  static_cast<int>(targets.size()),
                                  "Listed: " + targets[i].ip);
            continue;
        }

        // Assume host is up (discovery is Phase 2 work with raw sockets)
        host.is_up = true;
        host.status_reason = skip_discovery ? "user-set" : "syn-ack";

        // ── Phase 4: Port scanning ──
        if (config.scan_type != ScanType::PingScan) {
            auto technique = create_scan_technique(config.scan_type);

            // Check privilege requirements
            if (technique->requires_raw_socket() && !has_raw_socket_privilege()) {
                // Fall back to TCP Connect
                technique = create_scan_technique(ScanType::TcpConnect);
            }

            impl_->report_progress("scanning",
                                  static_cast<int>(i),
                                  static_cast<int>(targets.size()),
                                  "Scanning " + host.ip + " (" + std::to_string(tcp_ports.size()) + " ports)");

            auto port_start = std::chrono::steady_clock::now();

            host.ports = technique->scan_ports(
                host.ip, tcp_ports, config.timing, config.evasion, impl_->cancel
            );

            auto port_elapsed = std::chrono::steady_clock::now() - port_start;
            host.scan_duration_ms = std::chrono::duration<double, std::milli>(port_elapsed).count();

            // ── Phase 5: Service detection ──
            if (config.service_detect && !impl_->cancel.load(std::memory_order_relaxed)) {
                impl_->report_progress("service-detect",
                                      static_cast<int>(i),
                                      static_cast<int>(targets.size()),
                                      "Detecting services on " + host.ip);

                ServiceDetector detector;
                int svc_timeout = static_cast<int>(config.timing.initial_rtt_timeout.count());
                if (svc_timeout <= 0) svc_timeout = 2000;

                detector.detect_batch(
                    host.ip, host.ports,
                    config.version_intensity,
                    svc_timeout,
                    std::min(config.concurrency, 20),  // Limit service detection parallelism
                    impl_->cancel
                );
            }

            // Check if host actually responded to any probe
            bool any_response = false;
            for (const auto& p : host.ports) {
                if (p.state != PortState::Filtered && p.state != PortState::Unknown) {
                    any_response = true;
                    break;
                }
            }
            if (!any_response && !skip_discovery) {
                host.is_up = false;
                host.status_reason = "no-response";
            }
        }

        if (host.is_up)
            ++result.hosts_up;
        else
            ++result.hosts_down;

        result.hosts.push_back(std::move(host));

        impl_->report_progress("scanning",
                              static_cast<int>(i + 1),
                              static_cast<int>(targets.size()),
                              "Completed " + targets[i].ip);
    }

    // ── Finalize ──
    auto scan_elapsed = std::chrono::steady_clock::now() - scan_start;
    result.elapsed_seconds = std::chrono::duration<double>(scan_elapsed).count();
    result.end_time = iso8601_now();

    impl_->progress_val.store(1.0);
    impl_->scanning.store(false);

    return result;
}

// ─── Platform helpers ───────────────────────────────────────────────────────

std::string default_interface() {
    // TODO: Implement per-platform
    return "";
}

std::vector<std::string> list_interfaces() {
    std::vector<std::string> result;

#ifdef NEMESIS_WINDOWS
    // Use GetAdaptersAddresses
    ULONG size = 15000;
    auto* addrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(malloc(size));
    if (!addrs) return result;

    ULONG ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, addrs, &size);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        free(addrs);
        addrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(malloc(size));
        if (!addrs) return result;
        ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, addrs, &size);
    }

    if (ret == NO_ERROR) {
        for (auto* adapter = addrs; adapter != nullptr; adapter = adapter->Next) {
            if (adapter->OperStatus == IfOperStatusUp) {
                // Convert wide string to narrow
                char name[256];
                WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1, name, sizeof(name), nullptr, nullptr);
                result.emplace_back(name);
            }
        }
    }
    free(addrs);

#else
    struct ifaddrs* ifap = nullptr;
    if (getifaddrs(&ifap) == 0) {
        std::set<std::string> seen;
        for (auto* ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_name && (ifa->ifa_flags & IFF_UP) && seen.insert(ifa->ifa_name).second) {
                result.emplace_back(ifa->ifa_name);
            }
        }
        freeifaddrs(ifap);
    }
#endif

    return result;
}

} // namespace nemesis
