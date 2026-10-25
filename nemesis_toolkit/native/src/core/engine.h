#pragma once
/**
 * @file engine.h
 * @brief NemesisScanEngine — the top-level controller that orchestrates
 *        discovery, scanning, detection, scripting, and output.
 */

#include "config.h"
#include "scan_result.h"
#include "timing.h"
#include <atomic>
#include <functional>
#include <memory>
#include <string>

namespace nemesis {

/**
 * Progress callback signature.
 *   phase   : "discovery", "scanning", "service-detect", "os-detect", "scripting"
 *   current : items completed so far
 *   total   : total items to process
 *   message : human-readable status string
 */
using ProgressCallback = std::function<void(
    const std::string& phase,
    int current,
    int total,
    const std::string& message
)>;

/**
 * Main scanning engine. Thread-safe: one Engine instance may be used
 * from multiple threads, but only one scan() call can be active at a time.
 *
 * Usage:
 *   NemesisScanEngine engine;
 *   engine.set_progress_callback([](auto&&... args) { ... });
 *   ScanConfig config;
 *   config.targets = {"192.168.1.1"};
 *   config.scan_type = ScanType::TcpSyn;
 *   ScanResult result = engine.scan(config);
 */
class NemesisScanEngine {
public:
    NemesisScanEngine();
    ~NemesisScanEngine();

    // Non-copyable, movable
    NemesisScanEngine(const NemesisScanEngine&) = delete;
    NemesisScanEngine& operator=(const NemesisScanEngine&) = delete;
    NemesisScanEngine(NemesisScanEngine&&) noexcept;
    NemesisScanEngine& operator=(NemesisScanEngine&&) noexcept;

    /**
     * Execute a scan with the given configuration.
     * This is the main entry point. Blocks until the scan completes or is cancelled.
     *
     * @param config  Fully populated scan configuration.
     * @return        Complete scan results.
     * @throws std::runtime_error on fatal errors (e.g. no raw socket privilege).
     */
    ScanResult scan(const ScanConfig& config);

    /**
     * Cancel a running scan. Safe to call from any thread.
     * The scan() call will return partial results.
     */
    void cancel();

    /**
     * Check whether a scan is currently running.
     */
    bool is_scanning() const;

    /**
     * Get a snapshot of current progress (0.0 – 1.0).
     */
    double progress() const;

    /**
     * Set a callback to receive progress updates during scanning.
     */
    void set_progress_callback(ProgressCallback cb);

    /**
     * Check if the current platform supports raw sockets (admin/root).
     */
    static bool has_raw_socket_privilege();

    /**
     * List available network interfaces.
     */
    static std::vector<std::string> list_interfaces();

    /**
     * Get the engine version string.
     */
    static std::string version();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace nemesis
