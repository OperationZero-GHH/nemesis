#pragma once
/**
 * @file timing.h
 * @brief Timing profiles and rate-limiting for scan operations.
 *
 * Implements Nmap-compatible T0–T5 templates plus fine-grained control.
 */

#include "types.h"
#include <chrono>
#include <algorithm>
#include <mutex>
#include <condition_variable>

namespace nemesis {

using ms = std::chrono::milliseconds;
using sec = std::chrono::seconds;

// ─── Timing Configuration ───────────────────────────────────────────────────

struct TimingConfig {
    TimingTemplate template_level = TimingTemplate::Normal;

    // Parallelism
    int  max_parallelism    = 0;     // 0 = auto-detect
    int  min_parallelism    = 0;

    // Retries
    int  max_retries        = 10;

    // RTT timeouts
    ms   initial_rtt_timeout{1000};
    ms   max_rtt_timeout{10000};
    ms   min_rtt_timeout{100};

    // Scan delay between probes
    ms   scan_delay{0};
    ms   max_scan_delay{1000};

    // Rate limiting (packets per second)
    double min_rate         = 0.0;   // 0 = no minimum
    double max_rate         = 0.0;   // 0 = no maximum

    // Host timeout
    sec  host_timeout{0};            // 0 = no timeout

    /**
     * Apply a timing template preset, overriding current values.
     */
    void apply_template(TimingTemplate tmpl);

    /**
     * Compute the effective parallelism for a given number of targets.
     */
    int effective_parallelism(int num_targets) const;

    /**
     * Compute the timeout for a single probe, factoring in adaptive RTT.
     */
    ms probe_timeout(ms observed_rtt = ms{0}) const;
};

// ─── Rate Limiter ───────────────────────────────────────────────────────────

/**
 * Thread-safe token-bucket rate limiter for packet transmission.
 */
class RateLimiter {
public:
    explicit RateLimiter(double max_pps = 0.0, double min_pps = 0.0);

    /**
     * Wait until a packet can be sent. Returns immediately if no rate limit.
     */
    void acquire();

    /**
     * Update the rate limits.
     */
    void set_rates(double max_pps, double min_pps = 0.0);

    /**
     * Get current effective rate (packets sent / elapsed time).
     */
    double current_rate() const;

private:
    double              max_pps_     = 0.0;
    double              min_pps_     = 0.0;
    int64_t             packets_     = 0;
    std::chrono::steady_clock::time_point start_;
    std::chrono::steady_clock::time_point last_send_;
    mutable std::mutex  mu_;
    std::condition_variable cv_;
};

} // namespace nemesis
