/**
 * @file timing.cpp
 * @brief Timing engine implementation — T0–T5 presets and rate limiter.
 */

#include "timing.h"
#include <thread>
#include <algorithm>

namespace nemesis {

// ─── Timing template presets ────────────────────────────────────────────────

void TimingConfig::apply_template(TimingTemplate tmpl) {
    template_level = tmpl;

    switch (tmpl) {
        case TimingTemplate::Paranoid:  // T0
            max_parallelism     = 1;
            min_parallelism     = 0;
            max_retries         = 10;
            initial_rtt_timeout = ms{300000};   // 5 minutes
            max_rtt_timeout     = ms{300000};
            min_rtt_timeout     = ms{100};
            scan_delay          = ms{300000};   // 5 minutes between probes
            max_scan_delay      = ms{300000};
            min_rate            = 0;
            max_rate            = 0;
            host_timeout        = sec{0};
            break;

        case TimingTemplate::Sneaky:  // T1
            max_parallelism     = 1;
            min_parallelism     = 0;
            max_retries         = 10;
            initial_rtt_timeout = ms{15000};
            max_rtt_timeout     = ms{15000};
            min_rtt_timeout     = ms{100};
            scan_delay          = ms{15000};
            max_scan_delay      = ms{15000};
            min_rate            = 0;
            max_rate            = 0;
            host_timeout        = sec{0};
            break;

        case TimingTemplate::Polite:  // T2
            max_parallelism     = 1;
            min_parallelism     = 0;
            max_retries         = 10;
            initial_rtt_timeout = ms{1000};
            max_rtt_timeout     = ms{10000};
            min_rtt_timeout     = ms{100};
            scan_delay          = ms{400};
            max_scan_delay      = ms{400};
            min_rate            = 0;
            max_rate            = 0;
            host_timeout        = sec{0};
            break;

        case TimingTemplate::Normal:  // T3 (default)
            max_parallelism     = 0;  // auto
            min_parallelism     = 0;
            max_retries         = 10;
            initial_rtt_timeout = ms{1000};
            max_rtt_timeout     = ms{10000};
            min_rtt_timeout     = ms{100};
            scan_delay          = ms{0};
            max_scan_delay      = ms{1000};
            min_rate            = 0;
            max_rate            = 0;
            host_timeout        = sec{0};
            break;

        case TimingTemplate::Aggressive:  // T4
            max_parallelism     = 0;  // auto
            min_parallelism     = 0;
            max_retries         = 6;
            initial_rtt_timeout = ms{500};
            max_rtt_timeout     = ms{1250};
            min_rtt_timeout     = ms{100};
            scan_delay          = ms{0};
            max_scan_delay      = ms{10};
            min_rate            = 0;
            max_rate            = 0;
            host_timeout        = sec{300};
            break;

        case TimingTemplate::Insane:  // T5
            max_parallelism     = 0;  // auto
            min_parallelism     = 0;
            max_retries         = 2;
            initial_rtt_timeout = ms{250};
            max_rtt_timeout     = ms{300};
            min_rtt_timeout     = ms{50};
            scan_delay          = ms{0};
            max_scan_delay      = ms{5};
            min_rate            = 300;
            max_rate            = 0;
            host_timeout        = sec{900};
            break;
    }
}

int TimingConfig::effective_parallelism(int num_targets) const {
    if (max_parallelism > 0)
        return max_parallelism;

    // Auto-detect based on timing template
    int computed = 1;
    switch (template_level) {
        case TimingTemplate::Paranoid:
        case TimingTemplate::Sneaky:
        case TimingTemplate::Polite:
            computed = 1;
            break;
        case TimingTemplate::Normal:
            computed = std::min(num_targets, 256);
            break;
        case TimingTemplate::Aggressive:
            computed = std::min(num_targets, 512);
            break;
        case TimingTemplate::Insane:
            computed = std::min(num_targets, 1024);
            break;
    }

    if (min_parallelism > 0)
        computed = std::max(computed, min_parallelism);

    return std::max(computed, 1);
}

ms TimingConfig::probe_timeout(ms observed_rtt) const {
    if (observed_rtt.count() <= 0)
        return initial_rtt_timeout;

    // Adaptive: 2x observed RTT, clamped to [min, max]
    auto adaptive = ms{observed_rtt.count() * 2};
    adaptive = std::max(adaptive, min_rtt_timeout);
    adaptive = std::min(adaptive, max_rtt_timeout);
    return adaptive;
}

// ─── Rate Limiter ───────────────────────────────────────────────────────────

RateLimiter::RateLimiter(double max_pps, double min_pps)
    : max_pps_(max_pps), min_pps_(min_pps), packets_(0),
      start_(std::chrono::steady_clock::now()),
      last_send_(start_) {}

void RateLimiter::acquire() {
    if (max_pps_ <= 0) {
        // No rate limit — just count
        std::lock_guard lock(mu_);
        ++packets_;
        last_send_ = std::chrono::steady_clock::now();
        return;
    }

    std::unique_lock lock(mu_);
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration<double>(now - start_).count();

    // Calculate minimum interval between packets
    double interval = 1.0 / max_pps_;
    auto since_last = std::chrono::duration<double>(now - last_send_).count();

    if (since_last < interval) {
        double wait = interval - since_last;
        lock.unlock();
        std::this_thread::sleep_for(
            std::chrono::microseconds(static_cast<int64_t>(wait * 1e6))
        );
        lock.lock();
    }

    ++packets_;
    last_send_ = std::chrono::steady_clock::now();
}

void RateLimiter::set_rates(double max_pps, double min_pps) {
    std::lock_guard lock(mu_);
    max_pps_ = max_pps;
    min_pps_ = min_pps;
}

double RateLimiter::current_rate() const {
    std::lock_guard lock(mu_);
    auto elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - start_
    ).count();
    if (elapsed <= 0) return 0;
    return static_cast<double>(packets_) / elapsed;
}

} // namespace nemesis
