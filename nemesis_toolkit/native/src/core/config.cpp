/**
 * @file config.cpp
 * @brief ScanConfig finalization and defaults.
 */

#include "config.h"
#include <algorithm>

namespace nemesis {

void ScanConfig::finalize() {
    // Apply timing template
    timing.apply_template(timing.template_level);

    // Default discovery methods
    if (discovery_methods.empty() && !skip_discovery) {
        if (scan_type == ScanType::ListScan || scan_type == ScanType::PingScan) {
            // For list/ping scans, use standard ping probes
            discovery_methods.push_back(DiscoveryMethod::IcmpEcho);
            discovery_methods.push_back(DiscoveryMethod::TcpSynPing);
            discovery_methods.push_back(DiscoveryMethod::TcpAckPing);
            discovery_methods.push_back(DiscoveryMethod::IcmpTimestamp);
        } else {
            // Default: ICMP echo + TCP SYN to port 443 + TCP ACK to port 80
            discovery_methods.push_back(DiscoveryMethod::IcmpEcho);
            discovery_methods.push_back(DiscoveryMethod::TcpSynPing);
        }
    }

    if (skip_discovery) {
        discovery_methods.clear();
        discovery_methods.push_back(DiscoveryMethod::Skip);
    }

    // Default scan type: use TcpConnect if no raw socket privilege available
    // (The engine will handle this at runtime)

    // Version detection intensity
    if (version_light) version_intensity = 2;
    if (version_all)   version_intensity = 9;

    // OS scan guess implies OS detect
    if (os_scan_guess) os_detect = true;

    // Concurrency from timing template
    if (concurrency <= 0) {
        switch (timing.template_level) {
            case TimingTemplate::Paranoid:
            case TimingTemplate::Sneaky:
            case TimingTemplate::Polite:
                concurrency = 1;
                break;
            case TimingTemplate::Normal:
                concurrency = 500;
                break;
            case TimingTemplate::Aggressive:
                concurrency = 800;
                break;
            case TimingTemplate::Insane:
                concurrency = 1500;
                break;
        }
    }

    // Output prefix handling
    if (all_output && !output_prefix.empty()) {
        if (normal_output.empty())   normal_output   = output_prefix + ".nmap";
        if (xml_output.empty())      xml_output      = output_prefix + ".xml";
        if (grepable_output.empty()) grepable_output = output_prefix + ".gnmap";
        if (json_output.empty())     json_output     = output_prefix + ".json";
    }
}

} // namespace nemesis
