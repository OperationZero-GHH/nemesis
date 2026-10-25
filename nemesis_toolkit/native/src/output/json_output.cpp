/**
 * @file json_output.cpp
 * @brief High-performance JSON serializer for scan results and Nemesis findings.
 */

#include "json_output.h"
#include "../core/types.h"
#include <sstream>
#include <fstream>
#include <iomanip>

namespace nemesis {

namespace {

void json_escape_into(std::string& out, const std::string& s) {
    out.push_back('"');
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out.append("\\\""); break;
            case '\\': out.append("\\\\"); break;
            case '\b': out.append("\\b");  break;
            case '\f': out.append("\\f");  break;
            case '\n': out.append("\\n");  break;
            case '\r': out.append("\\r");  break;
            case '\t': out.append("\\t");  break;
            default:
                if (c < 0x20) {
                    char hex[8];
                    snprintf(hex, sizeof(hex), "\\u%04x", c);
                    out.append(hex);
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    out.push_back('"');
}

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    json_escape_into(out, s);
    return out;
}

} // anonymous namespace

std::string scan_result_to_json(const ScanResult& result, bool pretty) {
    std::ostringstream ss;
    const std::string nl = pretty ? "\n" : "";
    const std::string ind1 = pretty ? "  " : "";
    const std::string ind2 = pretty ? "    " : "";
    const std::string ind3 = pretty ? "      " : "";
    const std::string ind4 = pretty ? "        " : "";

    ss << "{" << nl;
    ss << ind1 << "\"scanner\": " << json_escape(result.scanner) << "," << nl;
    ss << ind1 << "\"scanner_version\": " << json_escape(result.scanner_version) << "," << nl;
    ss << ind1 << "\"command_line\": " << json_escape(result.command_line) << "," << nl;
    ss << ind1 << "\"start_time\": " << json_escape(result.start_time) << "," << nl;
    ss << ind1 << "\"end_time\": " << json_escape(result.end_time) << "," << nl;
    ss << ind1 << "\"elapsed_seconds\": " << result.elapsed_seconds << "," << nl;
    ss << ind1 << "\"hosts_total\": " << result.hosts_total << "," << nl;
    ss << ind1 << "\"hosts_up\": " << result.hosts_up << "," << nl;
    ss << ind1 << "\"hosts_down\": " << result.hosts_down << "," << nl;
    ss << ind1 << "\"hosts\": [" << nl;

    for (size_t h = 0; h < result.hosts.size(); ++h) {
        const auto& host = result.hosts[h];
        ss << ind2 << "{" << nl;
        ss << ind3 << "\"ip\": " << json_escape(host.ip) << "," << nl;
        ss << ind3 << "\"hostname\": " << json_escape(host.hostname) << "," << nl;
        ss << ind3 << "\"is_up\": " << (host.is_up ? "true" : "false") << "," << nl;
        ss << ind3 << "\"status_reason\": " << json_escape(host.status_reason) << "," << nl;
        ss << ind3 << "\"latency_ms\": " << host.latency_ms << "," << nl;
        ss << ind3 << "\"scan_duration_ms\": " << host.scan_duration_ms << "," << nl;

        // Ports
        ss << ind3 << "\"ports\": [" << nl;
        for (size_t p = 0; p < host.ports.size(); ++p) {
            const auto& port = host.ports[p];
            ss << ind4 << "{" << nl;
            ss << ind4 << "  \"port\": " << port.port << "," << nl;
            ss << ind4 << "  \"protocol\": " << json_escape(port.protocol) << "," << nl;
            ss << ind4 << "  \"state\": " << json_escape(port_state_str(port.state)) << "," << nl;
            ss << ind4 << "  \"reason\": " << json_escape(port.reason) << "," << nl;
            ss << ind4 << "  \"service\": " << json_escape(port.service) << "," << nl;
            ss << ind4 << "  \"product\": " << json_escape(port.product) << "," << nl;
            ss << ind4 << "  \"version\": " << json_escape(port.version) << "," << nl;
            ss << ind4 << "  \"extra_info\": " << json_escape(port.extra_info) << "," << nl;
            ss << ind4 << "  \"cpe\": " << json_escape(port.cpe) << "," << nl;
            ss << ind4 << "  \"banner\": " << json_escape(port.banner) << "," << nl;
            ss << ind4 << "  \"is_ssl\": " << (port.is_ssl ? "true" : "false");

            if (!port.scripts.empty()) {
                ss << "," << nl << ind4 << "  \"scripts\": [" << nl;
                for (size_t s = 0; s < port.scripts.size(); ++s) {
                    const auto& sc = port.scripts[s];
                    ss << ind4 << "    {\"id\": " << json_escape(sc.id)
                       << ", \"output\": " << json_escape(sc.output) << "}"
                       << (s + 1 < port.scripts.size() ? "," : "") << nl;
                }
                ss << ind4 << "  ]" << nl;
            } else {
                ss << nl;
            }

            ss << ind4 << "}" << (p + 1 < host.ports.size() ? "," : "") << nl;
        }
        ss << ind3 << "]," << nl;

        // OS
        ss << ind3 << "\"os\": {" << nl;
        ss << ind3 << "  \"matches\": [" << nl;
        for (size_t m = 0; m < host.os.matches.size(); ++m) {
            const auto& match = host.os.matches[m];
            ss << ind4 << "{" << nl;
            ss << ind4 << "  \"name\": " << json_escape(match.name) << "," << nl;
            ss << ind4 << "  \"accuracy\": " << match.accuracy << "," << nl;
            ss << ind4 << "  \"device_type\": " << json_escape(match.device_type) << "," << nl;
            ss << ind4 << "  \"os_family\": " << json_escape(match.os_family) << nl;
            ss << ind4 << "}" << (m + 1 < host.os.matches.size() ? "," : "") << nl;
        }
        ss << ind3 << "  ]," << nl;
        ss << ind3 << "  \"uptime_seconds\": " << host.os.uptime_seconds << nl;
        ss << ind3 << "}," << nl;

        // Traceroute
        ss << ind3 << "\"traceroute\": [" << nl;
        for (size_t tr = 0; tr < host.traceroute.size(); ++tr) {
            const auto& hop = host.traceroute[tr];
            ss << ind4 << "{\"ttl\": " << hop.ttl << ", \"ip\": " << json_escape(hop.ip)
               << ", \"hostname\": " << json_escape(hop.hostname)
               << ", \"rtt_ms\": " << hop.rtt_ms
               << ", \"timed_out\": " << (hop.timed_out ? "true" : "false") << "}"
               << (tr + 1 < host.traceroute.size() ? "," : "") << nl;
        }
        ss << ind3 << "]" << nl;

        ss << ind2 << "}" << (h + 1 < result.hosts.size() ? "," : "") << nl;
    }

    ss << ind1 << "]" << nl;
    ss << "}";
    return ss.str();
}

std::string scan_result_to_findings_json(const ScanResult& result, bool pretty) {
    std::ostringstream ss;
    const std::string nl = pretty ? "\n" : "";
    const std::string ind1 = pretty ? "  " : "";
    const std::string ind2 = pretty ? "    " : "";
    const std::string ind3 = pretty ? "      " : "";

    ss << "[" << nl;
    bool first = true;

    for (const auto& host : result.hosts) {
        // Open/Filtered Ports findings
        for (const auto& port : host.ports) {
            if (!port.is_open() && port.state != PortState::OpenFiltered) {
                continue;
            }

            if (!first) ss << "," << nl;
            first = false;

            std::string state_str = port_state_str(port.state);
            std::string evidence = "Port " + std::to_string(port.port) + "/" + port.protocol +
                                   " is " + state_str;
            if (!port.service.empty()) {
                evidence += " (" + port.service;
                if (!port.product.empty()) {
                    evidence += " - " + port.product;
                    if (!port.version.empty()) evidence += " " + port.version;
                }
                evidence += ")";
            }

            std::string url;
            if (port.service == "http" || port.port == 80 || port.port == 8080) {
                url = "http://" + host.ip + ":" + std::to_string(port.port);
            } else if (port.service == "https" || port.port == 443 || port.port == 8443 || port.is_ssl) {
                url = "https://" + host.ip + ":" + std::to_string(port.port);
            }

            ss << ind1 << "{" << nl;
            ss << ind2 << "\"type\": \"open_port\"," << nl;
            ss << ind2 << "\"evidence\": " << json_escape(evidence) << "," << nl;
            ss << ind2 << "\"severity\": \"info\"," << nl;
            ss << ind2 << "\"confidence\": \"high\"," << nl;
            if (url.empty()) {
                ss << ind2 << "\"url\": null," << nl;
            } else {
                ss << ind2 << "\"url\": " << json_escape(url) << "," << nl;
            }
            ss << ind2 << "\"param\": null," << nl;
            ss << ind2 << "\"target\": " << json_escape(host.ip) << "," << nl;
            ss << ind2 << "\"module\": \"portscan\"," << nl;
            ss << ind2 << "\"timestamp\": " << json_escape(result.start_time) << "," << nl;
            ss << ind2 << "\"metadata\": {" << nl;
            ss << ind3 << "\"port\": " << port.port << "," << nl;
            ss << ind3 << "\"protocol\": " << json_escape(port.protocol) << "," << nl;
            ss << ind3 << "\"state\": " << json_escape(state_str) << "," << nl;
            ss << ind3 << "\"reason\": " << json_escape(port.reason) << "," << nl;
            ss << ind3 << "\"service\": " << json_escape(port.service) << "," << nl;
            ss << ind3 << "\"product\": " << json_escape(port.product) << "," << nl;
            ss << ind3 << "\"version\": " << json_escape(port.version) << "," << nl;
            ss << ind3 << "\"cpe\": " << json_escape(port.cpe) << "," << nl;
            ss << ind3 << "\"banner\": " << json_escape(port.banner) << "," << nl;
            ss << ind3 << "\"hostname\": " << json_escape(host.hostname) << nl;
            ss << ind2 << "}" << nl;
            ss << ind1 << "}";
        }

        // OS Detection finding if detected
        if (!host.os.matches.empty()) {
            const auto& top_match = host.os.matches[0];
            if (!first) ss << "," << nl;
            first = false;

            std::string evidence = "OS match: " + top_match.name + " (" +
                                   std::to_string(top_match.accuracy) + "% accuracy)";
            ss << ind1 << "{" << nl;
            ss << ind2 << "\"type\": \"os_detect\"," << nl;
            ss << ind2 << "\"evidence\": " << json_escape(evidence) << "," << nl;
            ss << ind2 << "\"severity\": \"info\"," << nl;
            ss << ind2 << "\"confidence\": "
               << (top_match.accuracy >= 90 ? "\"high\"" : (top_match.accuracy >= 70 ? "\"medium\"" : "\"low\""))
               << "," << nl;
            ss << ind2 << "\"url\": null," << nl;
            ss << ind2 << "\"param\": null," << nl;
            ss << ind2 << "\"target\": " << json_escape(host.ip) << "," << nl;
            ss << ind2 << "\"module\": \"portscan\"," << nl;
            ss << ind2 << "\"timestamp\": " << json_escape(result.start_time) << "," << nl;
            ss << ind2 << "\"metadata\": {" << nl;
            ss << ind3 << "\"os_name\": " << json_escape(top_match.name) << "," << nl;
            ss << ind3 << "\"accuracy\": " << top_match.accuracy << "," << nl;
            ss << ind3 << "\"device_type\": " << json_escape(top_match.device_type) << "," << nl;
            ss << ind3 << "\"os_family\": " << json_escape(top_match.os_family) << "," << nl;
            ss << ind3 << "\"uptime_seconds\": " << host.os.uptime_seconds << nl;
            ss << ind2 << "}" << nl;
            ss << ind1 << "}";
        }
    }

    ss << nl << "]";
    return ss.str();
}

bool write_json_file(const ScanResult& result, const std::string& path, bool pretty) {
    std::ofstream ofs(path);
    if (!ofs.is_open()) return false;
    ofs << scan_result_to_json(result, pretty);
    return ofs.good();
}

} // namespace nemesis
