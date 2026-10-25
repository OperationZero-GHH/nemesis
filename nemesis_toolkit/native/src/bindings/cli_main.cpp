/**
 * @file cli_main.cpp
 * @brief Standalone CLI entry point for nemesis-scan.
 */

#include "../core/engine.h"
#include "../core/config.h"
#include "../output/json_output.h"
#include "../platform/platform.h"
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>

using namespace nemesis;

static void print_usage(const char* prog) {
    std::cout << "Nemesis Port Scanner Engine v" << NemesisScanEngine::version() << "\n\n"
              << "Usage: " << prog << " [options] <target(s)>\n\n"
              << "TARGET SPECIFICATION:\n"
              << "  Can pass hostnames, IP addresses, networks (e.g. 192.168.1.0/24)\n"
              << "  -iL <inputfilename>: Input from list of hosts/networks\n"
              << "  --exclude <host1[,host2]...>: Exclude hosts/networks\n\n"
              << "HOST DISCOVERY:\n"
              << "  -sL: List Scan - simply list targets to scan\n"
              << "  -sn: Ping Scan - disable port scan\n"
              << "  -Pn: Treat all hosts as online -- skip host discovery\n\n"
              << "SCAN TECHNIQUES:\n"
              << "  -sS/--syn: TCP SYN scan (requires privileges)\n"
              << "  -sT/--connect: TCP Connect scan (default unprivileged)\n"
              << "  -sA/--ack: TCP ACK scan\n"
              << "  -sU/--udp: UDP scan\n"
              << "  -sN/--null: TCP Null scan\n"
              << "  -sF/--fin: TCP FIN scan\n"
              << "  -sX/--xmas: TCP Xmas scan\n\n"
              << "PORT SPECIFICATION:\n"
              << "  -p <port ranges>: Only scan specified ports (e.g. -p22; -p1-65535; -p U:53,111,T:21-25)\n"
              << "  -p-: Fast scan all 65535 ports\n"
              << "  -F: Fast mode - Scan fewer ports (100) than the default scan\n"
              << "  --top-ports <number>: Scan <number> most common ports\n"
              << "  -r: Don't randomize port scan order\n\n"
              << "SERVICE/VERSION DETECTION:\n"
              << "  -sV: Probe open ports to determine service/version info\n"
              << "  --version-intensity <level>: Set from 0 (light) to 9 (try all probes)\n\n"
              << "OS DETECTION:\n"
              << "  -O: Enable OS detection\n\n"
              << "TIMING AND PERFORMANCE:\n"
              << "  -T<0-5>: Set timing template (higher is faster)\n"
              << "  --max-retries <tries>: Caps number of port scan probe retransmissions\n"
              << "  --concurrency <num>: Set maximum concurrent probes (default 500)\n\n"
              << "OUTPUT:\n"
              << "  -oJ <file>: Output scan in JSON format to given filename\n"
              << "  --findings: Print Nemesis Finding JSON array to standard output\n"
              << "  --json: Print full ScanResult JSON to standard output\n"
              << "  -v: Increase verbosity level\n"
              << "  -h, --help: Print this help summary\n";
}

int main(int argc, char* argv[]) {
    WinsockInit winsock_init;

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    ScanConfig config;
    bool output_findings_stdout = false;
    bool output_json_stdout = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "-v") {
            config.verbosity++;
        } else if (arg == "-vv") {
            config.verbosity += 2;
        } else if (arg == "-Pn") {
            config.skip_discovery = true;
        } else if (arg == "-sL") {
            config.scan_type = ScanType::ListScan;
        } else if (arg == "-sn") {
            config.scan_type = ScanType::PingScan;
        } else if (arg == "-sS" || arg == "--syn") {
            config.scan_type = ScanType::TcpSyn;
        } else if (arg == "-sT" || arg == "--connect") {
            config.scan_type = ScanType::TcpConnect;
        } else if (arg == "-sA" || arg == "--ack") {
            config.scan_type = ScanType::TcpAck;
        } else if (arg == "-sU" || arg == "--udp") {
            config.scan_type = ScanType::Udp;
        } else if (arg == "-sN" || arg == "--null") {
            config.scan_type = ScanType::TcpNull;
        } else if (arg == "-sF" || arg == "--fin") {
            config.scan_type = ScanType::TcpFin;
        } else if (arg == "-sX" || arg == "--xmas") {
            config.scan_type = ScanType::TcpXmas;
        } else if (arg == "-sV") {
            config.service_detect = true;
        } else if (arg == "-O") {
            config.os_detect = true;
        } else if (arg == "-F") {
            config.fast_scan = true;
        } else if (arg == "-p-") {
            config.all_ports = true;
        } else if (arg == "-r") {
            config.randomize_ports = false;
        } else if (arg == "--findings") {
            output_findings_stdout = true;
        } else if (arg == "--json") {
            output_json_stdout = true;
        } else if (arg == "-p" && i + 1 < argc) {
            config.port_spec = argv[++i];
        } else if (arg.rfind("-p", 0) == 0 && arg.size() > 2) {
            config.port_spec = arg.substr(2);
        } else if (arg == "--top-ports" && i + 1 < argc) {
            config.top_ports = std::atoi(argv[++i]);
        } else if (arg == "-oJ" && i + 1 < argc) {
            config.json_output = argv[++i];
        } else if (arg == "-iL" && i + 1 < argc) {
            config.target_file = argv[++i];
        } else if (arg == "--exclude" && i + 1 < argc) {
            config.exclude_hosts.push_back(argv[++i]);
        } else if (arg == "--concurrency" && i + 1 < argc) {
            config.concurrency = std::atoi(argv[++i]);
        } else if (arg.rfind("-T", 0) == 0 && arg.size() == 3 && arg[2] >= '0' && arg[2] <= '5') {
            int t_level = arg[2] - '0';
            config.timing = get_timing_preset(static_cast<TimingTemplate>(t_level));
        } else if (arg[0] != '-') {
            config.targets.push_back(arg);
        }
    }

    if (config.targets.empty() && config.target_file.empty()) {
        std::cerr << "Error: No targets specified.\n\n";
        print_usage(argv[0]);
        return 1;
    }

    // Set command line string for reproducibility
    for (int i = 0; i < argc; ++i) {
        if (i > 0) config.command_line += " ";
        config.command_line += argv[i];
    }

    NemesisScanEngine engine;
    if (!output_findings_stdout && !output_json_stdout && config.verbosity > 0) {
        engine.set_progress_callback([](const std::string& phase, int current, int total, const std::string& msg) {
            std::cout << "[" << phase << " " << current << "/" << total << "] " << msg << std::endl;
        });
    }

    try {
        ScanResult result = engine.scan(config);

        if (!config.json_output.empty()) {
            write_json_file(result, config.json_output, true);
        }

        if (output_findings_stdout) {
            std::cout << scan_result_to_findings_json(result, false) << std::endl;
        } else if (output_json_stdout) {
            std::cout << scan_result_to_json(result, true) << std::endl;
        } else {
            // Human-readable summary
            std::cout << "Starting Nemesis Port Scan at " << result.start_time << "\n";
            for (const auto& host : result.hosts) {
                std::cout << "\nNmap scan report for " << (host.hostname.empty() ? host.ip : host.hostname + " (" + host.ip + ")") << "\n";
                std::cout << "Host is " << (host.is_up ? "up" : "down") << " (" << host.status_reason << ").\n";
                
                auto open_ports = host.open_ports();
                if (open_ports.empty()) {
                    std::cout << "All " << host.ports.size() << " scanned ports are closed or filtered.\n";
                } else {
                    std::cout << "PORT      STATE SERVICE  VERSION\n";
                    for (const auto& p : open_ports) {
                        char line[128];
                        std::string pstr = std::to_string(p.port) + "/" + p.protocol;
                        std::string ver = p.product;
                        if (!p.version.empty()) ver += " " + p.version;
                        snprintf(line, sizeof(line), "%-9s %-5s %-8s %s",
                                 pstr.c_str(), port_state_str(p.state),
                                 p.service.empty() ? "unknown" : p.service.c_str(),
                                 ver.c_str());
                        std::cout << line << "\n";
                    }
                }
            }
            std::cout << "\nNemesis done: " << result.hosts_total << " IP address(es) ("
                      << result.hosts_up << " host(s) up) scanned in "
                      << result.elapsed_seconds << " seconds\n";
        }

    } catch (const std::exception& e) {
        std::cerr << "Fatal scan error: " << e.what() << std::endl;
        return 2;
    }

    return 0;
}
