/**
 * @file port_spec.cpp
 * @brief Port specification parser and top-ports database implementation.
 */

#include "port_spec.h"
#include <sstream>
#include <algorithm>
#include <random>
#include <stdexcept>

namespace nemesis {

// ─── Top 1000 TCP ports (by frequency) ──────────────────────────────────────
// Source: Nmap frequency-based ranking of most commonly open ports

const uint16_t PortSpec::TOP_1000_TCP[] = {
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080,
    1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81,
    6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433,
    49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153,
    8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357,
    427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
    7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051, 6646, 49157, 1028,
    873, 1755, 2717, 4899, 9100, 119, 37,
    // ... top 100 above; continuing to 1000:
    1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009,
    1010, 1011, 1012, 1013, 1014, 1015, 1016, 1017, 1018, 1019,
    1020, 1021, 1022, 1023, 1024, 1030, 1031, 1032, 1033, 1034,
    1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044,
    1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054,
    1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064,
    1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074,
    1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084,
    1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094,
    1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106,
    1107, 1108, 1109, 1111, 1112, 1113, 1114, 1117, 1119, 1121,
    1122, 1123, 1124, 1126, 1130, 1131, 1132, 1137, 1138, 1141,
    1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165,
    1166, 1169, 1174, 1175, 1183, 1185, 1186, 1187, 1192, 1198,
    1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244,
    1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301,
    1309, 1310, 1311, 1322, 1328, 1334, 1352, 1417, 1433, 1434,
    1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533,
    1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688,
    1700, 1717, 1718, 1719, 1721, 1782, 1783, 1801, 1805, 1812,
    1839, 1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947,
    1971, 1972, 1974, 1984, 1998, 1999, 2002, 2003, 2004, 2005,
    2006, 2007, 2008, 2009, 2010, 2013, 2020, 2021, 2022, 2030,
    2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046,
    2047, 2048, 2050, 2051, 2052, 2053, 2054, 2055, 2056, 2057,
    2058, 2059, 2060, 2061, 2062, 2063, 2064, 2065, 2066, 2067,
    2068, 2069, 2070, 2071, 2072, 2073, 2074, 2075, 2076, 2077,
    2078, 2079, 2080, 2081, 2082, 2083, 2084, 2085, 2086, 2087,
    2088, 2089, 2090, 2091, 2092, 2093, 2094, 2095, 2096, 2097,
    2098, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121,
    2126, 2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196,
    2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366, 2381, 2382,
    2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557,
    2601, 2602, 2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710,
    2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910, 2920,
    2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011,
    3013, 3017, 3030, 3031, 3052, 3071, 3077, 3128, 3168, 3211,
    3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322,
    3323, 3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372,
    3389, 3390, 3404, 3476, 3493, 3517, 3527, 3546, 3551, 3580,
    3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809,
    3814, 3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889,
    3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998, 4000,
    4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126,
    4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445, 4446,
    4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998, 5000, 5001,
    5002, 5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060,
    5061, 5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200, 5214,
    5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414,
    5431, 5432, 5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566,
    5631, 5633, 5666, 5678, 5679, 5718, 5730, 5800, 5801, 5802,
    5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900,
    5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922,
    5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988,
    5989, 5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006,
    6007, 6009, 6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129,
    6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567,
    6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779,
    6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002,
    7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201,
    7402, 7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741, 7777,
    7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001,
    8002, 8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042,
    8045, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088,
    8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194,
    8200, 8222, 8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400,
    8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701, 8800,
    8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010,
    9011, 9040, 9050, 9071, 9080, 9081, 9090, 9091, 9099, 9100,
    9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290, 9415,
    9418, 9443, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594,
    9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929,
    9943, 9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004,
    10009, 10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243,
    10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110,
    11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782,
    13783, 14000, 14238, 14441, 14442, 15000, 15002, 15003, 15004,
    15660, 15742, 16000, 16001, 16012, 16016, 16018, 16080, 16113,
    16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283,
    19315, 19350, 20000, 20005, 20031, 20221, 20222, 20828, 21571,
    22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352,
    27353, 27355, 27356, 27715, 28201, 30000, 30718, 30951, 31038,
    31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775,
    32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784,
    32785, 33354, 33899, 34571, 34572, 34573, 35500, 38292, 40193,
    40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100, 48080,
    49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160,
    49161, 49163, 49165, 49167, 49175, 49176, 49400, 49999, 50000,
    50001, 50002, 50003, 50006, 50300, 50389, 50500, 50636, 50800,
    51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055,
    55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020,
    60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129,
    65389
};
const int PortSpec::TOP_1000_TCP_COUNT = sizeof(TOP_1000_TCP) / sizeof(TOP_1000_TCP[0]);

const uint16_t PortSpec::TOP_100_UDP[] = {
    53, 67, 68, 69, 111, 123, 135, 137, 138, 139, 161, 162, 445, 500,
    514, 520, 631, 998, 999, 1434, 1701, 1900, 2049, 3283, 4500, 5060,
    5353, 5632, 17185, 20031, 30718, 31337, 32768, 32769, 32770, 32771,
    49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161,
    49163, 49165, 49167, 49175, 49176, 136, 143, 177, 427, 443, 464,
    497, 515, 518, 548, 626, 749, 750, 995, 1023, 1025, 1026, 1027,
    1028, 1029, 1030, 1645, 1646, 1718, 1719, 1812, 1813, 2000, 2048,
    2222, 2223, 3401, 4045, 4444, 5002, 5003, 5060, 5061, 5351, 6000,
    6001, 6002, 6003, 6004, 6005, 6006, 6007, 6346, 7777, 8888, 9999
};
const int PortSpec::TOP_100_UDP_COUNT = sizeof(TOP_100_UDP) / sizeof(TOP_100_UDP[0]);

// ─── Validation ─────────────────────────────────────────────────────────────

void PortSpec::validate_port(int port) {
    if (port < 1 || port > 65535)
        throw std::invalid_argument("Port must be between 1 and 65535, got: " + std::to_string(port));
}

// ─── Parsing ────────────────────────────────────────────────────────────────

void PortSpec::parse_single_spec(const std::string& spec, std::set<uint16_t>& target) {
    // Handle "all ports" shortcut
    if (spec == "-") {
        for (int p = 1; p <= 65535; ++p)
            target.insert(static_cast<uint16_t>(p));
        return;
    }

    // Split by comma
    std::stringstream ss(spec);
    std::string chunk;
    while (std::getline(ss, chunk, ',')) {
        // Trim
        while (!chunk.empty() && chunk.front() == ' ') chunk.erase(chunk.begin());
        while (!chunk.empty() && chunk.back() == ' ') chunk.pop_back();
        if (chunk.empty()) continue;

        auto dash = chunk.find('-');
        if (dash != std::string::npos && dash > 0) {
            // Range: "start-end"
            int start = std::stoi(chunk.substr(0, dash));
            int end   = std::stoi(chunk.substr(dash + 1));
            if (start > end) std::swap(start, end);
            validate_port(start);
            validate_port(end);
            for (int p = start; p <= end; ++p)
                target.insert(static_cast<uint16_t>(p));
        } else if (dash == 0) {
            // "-end" means "1-end"
            int end = std::stoi(chunk.substr(1));
            validate_port(end);
            for (int p = 1; p <= end; ++p)
                target.insert(static_cast<uint16_t>(p));
        } else {
            // Single port
            int port = std::stoi(chunk);
            validate_port(port);
            target.insert(static_cast<uint16_t>(port));
        }
    }
}

void PortSpec::parse(const std::string& spec) {
    if (spec.empty())
        throw std::invalid_argument("Empty port specification");

    // Check for protocol prefix: T: or U:
    std::string remaining = spec;

    // Handle mixed protocol specs like "T:80,443,U:53,161"
    // Split on "T:" and "U:" boundaries
    size_t pos = 0;
    enum { PROTO_BOTH, PROTO_TCP, PROTO_UDP } current_proto = PROTO_BOTH;

    // Simple parser: split by comma, track protocol prefix changes
    std::stringstream ss(remaining);
    std::string token;
    std::string tcp_spec, udp_spec, both_spec;

    while (std::getline(ss, token, ',')) {
        while (!token.empty() && token.front() == ' ') token.erase(token.begin());
        while (!token.empty() && token.back() == ' ') token.pop_back();
        if (token.empty()) continue;

        if (token.size() >= 2 && (token[0] == 'T' || token[0] == 't') && token[1] == ':') {
            current_proto = PROTO_TCP;
            token = token.substr(2);
        } else if (token.size() >= 2 && (token[0] == 'U' || token[0] == 'u') && token[1] == ':') {
            current_proto = PROTO_UDP;
            token = token.substr(2);
        }

        if (token.empty()) continue;

        switch (current_proto) {
            case PROTO_TCP:
                if (!tcp_spec.empty()) tcp_spec += ",";
                tcp_spec += token;
                break;
            case PROTO_UDP:
                if (!udp_spec.empty()) udp_spec += ",";
                udp_spec += token;
                break;
            case PROTO_BOTH:
                if (!both_spec.empty()) both_spec += ",";
                both_spec += token;
                break;
        }
    }

    if (!tcp_spec.empty()) parse_single_spec(tcp_spec, tcp_);
    if (!udp_spec.empty()) parse_single_spec(udp_spec, udp_);
    if (!both_spec.empty()) {
        // No protocol prefix: add to both
        parse_single_spec(both_spec, tcp_);
        parse_single_spec(both_spec, udp_);
    }

    // If only "both" was used (no T:/U: prefix), only populate tcp_
    // to match expected behavior of defaulting to TCP scan
    if (tcp_spec.empty() && udp_spec.empty() && !both_spec.empty()) {
        udp_.clear();  // Only TCP by default
    }
}

void PortSpec::set_top_ports(int n) {
    int tcp_count = std::min(n, TOP_1000_TCP_COUNT);
    for (int i = 0; i < tcp_count; ++i)
        tcp_.insert(TOP_1000_TCP[i]);
}

void PortSpec::set_fast_scan() {
    set_top_ports(100);
}

void PortSpec::set_all_ports() {
    for (int p = 1; p <= 65535; ++p)
        tcp_.insert(static_cast<uint16_t>(p));
}

void PortSpec::shuffle() {
    randomized_ = true;
    // Actual shuffling happens in the accessor methods
}

std::vector<uint16_t> PortSpec::tcp_ports() const {
    std::vector<uint16_t> result(tcp_.begin(), tcp_.end());
    if (randomized_) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::shuffle(result.begin(), result.end(), gen);
    }
    return result;
}

std::vector<uint16_t> PortSpec::udp_ports() const {
    std::vector<uint16_t> result(udp_.begin(), udp_.end());
    if (randomized_) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::shuffle(result.begin(), result.end(), gen);
    }
    return result;
}

std::vector<uint16_t> PortSpec::all_ports() const {
    std::set<uint16_t> combined;
    combined.insert(tcp_.begin(), tcp_.end());
    combined.insert(udp_.begin(), udp_.end());
    std::vector<uint16_t> result(combined.begin(), combined.end());
    if (randomized_) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::shuffle(result.begin(), result.end(), gen);
    }
    return result;
}

// ─── Static Helpers ─────────────────────────────────────────────────────────

std::string PortSpec::compress(const std::vector<uint16_t>& ports) {
    if (ports.empty()) return "";

    std::vector<uint16_t> sorted = ports;
    std::sort(sorted.begin(), sorted.end());
    sorted.erase(std::unique(sorted.begin(), sorted.end()), sorted.end());

    std::string result;
    uint16_t start = sorted[0], prev = sorted[0];

    for (size_t i = 1; i < sorted.size(); ++i) {
        if (sorted[i] == prev + 1) {
            prev = sorted[i];
        } else {
            if (!result.empty()) result += ",";
            if (start == prev)
                result += std::to_string(start);
            else
                result += std::to_string(start) + "-" + std::to_string(prev);
            start = prev = sorted[i];
        }
    }

    if (!result.empty()) result += ",";
    if (start == prev)
        result += std::to_string(start);
    else
        result += std::to_string(start) + "-" + std::to_string(prev);

    return result;
}

std::vector<uint16_t> PortSpec::top_tcp_ports(int n) {
    int count = std::min(n, TOP_1000_TCP_COUNT);
    return std::vector<uint16_t>(TOP_1000_TCP, TOP_1000_TCP + count);
}

std::vector<uint16_t> PortSpec::top_udp_ports(int n) {
    int count = std::min(n, TOP_100_UDP_COUNT);
    return std::vector<uint16_t>(TOP_100_UDP, TOP_100_UDP + count);
}

} // namespace nemesis
