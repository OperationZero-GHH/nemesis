#pragma once
/**
 * @file platform.h
 * @brief Platform detection macros and OS-specific includes.
 */

// ─── Platform Detection ─────────────────────────────────────────────────────

#if defined(_WIN32) || defined(_WIN64)
    #define NEMESIS_WINDOWS 1
    #define NEMESIS_PLATFORM_NAME "Windows"
#elif defined(__linux__)
    #define NEMESIS_LINUX 1
    #define NEMESIS_PLATFORM_NAME "Linux"
#elif defined(__APPLE__) && defined(__MACH__)
    #define NEMESIS_MACOS 1
    #define NEMESIS_PLATFORM_NAME "macOS"
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    #define NEMESIS_BSD 1
    #define NEMESIS_PLATFORM_NAME "BSD"
#else
    #define NEMESIS_UNKNOWN_PLATFORM 1
    #define NEMESIS_PLATFORM_NAME "Unknown"
#endif

// ─── OS-Specific Socket Headers ─────────────────────────────────────────────

#ifdef NEMESIS_WINDOWS
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #include <windows.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "iphlpapi.lib")

    using socket_t = SOCKET;
    constexpr socket_t INVALID_SOCK = INVALID_SOCKET;
    inline int close_socket(socket_t s) { return closesocket(s); }
    inline int socket_error() { return WSAGetLastError(); }

    /**
     * RAII Winsock initialization. Create one instance at program start.
     */
    struct WinsockInit {
        WinsockInit() {
            WSADATA wsa;
            WSAStartup(MAKEWORD(2, 2), &wsa);
        }
        ~WinsockInit() { WSACleanup(); }
        WinsockInit(const WinsockInit&) = delete;
        WinsockInit& operator=(const WinsockInit&) = delete;
    };

#else
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <netinet/ip_icmp.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <errno.h>
    #include <fcntl.h>
    #include <poll.h>
    #include <ifaddrs.h>
    #include <net/if.h>

    using socket_t = int;
    constexpr socket_t INVALID_SOCK = -1;
    inline int close_socket(socket_t s) { return close(s); }
    inline int socket_error() { return errno; }

    struct WinsockInit {
        // No-op on non-Windows
    };
#endif

// ─── Privilege Check ────────────────────────────────────────────────────────

namespace nemesis {

/**
 * Check if the current process has sufficient privileges for raw sockets.
 */
inline bool check_raw_socket_privilege() {
#ifdef NEMESIS_WINDOWS
    // On Windows, try to create a raw socket to check
    SOCKET s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s == INVALID_SOCKET) return false;
    closesocket(s);
    return true;
#else
    // On Unix, check for root or CAP_NET_RAW
    if (geteuid() == 0) return true;
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0) return false;
    close(s);
    return true;
#endif
}

/**
 * Get the name of the default network interface.
 */
std::string default_interface();

/**
 * List all available network interface names.
 */
std::vector<std::string> list_interfaces();

} // namespace nemesis
