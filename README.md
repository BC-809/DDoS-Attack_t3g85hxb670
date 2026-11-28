# DDoS-Attack Distributed Denial of Service Attack Simulation Tool
# [中文](README-Chinese.md)

## Strict Legal and Ethical Warning

- This project is for educational purposes only! It is intended to help security researchers, network administrators, and students understand the principles of DDoS attacks so they can better design defense strategies.
- Launching attacks against any server, network, or device that you do not personally own without authorization is a serious crime and will be severely punished by law.
- Please ensure that you run this code only in an isolated lab environment that you fully control (e.g., local virtual machines, self-built test networks). The author assumes no responsibility for any improper use.

---

## Project Overview

" DDoS-Attack_t3g85hxb670 " is a cross-platform high-performance DDoS simulation tool that supports Python, Java, and C implementations and can send UDP flood packets to a specified IP and port. All versions use high-performance optimization designs and support features such as multithreading/multiprocessing, batch sending, and random ports.

---

## Key Features

### General Features

- Concise command-line interactive interface + full command-line argument support
- Customizable target IP, port, total traffic (GB), thread count, burst size, and other parameters
- Automatically checks target reachability before attack (to avoid invalid attacks)
- Real-time progress bar display (sending progress, rate, remaining time, packet loss statistics)
- Incremental statistics updates (reduce lock contention, improve high-concurrency performance)
- Retry mechanism (retry only for EAGAIN/EWOULDBLOCK)
- Immediate stop (Ctrl+C signal handling)
- Logging support
- ASCII art startup screen (requires figlet support)

### Python Version Features

- Cross-platform support (Windows/Linux/macOS/Android_Termux)
- Multithreaded sending
- Cross-platform clear screen function

### Java Version Features

- Blocking DatagramChannel (reliable, simple)
- Preallocated SocketAddress array for random ports
- ThreadLocalRandom fast random
- LongAdder low-contention statistics
- BindException fallback handling

C Language Version Features

- Linux sendmmsg() batch sending support (send multiple packets in a single system call, greatly improving throughput)
- POSIX sockets + pthread multithreading
- Preallocated sockaddr_in array
- Atomic operation statistics (Interlocked/atomic)
- High-precision monotonic clock timing
- Linux only (Windows version provided separately)

### Windows C Language Version Features

- Winsock2 + _beginthreadex multithreading
- Built-in argument parsing (does not depend on getopt)
- Interlocked atomic operations
- Preallocated address array
- Supports --no-prealloc to disable preallocation

---

## Project Structure

```
DDOS-Attack/
├── DDOS/
│   ├── Chinese/
│   │   ├── DDOS-Attack_01_c.py      → Attack code file (full version), Chinese
│   │   ├── DDOS-Attack_02_c.py      → Quick version (skips ASCII art loading), Chinese
│   │   ├── DDOS-Attack_03_c.py      → Version with spoofable source IP (requires ROOT privileges), Chinese
│   │   ├── DDOS-Attack_04_c.py      → Minecraft_Java fake player attack, Chinese
│   │   ├── DDOS-Attack_05_c.c       → C language version, Windows only, Chinese
│   │   ├── DDOS-Attack_06_c.java    → Java version, Chinese
│   │   └── DDOS-Attack_07_c.c       → C language version, Linux only, Chinese
│   └── English/
│        ├── DDOS-Attack_01_e.py      → Attack code file (full version), English
│        ├── DDOS-Attack_02_e.py      → Quick version (skips ASCII art loading), English
│        └── DDOS-Attack_03_e.py      → Version with spoofable source IP (requires ROOT privileges), English
│        ├── DDOS-Attack_04_e.py      → Minecraft_Java fake player attack, English
│        ├── DDOS-Attack_05_e.c       → C language version, Windows only, English
│        ├── DDOS-Attack_06_e.java    → Java version, English
│        └── DDOS-Attack_07_e.c       → C language version, Linux only, English
├── Launcher/
│   ├── LauncherWindows.bat          → Windows run file (automatically installs dependencies and selects a file to run)
│   └── LauncherLinux                → Linux run file (automatically installs dependencies and selects a file to run)
├── Art/
│   ├── Figlet_DDOS-Attack           → figlet font preview (DDOS-Attack)
│   └── Figlet_AttackStarting        → figlet font preview (Attack Starting)
│   └── print-DDOS.py                → DDOS font preview（ALL）
├── README-Chinese.md                → Chinese introduction
├── README.md                        → English introduction
└── LICENSE                          → Open source license (GPLv3)
```

---

## Environment Requirements

### Python Version

- Python 3.6+ (3.9+ recommended)
- OS: Linux, Windows, macOS, Android (Termux)
- Dependency tools: git for cloning the repository, figlet for generating ASCII art titles (optional)

### Java Version

- JDK 8+ (JDK 11+ recommended)
- OS: Linux, Windows, macOS
- Dependency tools: figlet for generating ASCII art titles (optional)

### C Language Version (Linux)

- GCC 4.9+ or Clang
- OS: Linux (kernel 3.0+ to support sendmmsg)
- Dependency tools: figlet for generating ASCII art titles (optional)

### C Language Version (Windows)

- MinGW-w64 or Microsoft Visual Studio
- OS: Windows 7+
- Dependency tools: figlet for generating ASCII art titles (optional)

---

## Command-Line Arguments

All versions support the following general arguments:

Argument Description Default Value
```
- -t, --target Target IP address Required
- -p, --port Target UDP port Required
- -g, --gb Total traffic (GB) Required
- -P, --processes Number of threads/processes 4
- -T, --threads Same as -P -
- -b, --burst Packets per burst 50
- -r, --rate Rate limit (seconds/burst) 0 (unlimited)
- -d, --duration Attack duration (seconds) 0 (until sending completes)
- -s, --src-port Source port base -1 (random)
- --size Packet size (bytes) 1490
- --random-port Random target port Off
- --log Log file path None
- --no-interactive Skip confirmation Off
- --max-retries Maximum retry count 3
- --no-prealloc Disable preallocation (C/Java) Off
- -h, --help Show help -
```
---

## Performance Comparison

### Language Platform Key Technology Estimated PPS (64-byte packets)

- Python Cross-platform Multithreading + asyncio 50k~80k
- Java Cross-platform Multithreading + NIO 50k~100k
- C (Linux) Linux sendmmsg + multiprocessing 300k~500k
- C (Windows) Windows Multithreading + sendto 20k~50k

---

## Disclaimer

- This tool is for learning and research purposes only. Users should comply with local laws and regulations and must not use this tool for any illegal purposes. The author assumes no legal responsibility for any misuse.

---

## Open Source License

- This repository uses GPLv3 as its open source license. See the LICENSE file for details.

---

## Contribution and Feedback

- Issues and Pull Requests are welcome. For suggestions or questions, please contact us via GitHub Issues.

---

## Author: Su-StackTrace

- GitHub: https://github.com/Su-StackTrace/Su-StackTrace.git
- Email: 3805908465@qq.com
