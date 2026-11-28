# DDoS-Attack 分布式拒绝服务攻击模拟工具

# [English](README.md) | [中文](README-Chinese.md)

## 严格的法律与道德警告

- **本项目仅用于教育目的！** 它旨在帮助安全研究人员、网络管理员和学生理解 DDoS 攻击的原理，以便更好地设计防御策略。
- **未经授权对任何非你个人拥有的服务器、网络或设备发起攻击是严重的犯罪行为，将受到法律严惩。**
- **请确保你只在拥有完全控制权的隔离实验环境（例如本地虚拟机、自建测试网络）中运行此代码。** 作者对任何不当使用不承担任何责任。

---

## 项目简介

「 DDoS-Attack_t3g85hxb670 」是一个跨平台的高性能 DDoS 模拟工具，支持 **Python**、**Java** 和 **C 语言** 三种实现版本，能够向指定 IP 和端口发送 UDP 洪水数据包。所有版本均采用高性能优化设计，支持多线程 / 多进程、批量发送、随机端口等特性。

项目还附带一个交互式 shell —— **Sucodesuddos**，可以在任意目录下一条命令进入命令行交互环境，快速定位、编译并运行任意目标文件。

---

## 主要特性

### 通用特性

- 简洁的命令行交互界面 + 完整的命令行参数支持
- 可自定义目标 IP、端口、总流量（GB）、线程数、突发大小等参数
- 攻击前自动检测目标可达性（避免无效攻击）
- 实时进度条显示（发送进度、速率、剩余时间、丢包统计）
- 增量统计更新（减少锁竞争，提升高并发性能）
- 重试机制（仅针对 EAGAIN / EWOULDBLOCK 重试）
- 立即停止（Ctrl+C 信号处理）
- 日志记录支持
- 艺术字启动界面（需要 figlet 支持）
- **Sucodesuddos 交互式 shell**（任意目录一条命令启动，无需 `cd`）

### Python 版特性

- 跨平台支持（Windows / Linux / macOS / Android Termux）
- 多线程发送
- 跨平台清屏函数

### Java 版特性

- 阻塞式 DatagramChannel（可靠、简单）
- 预分配 SocketAddress 数组用于随机端口
- ThreadLocalRandom 快速随机
- LongAdder 低竞争统计
- BindException 降级处理

### C 语言版特性（Linux）

- Linux `sendmmsg()` 批量发送支持（单次系统调用发送多个包，大幅提升吞吐量）
- POSIX sockets + pthread 多线程
- 预分配 sockaddr_in 数组
- 原子操作统计（atomic）
- 高精度单调时钟计时
- 仅支持 Linux（Windows 版单独提供）

### C 语言版特性（Windows）

- Winsock2 + `_beginthreadex` 多线程
- 内置参数解析（不依赖 getopt）
- Interlocked 原子操作
- 预分配地址数组
- 支持 `--no-prealloc` 禁用预分配

---

## 项目结构

```
DDOS-Attack/
├── DDOS/
│   ├── Chinese/
│   │   ├── DDOS-Attack_01_c.py      → 攻击代码文件（完整版），中文
│   │   ├── DDOS-Attack_02_c.py      → 快捷版（纯命令行，无艺术字），中文
│   │   ├── DDOS-Attack_03_c.py      → 可伪造源 IP 版本（需 ROOT 权限），中文
│   │   ├── DDOS-Attack_04_c.py      → Minecraft Java 假人攻击，中文
│   │   ├── DDOS-Attack_05_c.c       → C 语言版本，仅适用于 Windows，中文
│   │   ├── DDOS-Attack_06_c.java    → Java 版本，中文
│   │   └── DDOS-Attack_07_c.c       → C 语言版本，仅适用于 Linux，中文
│   └── English/
│       ├── DDOS-Attack_01_e.py      → 攻击代码文件（完整版），英文
│       ├── DDOS-Attack_02_e.py      → 快捷版（纯命令行，无艺术字），英文
│       ├── DDOS-Attack_03_e.py      → 可伪造源 IP 版本（需 ROOT 权限），英文
│       ├── DDOS-Attack_04_e.py      → Minecraft Java 假人攻击，英文
│       ├── DDOS-Attack_05_e.c       → C 语言版本，仅适用于 Windows，英文
│       ├── DDOS-Attack_06_e.java    → Java 版本，英文
│       └── DDOS-Attack_07_e.c       → C 语言版本，仅适用于 Linux，英文
├── Launcher/
│   ├── LauncherWindows.bat          → Windows 运行文件（自动安装依赖，并选择文件运行）
│   └── LauncherLinux                → Linux 运行文件（自动安装依赖，并选择文件运行）
├── Art/
│   ├── Figlet_DDOS-Attack           → figlet 字体预览（DDOS-Attack）
│   ├── Figlet_AttackStarting        → figlet 字体预览（Attack Starting）
│   └── print-DDOS.py                → DDOS 字体预览（ALL）
├── Sucodesuddos.py                  → 交互式 shell（Python 源码）
├── build.bat                        → 打包 + 安装 Sucodesuddos.exe（Windows 一键）
├── README-Chinese.md                → 中文介绍
├── README.md                        → 英文介绍
└── LICENSE                          → 开源许可（GPLv3）
```

---

## Sucodesuddos 交互式 Shell

### 简介

`Sucodesuddos` 是一个交互式命令行工具，进入后提供统一提示符 `[Sucodesuddos]> `，可以：

- 用 `ls` 查看项目结构
- 用 `help` 查看所有命令和各文件使用教程
- 用 `run` 一条命令编译并运行任意目标文件（自动识别 `.py` / `.c` / `.java`）
- 用 `cat` 快速查看源码
- 用 `selftest` 一键检查环境依赖

### 安装（Windows）

**前置要求**：本机已安装 Python 3.8+，且 `python` 或 `py` 命令在 PATH 中可用。

**步骤**：

1. 把 `Sucodesuddos.py` 和 `build.bat` 放在项目根目录（和 `DDOS/` 同级）
2. **双击 `build.bat`**
3. 等待完成（会自动做三件事）：
   - 用 PyInstaller 打包成 `Sucodesuddos.exe`
   - 安装到 `%LOCALAPPDATA%\Sucodesuddos\`
   - 把该目录写入用户 `PATH`，把项目根写入用户环境变量 `SUCODES_ROOT`
4. **关闭当前窗口，新开一个 CMD 或 PowerShell 窗口**
5. 在**任意目录**输入：

```cmd
Sucodesuddos
```

即可进入交互式 shell，**不需要 `cd` 到项目目录**。

### 安装（Linux / macOS）

```bash
# 1. 放到项目根
cp Sucodesuddos.py /path/to/DDOS-Attack/Sucodesuddos.py
chmod +x /path/to/DDOS-Attack/Sucodesuddos.py

# 2. 软链到 PATH
sudo ln -sf /path/to/DDOS-Attack/Sucodesuddos.py /usr/local/bin/Sucodesuddos

# 3. 设置项目根（任选其一）
export SUCODES_ROOT=/path/to/DDOS-Attack         # 当前会话
echo 'export SUCODES_ROOT=/path/to/DDOS-Attack' >> ~/.bashrc   # 永久
```

之后在任意目录输入 `Sucodesuddos` 即可。

### 使用示例

```text
$ Sucodesuddos
==================================================================
  Sucodesuddos Shell v1.2.1
  Project : D:\path\to\DDOS-Attack
  Platform: Windows AMD64
  Mode    : frozen (exe)
==================================================================
[+] Project root: D:\path\to\DDOS-Attack
[*] Type 'help' for commands, 'ls' for project tree, 'exit' to quit.

[Sucodesuddos]> ls
DDOS-Attack/
DDOS-Attack/
├── DDOS/
│   ├── Chinese/
│   │   ├── DDOS-Attack_01_c.py      → 攻击代码文件（完整版），中文
│   │   ├── DDOS-Attack_02_c.py      → 快捷版（纯命令行，无艺术字），中文
│   │   ├── DDOS-Attack_03_c.py      → 可伪造源 IP 版本（需 ROOT 权限），中文
│   │   ├── DDOS-Attack_04_c.py      → Minecraft Java 假人攻击，中文
│   │   ├── DDOS-Attack_05_c.c       → C 语言版本，仅适用于 Windows，中文
│   │   ├── DDOS-Attack_06_c.java    → Java 版本，中文
│   │   └── DDOS-Attack_07_c.c       → C 语言版本，仅适用于 Linux，中文
│   └── English/
│       ├── DDOS-Attack_01_e.py      → 攻击代码文件（完整版），英文
│       ├── DDOS-Attack_02_e.py      → 快捷版（纯命令行，无艺术字），英文
│       ├── DDOS-Attack_03_e.py      → 可伪造源 IP 版本（需 ROOT 权限），英文
│       ├── DDOS-Attack_04_e.py      → Minecraft Java 假人攻击，英文
│       ├── DDOS-Attack_05_e.c       → C 语言版本，仅适用于 Windows，英文
│       ├── DDOS-Attack_06_e.java    → Java 版本，英文
│       └── DDOS-Attack_07_e.c       → C 语言版本，仅适用于 Linux，英文
├── Launcher/
│   ├── LauncherWindows.bat          → Windows 运行文件（自动安装依赖，并选择文件运行）
│   └── LauncherLinux                → Linux 运行文件（自动安装依赖，并选择文件运行）
├── Art/
│   ├── Figlet_DDOS-Attack           → figlet 字体预览（DDOS-Attack）
│   ├── Figlet_AttackStarting        → figlet 字体预览（Attack Starting）
│   └── print-DDOS.py                → DDOS 字体预览（ALL）
├── Sucodesuddos.py                  → 交互式 shell（Python 源码）
├── build.bat                        → 打包 + 安装 Sucodesuddos.exe（Windows 一键）
├── README-Chinese.md                → 中文介绍
├── README.md                        → 英文介绍
└── LICENSE                          → 开源许可（GPLv3）

[Sucodesuddos]> run 01c
[>] Running: D:\path\to\DDOS-Attack\DDOS\Chinese\DDOS-Attack_01_c.py
（进入 01 的交互界面）

[Sucodesuddos]> run 02c -t 127.0.0.1 -p 8080 -g 0.001 -y
[>] Running: ...\DDOS-Attack_02_c.py
[>] Args: -t 127.0.0.1 -p 8080 -g 0.001 -y

[Sucodesuddos]> run 07c -t 127.0.0.1 -p 8080 -g 0.001 -y
[>] gcc -O3 -pthread -o /tmp/sucodes_xxx/udp_flood ...\DDOS-Attack_07_c.c
[>] /tmp/sucodes_xxx/udp_flood -t 127.0.0.1 -p 8080 -g 0.001 -y

[Sucodesuddos]> help
（显示所有命令和 01-07 各文件使用教程）

[Sucodesuddos]> exit
Bye.
```

### 命令速查

| 命令 | 说明 |
|------|------|
| `ls` / `list` / `ll` | 显示项目树 |
| `help` | 显示所有命令 + 各文件使用教程 |
| `help run` | `run` 子命令帮助 |
| `help cat` | `cat` 子命令帮助 |
| `run <id><lang>` | 按编号运行，如 `run 01c` / `run 01e` |
| `run <id> <lang>` | 空格分隔写法，如 `run 01 c` |
| `run <id><lang> <args...>` | 带参数传参，如 `run 02c -t 1.1.1.1 -p 53 -g 1 -y` |
| `run <filename>` | 按文件名运行 |
| `cat <file>` | 查看源码 |
| `clear` / `cls` | 清屏 |
| `history` / `hist` | 命令历史 |
| `pwd` | 当前目录 + 项目根 |
| `version` / `ver` | 版本信息 |
| `art` | 调用 `Art/print-DDOS.py` 显示 DDOS 艺术字 |
| `selftest` | 环境体检（Python / Java / gcc / 项目文件） |
| `exit` / `quit` / `q` | 退出 |

### `run` 的语言参数规则

| 写法 | 实际语言 | 说明 |
|------|---------|------|
| `run 01c` | Chinese | `c` 选择中文 |
| `run 01C` | Chinese | 大小写不敏感 |
| `run 01e` | English | `e` 选择英文 |
| `run 01n` | English | 后缀非 `c` 时静默降级为英文 |
| `run 01x` | English | 同上 |
| `run 01` | English | 无后缀时默认英文 |
| `run 1c` | Chinese | 编号前导零可省略 |
| `run 01 c` | Chinese | 空格分隔写法 |
| `run 01 -t 1.1.1.1 -p 53 -g 1` | English | `-t` 是参数，不是语言 |

### 参数错误规则

| 输入 | 输出 |
|------|------|
| `run`（无参数） | `ERROR: Invalid arguments, type <help> for help` |
| `cat`（无参数） | `ERROR: Invalid arguments, type <help> for help` |
| `help foo`（未知子命令） | `ERROR: Invalid arguments, type <help> for help` |
| `run 99c`（合法格式，文件不存在） | `[!] No matching file: DDOS-Attack_99_c` |

**格式错误 → `ERROR`；格式正确但文件不存在 → `[!] No matching file`**，便于区分。

### 环境变量

| 变量 | 说明 |
|------|------|
| `SUCODES_ROOT` | 项目根目录路径（包含 `DDOS/` 的目录）。`build.bat` 会自动设置；手动设置后可在任意目录启动 |

手动设置（Windows，永久）：

```cmd
setx SUCODES_ROOT "D:\path\to\DDOS-Attack"
```

（Linux / macOS）：

```bash
export SUCODES_ROOT=/path/to/DDOS-Attack
```

### 卸载

删除 `%LOCALAPPDATA%\Sucodesuddos\` 目录，再从用户 PATH 中移除该目录即可。若需同时清除 `SUCODES_ROOT`：

```cmd
REG delete HKCU\Environment /v SUCODES_ROOT /f
```

---

## 环境要求

### Python 版

- **Python 3.6+**（推荐 3.9+）
- 操作系统：Linux、Windows、macOS、Android（Termux）
- 依赖工具：`git` 用于克隆仓库，`figlet` 用于生成艺术字标题（可选）

### Java 版

- **JDK 8+**（推荐 JDK 11+）
- 操作系统：Linux、Windows、macOS
- 依赖工具：`figlet` 用于生成艺术字标题（可选）

### C 语言版（Linux）

- **GCC 4.9+** 或 Clang
- 操作系统：Linux（内核 3.0+ 以支持 `sendmmsg`）
- 依赖工具：`figlet` 用于生成艺术字标题（可选）

### C 语言版（Windows）

- **MinGW-w64** 或 **Microsoft Visual Studio**
- 操作系统：Windows 7+
- 依赖工具：`figlet` 用于生成艺术字标题（可选）

### Sucodesuddos Shell

- **Python 3.8+**（打包 exe 和 `run .py` 均需要）
- **PyInstaller**（`build.bat` 会自动安装）
- 可选：`javac` / `java` / `gcc`（用于 `run` 编译 `.java` / `.c`）

---

## 命令行参数

所有攻击文件均支持以下通用参数：

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-t, --target` | 目标 IP 地址 | 必填 |
| `-p, --port` | 目标 UDP 端口 | 必填 |
| `-g, --gb` | 总流量（GB） | 必填 |
| `-P, --processes` | 线程数 / 进程数 | 4 |
| `-T, --threads` | 同 `-P` | — |
| `-b, --burst` | 每突发包数 | 50 |
| `-r, --rate` | 速率限制（秒/突发） | 0（不限速） |
| `-d, --duration` | 攻击持续时间（秒） | 0（直到发完） |
| `-s, --src-port` | 源端口基数 | -1（随机） |
| `--size` | 包大小（字节） | 1490 |
| `--random-port` | 随机目标端口 | 关闭 |
| `--log` | 日志文件路径 | 无 |
| `--no-interactive` | 跳过确认 | 关闭 |
| `--max-retries` | 最大重试次数 | 3 |
| `--no-prealloc` | 禁用预分配（C / Java） | 关闭 |
| `-h, --help` | 显示帮助 | — |

---

## 性能对比

| 语言 | 平台 | 关键技术 | 预估 PPS（64 字节包） |
|------|------|----------|----------------------|
| Python | 跨平台 | 多线程 + asyncio | 5 万 ~ 8 万 |
| Java | 跨平台 | 多线程 + NIO | 5 万 ~ 10 万 |
| C (Linux) | Linux | sendmmsg + 多进程 | 30 万 ~ 50 万 |
| C (Windows) | Windows | 多线程 + sendto | 2 万 ~ 5 万 |

> 注：实际 PPS 受 CPU、网卡、内核参数、目标链路影响，以上数据为参考值。测试前建议先运行 `sysctl` 调整内核参数（见 `Sucodesuddos` 启动时的提示）。

---

## 免责声明

- 本工具仅供学习和研究使用。使用者应遵守当地法律法规，不得将本工具用于任何非法用途。作者不对任何滥用行为承担法律责任。

---

## 开源协议

- 本仓库使用 **GPLv3** 作为开源协议。详见 `LICENSE` 文件。

---

## 贡献与反馈

- 欢迎提交 Issue 和 Pull Request。如有建议或问题，请通过 GitHub Issues 联系。

---

## 作者

- **Su-StackTrace**
- GitHub: https://github.com/Su-StackTrace/Su-StackTrace.git
- 邮箱：3805908465@qq.com
