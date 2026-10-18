package bd.bettingshield.vpn;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import bd.bettingshield.R;
import bd.bettingshield.core.DnsMessage;
import bd.bettingshield.core.Ipv4Udp;
import bd.bettingshield.data.BlockLog;
import bd.bettingshield.data.BlocklistStore;
import bd.bettingshield.data.Prefs;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Local "DNS-only" VPN. Only DNS traffic (to a fake DNS server address) enters the tunnel;
 * everything else flows normally, so no VPN server and no data forwarding is involved.
 * Queries for blocked domains are answered with "does not exist"; all others are forwarded
 * to the DNS servers of the phone's real network.
 */
public class ShieldVpnService extends VpnService {

    public static final String ACTION_START = "bd.bettingshield.START";
    public static final String ACTION_STOP = "bd.bettingshield.STOP";

    private static final String VPN_ADDRESS = "10.111.222.2";
    private static final String VPN_DNS = "10.111.222.1";

    private static volatile boolean running = false;

    private ParcelFileDescriptor tun;
    private Thread reader;
    private ExecutorService pool;
    private FileOutputStream tunOut;

    // upstream cache
    private final Object upstreamLock = new Object();
    private List<Upstream> upstreamCache = new ArrayList<>();
    private long upstreamCacheTime = 0;

    private static final class Upstream {
        final Network network; // may be null (then the socket is protect()ed instead)
        final InetAddress address;

        Upstream(Network n, InetAddress a) {
            network = n;
            address = a;
        }
    }

    /** True only while the tunnel is really established and the packet loop is running. */
    public static boolean isRunning() {
        return running;
    }

    public static void start(Context c) {
        Intent i = new Intent(c, ShieldVpnService.class).setAction(ACTION_START);
        c.startForegroundService(i);
    }

    public static void stop(Context c) {
        // Runs even if the service is not alive: just flag it.
        Prefs.setProtectionWanted(c, false);
        Intent i = new Intent(c, ShieldVpnService.class).setAction(ACTION_STOP);
        c.startService(i);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();

        if (ACTION_STOP.equals(action)) {
            shutdown();
            stopForeground(STOP_FOREGROUND_REMOVE);
            stopSelf();
            return START_NOT_STICKY;
        }

        // Must call startForeground quickly after startForegroundService().
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(Notifications.ID_STATUS, Notifications.statusNotification(this),
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(Notifications.ID_STATUS, Notifications.statusNotification(this));
        }

        // A null intent means Android restarted us after the process was killed (or Always-on VPN).
        if (intent == null && !Prefs.isProtectionWanted(this)) {
            // Always-on VPN can start us without the user having pressed the button: allow it.
            Prefs.setProtectionWanted(this, true);
        }

        if (!running) {
            if (!establish()) {
                Notifications.showStopped(this, getString(R.string.notif_stopped_cannot_start));
                stopForeground(STOP_FOREGROUND_REMOVE);
                stopSelf();
                return START_NOT_STICKY;
            }
            Prefs.setProtectionWanted(this, true);
            Notifications.clearStopped(this);
            // Refresh the shared lists in the background; the old list keeps working meanwhile.
            new Thread(() -> BlocklistStore.update(getApplicationContext(), false), "list-update").start();
        }
        return START_STICKY;
    }

    private boolean establish() {
        BlocklistStore.load(this);
        try {
            Builder b = new Builder()
                    .setSession(getString(R.string.app_name))
                    .setMtu(1500)
                    .addAddress(VPN_ADDRESS, 32)
                    .addDnsServer(VPN_DNS)
                    .addRoute(VPN_DNS, 32); // only traffic to our fake DNS server enters the tunnel
            try {
                b.addDisallowedApplication(getPackageName()); // our own downloads bypass the filter
            } catch (Exception ignored) {
                // not fatal
            }
            if (Build.VERSION.SDK_INT >= 29) b.setMetered(false);
            tun = b.establish();
        } catch (Exception e) {
            tun = null;
        }
        if (tun == null) return false; // permission missing/revoked

        pool = Executors.newFixedThreadPool(8);
        tunOut = new FileOutputStream(tun.getFileDescriptor());
        running = true;
        reader = new Thread(this::readLoop, "vpn-reader");
        reader.start();
        return true;
    }

    private void readLoop() {
        FileInputStream in = new FileInputStream(tun.getFileDescriptor());
        byte[] buf = new byte[32767];
        try {
            while (running) {
                int n = in.read(buf);
                if (n < 0) break;
                if (n == 0) continue;
                final Ipv4Udp.Packet p = Ipv4Udp.parse(buf, n);
                if (p == null || p.dstPort != 53) continue; // only DNS over UDP is handled
                final byte[] query = new byte[p.payloadLength];
                System.arraycopy(buf, p.payloadOffset, query, 0, p.payloadLength);
                try {
                    pool.execute(() -> handleQuery(p, query));
                } catch (RuntimeException rejected) {
                    break; // pool shut down
                }
            }
        } catch (IOException ignored) {
            // tunnel closed
        } finally {
            boolean unexpected = running;
            running = false;
            if (unexpected) {
                // The tunnel died without us asking (VPN revoked, system killed it, ...).
                Notifications.showStopped(this, getString(R.string.notif_stopped_unexpected));
            }
        }
    }

    private void handleQuery(Ipv4Udp.Packet p, byte[] query) {
        try {
            DnsMessage.Question q = DnsMessage.parseQuestion(query, 0, query.length);
            if (q != null) {
                String hit = BlocklistStore.MATCHER.match(q.name);
                if (hit != null) {
                    BlockLog.add(getApplicationContext(), q.name, hit);
                    byte[] resp = DnsMessage.buildBlockedResponse(query, 0, query.length, q);
                    writeToTun(Ipv4Udp.buildReply(p, resp, resp.length));
                    return;
                }
            }
            byte[] resp = forward(query);
            if (resp != null) {
                if (resp.length > 1400) resp = truncated(resp, query);
                if (resp != null) writeToTun(Ipv4Udp.buildReply(p, resp, resp.length));
            }
        } catch (Exception ignored) {
            // a single bad packet must never stop the service
        }
    }

    /** Answers too big for the tunnel MTU get the "truncated" flag so the app can retry. */
    private byte[] truncated(byte[] resp, byte[] query) {
        DnsMessage.Question q = DnsMessage.parseQuestion(query, 0, query.length);
        if (q == null) return null;
        byte[] out = new byte[q.endOffset];
        System.arraycopy(query, 0, out, 0, q.endOffset);
        out[2] = (byte) (0x80 | 0x02 | (query[2] & 0x79)); // QR + TC, keep opcode/RD
        out[3] = (byte) 0x80;                              // RA, rcode 0
        out[6] = out[7] = out[8] = out[9] = out[10] = out[11] = 0;
        return out;
    }

    private void writeToTun(byte[] packet) throws IOException {
        synchronized (this) {
            if (tunOut != null) tunOut.write(packet);
        }
    }

    private byte[] forward(byte[] query) {
        List<Upstream> servers = upstreams();
        for (Upstream u : servers) {
            DatagramSocket s = null;
            try {
                s = new DatagramSocket();
                if (u.network != null) {
                    u.network.bindSocket(s);
                } else {
                    protect(s);
                }
                s.setSoTimeout(2500);
                s.send(new DatagramPacket(query, query.length, u.address, 53));
                byte[] buf = new byte[4096];
                DatagramPacket resp = new DatagramPacket(buf, buf.length);
                s.receive(resp);
                byte[] out = new byte[resp.getLength()];
                System.arraycopy(buf, 0, out, 0, out.length);
                return out;
            } catch (IOException e) {
                // try next server
            } finally {
                if (s != null) s.close();
            }
        }
        return null;
    }

    private List<Upstream> upstreams() {
        synchronized (upstreamLock) {
            long now = System.currentTimeMillis();
            if (!upstreamCache.isEmpty() && now - upstreamCacheTime < 10_000) return upstreamCache;
            List<Upstream> list = new ArrayList<>();
            try {
                ConnectivityManager cm = getSystemService(ConnectivityManager.class);
                List<Network> nets = new ArrayList<>();
                for (Network n : cm.getAllNetworks()) {
                    NetworkCapabilities caps = cm.getNetworkCapabilities(n);
                    if (caps == null) continue;
                    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue;
                    if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue;
                    if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) continue;
                    // Wi-Fi / Ethernet first, then mobile data.
                    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                            || caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
                        nets.add(0, n);
                    } else {
                        nets.add(n);
                    }
                }
                // IPv4 DNS servers first, then IPv6 ones (for IPv6-only mobile networks).
                for (Network n : nets) {
                    LinkProperties lp = cm.getLinkProperties(n);
                    if (lp == null) continue;
                    for (InetAddress a : lp.getDnsServers()) {
                        if (a instanceof Inet4Address) list.add(new Upstream(n, a));
                    }
                }
                for (Network n : nets) {
                    LinkProperties lp = cm.getLinkProperties(n);
                    if (lp == null) continue;
                    for (InetAddress a : lp.getDnsServers()) {
                        if (!(a instanceof Inet4Address)) list.add(new Upstream(n, a));
                    }
                }
            } catch (Exception ignored) {
                // fall through to public fallbacks
            }
            try {
                list.add(new Upstream(null, InetAddress.getByAddress(new byte[]{1, 1, 1, 1})));
                list.add(new Upstream(null, InetAddress.getByAddress(new byte[]{8, 8, 8, 8})));
            } catch (Exception ignored) {
                // cannot happen
            }
            upstreamCache = list;
            upstreamCacheTime = now;
            return list;
        }
    }

    private void shutdown() {
        running = false;
        if (pool != null) pool.shutdownNow();
        try {
            if (tun != null) tun.close();
        } catch (IOException ignored) {
            // ignore
        }
        tun = null;
        tunOut = null;
    }

    /** Another VPN took over, or the user removed our VPN permission. */
    @Override
    public void onRevoke() {
        boolean wasRunning = running;
        shutdown();
        if (wasRunning) {
            Notifications.showStopped(this, getString(R.string.notif_stopped_revoked));
        }
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    @Override
    public void onDestroy() {
        shutdown();
        super.onDestroy();
    }
}
