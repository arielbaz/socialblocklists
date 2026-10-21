package dev.geder.core;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;

/** Usage : JniSmokeTest <clé-publique> <liste-signée> <liste-non-signée> */
public final class JniSmokeTest {
    static final byte[] CLIENT = {10, 111, 0, 1};
    static final byte[] RESOLVER = {10, 111, 0, 53};
    static int failures = 0;

    public static void main(String[] args) throws Exception {
        System.loadLibrary("geder_core");
        byte[] key = Base64.getDecoder().decode(Files.readString(Path.of(args[0])).trim());
        byte[] signed = Files.readAllBytes(Path.of(args[1]));
        byte[] unsigned = Files.readAllBytes(Path.of(args[2]));

        check("clé invalide refusée", GederEngine.nativeNew(new byte[][] {{1, 2, 3}}, RESOLVER, new byte[0]) == 0);
        long h = GederEngine.nativeNew(new byte[][] {key}, RESOLVER, new byte[0]);
        check("moteur créé", h != 0);

        check("liste non signée refusée", GederEngine.nativeLoadList(h, unsigned) != null);
        check("fail-closed avant chargement", !GederEngine.nativeIsDomainAllowed(h, "www.impots.gouv.fr"));
        String err = GederEngine.nativeLoadList(h, signed);
        check("liste signée acceptée (" + err + ")", err == null);
        check("domaine autorisé", GederEngine.nativeIsDomainAllowed(h, "www.impots.gouv.fr"));
        check("domaine bloqué", !GederEngine.nativeIsDomainAllowed(h, "www.youtube.com"));

        // Requête bloquée : réponse directe, avec le nom à signaler.
        byte[] blockedPkt = ipv4Udp(CLIENT, RESOLVER, 40000, 53, dnsQuery(7, "www.youtube.com"));
        byte[] out = GederEngine.nativeHandleDnsPacket(h, blockedPkt);
        check("bloqué -> réponse", out[0] == 1);
        String name = new String(out, 2, out[1], StandardCharsets.US_ASCII);
        check("nom bloqué signalé : " + name, name.equals("www.youtube.com"));
        byte[] reply = Arrays.copyOfRange(out, 2 + out[1], out.length);
        check("réponse adressée au client", reply[16] == 10 && reply[19] == 1 && (reply[0] >> 4) == 4);
        check("NXDOMAIN", (reply[28 + 3] & 0x0f) == 3);

        // Requête autorisée : transmise, puis réponse amont -> IP liée.
        byte[] q = dnsQuery(8, "www.impots.gouv.fr");
        byte[] pkt = ipv4Udp(CLIENT, RESOLVER, 40001, 53, q);
        out = GederEngine.nativeHandleDnsPacket(h, pkt);
        check("autorisé -> transmis", out[0] == 0 && Arrays.equals(Arrays.copyOfRange(out, 1, out.length), q));
        byte[] target = {(byte) 203, 0, 113, 10};
        check("IP inconnue refusée", GederEngine.nativeClassifyPacket(h, ipv4TcpSyn(CLIENT, target, 443)) == 10);
        byte[] done = GederEngine.nativeCompleteDnsPacket(h, pkt, dnsAnswerA(q, target));
        check("réponse emballée", done != null && done.length > 28);
        check("IP liée autorisée", GederEngine.nativeClassifyPacket(h, ipv4TcpSyn(CLIENT, target, 443)) == 0);
        check("QUIC refusé", GederEngine.nativeClassifyPacket(h, ipv4Udp(CLIENT, target, 5555, 443, new byte[0])) == 11);
        check("réponse sans rapport refusée",
                GederEngine.nativeCompleteDnsPacket(h, pkt, dnsAnswerA(dnsQuery(9, "www.impots.gouv.fr"), target)) == null);

        GederEngine.nativePurge(h);
        GederEngine.nativeFree(h);
        check("handle nul -> refus", !GederEngine.nativeIsDomainAllowed(0, "www.impots.gouv.fr"));
        check("handle nul -> paquet refusé", GederEngine.nativeClassifyPacket(0, new byte[0]) == 17);

        if (failures > 0) {
            System.err.println(failures + " échec(s)");
            System.exit(1);
        }
        System.out.println("JNI : tous les contrôles passent");
    }

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok  " : "  ÉCHEC  ") + what);
        if (!ok) failures++;
    }

    static byte[] dnsQuery(int id, String name) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(id >> 8); b.write(id); b.write(1); b.write(0);
        b.writeBytes(new byte[] {0, 1, 0, 0, 0, 0, 0, 0});
        for (String label : name.split("\\.")) {
            b.write(label.length());
            b.writeBytes(label.getBytes(StandardCharsets.US_ASCII));
        }
        b.writeBytes(new byte[] {0, 0, 1, 0, 1});
        return b.toByteArray();
    }

    static byte[] dnsAnswerA(byte[] query, byte[] ip) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.writeBytes(query);
        byte[] r = b.toByteArray();
        r[2] |= (byte) 0x80; r[3] |= (byte) 0x80; r[7] = 1;
        b.reset();
        b.writeBytes(r);
        b.writeBytes(new byte[] {(byte) 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4});
        b.writeBytes(ip);
        return b.toByteArray();
    }

    static byte[] ipv4(int proto, byte[] src, byte[] dst, byte[] l4) {
        int total = 20 + l4.length;
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.writeBytes(new byte[] {0x45, 0, (byte) (total >> 8), (byte) total, 0, 0, 0x40, 0, 64, (byte) proto, 0, 0});
        b.writeBytes(src); b.writeBytes(dst); b.writeBytes(l4);
        return b.toByteArray();
    }

    static byte[] ipv4Udp(byte[] src, byte[] dst, int sport, int dport, byte[] payload) {
        int len = 8 + payload.length;
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.writeBytes(new byte[] {(byte) (sport >> 8), (byte) sport, (byte) (dport >> 8), (byte) dport,
                (byte) (len >> 8), (byte) len, 0, 0});
        b.writeBytes(payload);
        return ipv4(17, src, dst, b.toByteArray());
    }

    static byte[] ipv4TcpSyn(byte[] src, byte[] dst, int dport) {
        byte[] tcp = new byte[20];
        tcp[0] = (byte) 0x9c; tcp[1] = 0x40; tcp[2] = (byte) (dport >> 8); tcp[3] = (byte) dport;
        tcp[12] = 0x50; tcp[13] = 0x02;
        return ipv4(6, src, dst, tcp);
    }
}
