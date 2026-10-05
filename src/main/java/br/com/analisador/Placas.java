package br.com.analisador;

import org.pcap4j.core.PcapNetworkInterface;

import java.net.Inet4Address;
import java.util.List;

public final class Placas {

    private Placas() { }

    /** Prefere a primeira placa física com IPv4; cai para qualquer uma com IPv4 e, por fim, a primeira da lista. */
    public static PcapNetworkInterface escolherPadrao(List<PcapNetworkInterface> placas) {
        List<PcapNetworkInterface> comIpv4 = placas.stream()
                .filter(n -> !n.isLoopBack())
                .filter(n -> n.getAddresses().stream().anyMatch(a -> a.getAddress() instanceof Inet4Address))
                .toList();
        return comIpv4.stream()
                .filter(n -> !eVirtual(n))
                .findFirst()
                .orElse(comIpv4.isEmpty() ? placas.get(0) : comIpv4.get(0));
    }

    private static boolean eVirtual(PcapNetworkInterface nif) {
        String d = (nif.getDescription() != null ? nif.getDescription() : nif.getName()).toLowerCase();
        return d.contains("virtual") || d.contains("hyper-v") || d.contains("vmware") || d.contains("loopback");
    }
}
