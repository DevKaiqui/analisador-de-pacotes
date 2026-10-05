package br.com.analisador.detector;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;

import java.util.*;

/**
 * Detecta ARP spoofing: o mesmo IP passa a ser anunciado por um MAC diferente.
 * É o sinal clássico de ataque man-in-the-middle na rede local.
 * Obs.: troca legítima de equipamento também pode disparar (falso positivo).
 */
public final class DetectorArpSpoofing implements RegraDeteccao {

    private final Mascara mascara;
    private final Map<String, String> tabela = new HashMap<>();

    public DetectorArpSpoofing(Mascara mascara) {
        this.mascara = mascara;
    }

    @Override
    public String nome() { return "ARP Spoofing"; }

    @Override
    public Optional<Alerta> analisar(Packet pacote, long agora) {
        ArpPacket arp = pacote.get(ArpPacket.class);
        if (arp == null) return Optional.empty();

        String ip = arp.getHeader().getSrcProtocolAddr().getHostAddress();
        String mac = arp.getHeader().getSrcHardwareAddr().toString();
        if (ip.equals("0.0.0.0")) return Optional.empty(); // ARP probe, ignorar

        String macAnterior = tabela.put(ip, mac);
        if (macAnterior == null || macAnterior.equalsIgnoreCase(mac)) return Optional.empty();

        String ipMascarado = mascara.ip().apply(ip);
        return Optional.of(Alerta.agora(Severidade.ALTA, nome(), ipMascarado,
                String.format("IP %s mudou de MAC: %s -> %s (possível man-in-the-middle)",
                        ipMascarado, mascara.mac().apply(macAnterior), mascara.mac().apply(mac)),
                nome() + "|" + ip));
    }
}
