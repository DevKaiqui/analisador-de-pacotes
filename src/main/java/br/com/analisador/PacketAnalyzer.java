package br.com.analisador;

import org.pcap4j.packet.*;

import java.util.StringJoiner;

/** Resume um pacote em uma linha legível, respeitando o mascaramento de dados sensíveis. */
public final class PacketAnalyzer {

    private final SensitiveDataMasker masker;

    public PacketAnalyzer(SensitiveDataMasker masker) {
        this.masker = masker;
    }

    /** O número do pacote não entra no texto: a tabela da interface já o mostra em coluna própria. */
    public String describe(Packet pacote, int numero, boolean mostrarSensivel) {
        int tamanho = pacote.length();

        ArpPacket arp = pacote.get(ArpPacket.class);
        if (arp != null) {
            ArpPacket.ArpHeader h = arp.getHeader();
            return String.format("ARP %s  %s (%s) -> %s  %d bytes",
                    h.getOperation().name(),
                    ip(h.getSrcProtocolAddr().getHostAddress(), mostrarSensivel),
                    masker.maskMac(h.getSrcHardwareAddr().toString(), mostrarSensivel),
                    ip(h.getDstProtocolAddr().getHostAddress(), mostrarSensivel),
                    tamanho);
        }

        IpPacket ipPacote = pacote.get(IpPacket.class);
        if (ipPacote == null) {
            return "Outro protocolo  " + tamanho + " bytes";
        }
        String origem = ip(ipPacote.getHeader().getSrcAddr().getHostAddress(), mostrarSensivel);
        String destino = ip(ipPacote.getHeader().getDstAddr().getHostAddress(), mostrarSensivel);

        TcpPacket tcp = pacote.get(TcpPacket.class);
        if (tcp != null) {
            TcpPacket.TcpHeader h = tcp.getHeader();
            return String.format("TCP %s:%d -> %s:%d [%s]  %d bytes",
                    origem, h.getSrcPort().valueAsInt(), destino, h.getDstPort().valueAsInt(),
                    flags(h), tamanho);
        }

        UdpPacket udp = pacote.get(UdpPacket.class);
        if (udp != null) {
            UdpPacket.UdpHeader h = udp.getHeader();
            String base = String.format("UDP %s:%d -> %s:%d", origem, h.getSrcPort().valueAsInt(),
                    destino, h.getDstPort().valueAsInt());
            DnsPacket dns = pacote.get(DnsPacket.class);
            if (dns != null && !dns.getHeader().getQuestions().isEmpty()) {
                base = (dns.getHeader().isResponse() ? "DNS resposta " : "DNS consulta ")
                        + dns.getHeader().getQuestions().get(0).getQName().getName()
                        + "  " + origem + " -> " + destino;
            }
            return base + "  " + tamanho + " bytes";
        }

        IcmpV4CommonPacket icmp = pacote.get(IcmpV4CommonPacket.class);
        if (icmp != null) {
            return String.format("ICMP %s  %s -> %s  %d bytes",
                    icmp.getHeader().getType().name(), origem, destino, tamanho);
        }

        return String.format("%s %s -> %s  %d bytes",
                ipPacote.getHeader().getProtocol().name(), origem, destino, tamanho);
    }

    private String ip(String ip, boolean mostrarSensivel) {
        return masker.maskIp(ip, mostrarSensivel);
    }

    private static String flags(TcpPacket.TcpHeader h) {
        StringJoiner f = new StringJoiner(",");
        if (h.getSyn()) f.add("SYN");
        if (h.getAck()) f.add("ACK");
        if (h.getFin()) f.add("FIN");
        if (h.getRst()) f.add("RST");
        if (h.getPsh()) f.add("PSH");
        return f.toString();
    }
}
